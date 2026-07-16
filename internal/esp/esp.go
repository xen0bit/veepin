// Package esp implements a minimal userspace ESP (RFC 4303) data path with
// UDP encapsulation (RFC 3948). It protects/opens IP payloads using the keys
// negotiated for a Child SA. This is a userspace demonstration data path: it
// does not touch the kernel IPsec stack.
package esp

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// Drop-path sentinel errors. Decapsulate can be called for every inbound packet
// including duplicates, replays and misrouted datagrams; returning static errors
// (rather than fmt.Errorf) keeps the reject path allocation-free so a flood of
// dropped packets does not create per-packet garbage. The pump logs the SPI/seq
// separately, so the error values need not carry them.
var (
	errShortPacket  = errors.New("esp: packet too short")
	errUnknownSPI   = errors.New("esp: unknown SPI")
	errReplayed     = errors.New("esp: replayed sequence")
	errShortTrailer = errors.New("esp: plaintext too short for trailer")
	errBadPadLength = errors.New("esp: bad pad length")
)

// Transform is the negotiated ESP algorithm configuration for one direction of
// an SA. It is plain data: the per-packet cipher state is built from it once and
// cached on the SA.
type Transform struct {
	// EncrID is the negotiated ESP encryption transform (required).
	EncrID uint16
	// EncrKeyLn is the encryption key length in bits; 0 selects the
	// algorithm's default.
	EncrKeyLn uint16
	// IntegID is the negotiated integrity transform, or 0 for AEAD suites,
	// which authenticate with the cipher itself.
	IntegID uint16

	EncKey   []byte
	IntegKey []byte
}

// SA is a userspace ESP security association for a single direction pair.
type SA struct {
	SPIOut uint32
	SPIIn  uint32

	Out Transform
	In  Transform

	mu     sync.Mutex
	seqOut uint32
	window replayWindow

	// Prepared per-direction crypters (built lazily from Out/In on first use).
	outCrypter cryptoutil.ESPCrypter
	inCrypter  cryptoutil.ESPCrypter
	prepErr    error
	prepOnce   sync.Once
}

// espHeaderLen is SPI(4) + Sequence(4).
const espHeaderLen = 8

// prepare builds the per-direction ESP crypters once, from the transform IDs the
// Child SA negotiated.
func (s *SA) prepare() error {
	s.prepOnce.Do(func() {
		s.outCrypter, s.prepErr = crypterFor(s.Out)
		if s.prepErr != nil {
			return
		}
		s.inCrypter, s.prepErr = crypterFor(s.In)
	})
	return s.prepErr
}

// crypterFor builds the prepared data-path cipher for one direction.
func crypterFor(t Transform) (cryptoutil.ESPCrypter, error) {
	return transform.ESPCrypter(t.EncrID, int(t.EncrKeyLn), t.EncKey, t.IntegID, t.IntegKey)
}

// ResetReplayWindow clears the inbound anti-replay window and outbound sequence
// counter. It is used when an SA's keys are rekeyed (a fresh SA restarts its
// sequence space) and by benchmarks that replay a fixed batch of packets.
func (s *SA) ResetReplayWindow() {
	s.mu.Lock()
	s.window = replayWindow{}
	s.seqOut = 0
	s.mu.Unlock()
}

// Encapsulate protects an inner IP packet, returning the ESP packet body
// (SPI | Seq | IV | ciphertext | [pad|padlen|nexthdr covered] | ICV).
//
// nextHeader is the IP protocol number of the inner payload (e.g. 4 for
// IPv4-in-IPv4, or the transport protocol for transport mode).
func (s *SA) Encapsulate(inner []byte, nextHeader uint8) ([]byte, error) {
	if err := s.prepare(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.seqOut++
	seq := s.seqOut
	s.mu.Unlock()

	block := max(s.outCrypter.BlockLen(), 1)
	payloadLen := len(inner)
	padLen := (block - (payloadLen+2)%block) % block

	// Assemble the plaintext (inner || pad || padLen || nextHeader) in one
	// buffer sized exactly, then seal appending into the final output buffer.
	ptLen := payloadLen + padLen + 2
	// Output = SPI(4) | Seq(4) | crypter overhead | ciphertext-sized region.
	// The ESP header is written into the (heap) output buffer and that prefix is
	// reused as the AAD, so no separate stack array escapes through the AEAD
	// interface (that escape was the second per-packet allocation on this path).
	out := make([]byte, espHeaderLen, espHeaderLen+s.outCrypter.Overhead()+ptLen)
	binary.BigEndian.PutUint32(out[0:4], s.SPIOut)
	binary.BigEndian.PutUint32(out[4:8], seq)

	// Build plaintext in a pooled scratch buffer to avoid a per-packet alloc.
	ptp := ptPool.Get().(*[]byte)
	pt := *ptp
	if cap(pt) < ptLen {
		pt = make([]byte, ptLen)
	} else {
		pt = pt[:ptLen]
	}
	copy(pt, inner)
	for i := 0; i < padLen; i++ {
		pt[payloadLen+i] = byte(i + 1)
	}
	pt[ptLen-2] = byte(padLen)
	pt[ptLen-1] = nextHeader

	// AAD covers SPI|Seq (the ESP header). Seal appends iv||ct||icv to out.
	result, err := s.outCrypter.Seal(out, out[:espHeaderLen], pt)
	*ptp = pt[:0]
	ptPool.Put(ptp)
	return result, err
}

// ptPool recycles plaintext scratch buffers for encapsulation.
var ptPool = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

// Decapsulate verifies and decrypts an ESP packet, returning the inner IP
// payload and the inner next-header value.
func (s *SA) Decapsulate(pkt []byte) (inner []byte, nextHeader uint8, err error) {
	if err := s.prepare(); err != nil {
		return nil, 0, err
	}
	if len(pkt) < espHeaderLen {
		return nil, 0, errShortPacket
	}
	spi := binary.BigEndian.Uint32(pkt[0:4])
	if spi != s.SPIIn {
		return nil, 0, errUnknownSPI
	}
	seq := binary.BigEndian.Uint32(pkt[4:8])

	hdr := pkt[:espHeaderLen]
	body := pkt[espHeaderLen:]

	// Decrypt appending into a fresh buffer sized to the ciphertext.
	plaintext, err := s.inCrypter.Open(make([]byte, 0, len(body)), hdr, body)
	if err != nil {
		return nil, 0, err
	}

	// Anti-replay check only after integrity passes (RFC 4303 3.4.3).
	s.mu.Lock()
	replayed := s.window.check(seq)
	s.mu.Unlock()
	if replayed {
		return nil, 0, errReplayed
	}

	// Strip trailer: last octet next-header, previous octet pad length.
	if len(plaintext) < 2 {
		return nil, 0, errShortTrailer
	}
	nextHeader = plaintext[len(plaintext)-1]
	padLen := int(plaintext[len(plaintext)-2])
	if padLen+2 > len(plaintext) {
		return nil, 0, errBadPadLength
	}
	inner = plaintext[:len(plaintext)-padLen-2]

	s.mu.Lock()
	s.window.advance(seq)
	s.mu.Unlock()
	return inner, nextHeader, nil
}

// replayWindow implements a 64-packet sliding anti-replay window.
type replayWindow struct {
	top  uint32 // highest accepted sequence number
	mask uint64 // bit i set => (top-i) already seen
}

// check reports whether seq is a replay (or too old). It does not mutate.
func (w *replayWindow) check(seq uint32) bool {
	if seq == 0 {
		return true // sequence 0 is never valid
	}
	if seq > w.top {
		return false // newer than anything seen
	}
	diff := w.top - seq
	if diff >= 64 {
		return true // too old
	}
	return w.mask&(1<<diff) != 0
}

// advance records seq as seen, sliding the window forward if needed.
func (w *replayWindow) advance(seq uint32) {
	if seq > w.top {
		shift := seq - w.top
		if shift >= 64 {
			w.mask = 0
		} else {
			w.mask <<= shift
		}
		w.mask |= 1
		w.top = seq
		return
	}
	diff := w.top - seq
	if diff < 64 {
		w.mask |= 1 << diff
	}
}

// const-time compare re-exported for tests / future MAC checks.
var _ = subtle.ConstantTimeCompare
