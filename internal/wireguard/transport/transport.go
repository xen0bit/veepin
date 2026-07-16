// Package transport is WireGuard's data path: it turns the directional keys a
// completed handshake yields into type-4 transport messages and back.
//
// It is where the handshake stops and steady-state traffic begins. A Session
// holds one keypair — a sending key and a receiving key — plus the two counters
// that keep the AEAD nonce unique: an outbound counter that increments per
// packet, and an inbound anti-replay window that rejects a nonce the peer has
// already spent.
//
// The construction is fixed (ChaCha20-Poly1305, a 64-bit counter in the nonce,
// empty additional data) and taken from the protocol paper §5.4.6. There is no
// negotiation and no state machine here; rekeying is the handshake's business,
// and a fresh handshake simply produces a fresh Session.
package transport

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// RejectAfterMessages is the largest counter a Session will use or accept: a
// keypair must be replaced before the 64-bit nonce space runs out (protocol
// paper §6.1). It is 2^64 - 2^13 - 1, leaving a margin below the wrap so a
// handful of in-flight packets past the limit cannot alias counter zero.
const RejectAfterMessages uint64 = (1 << 64) - (1 << 13) - 1

var (
	// ErrDecrypt reports a transport packet that failed authentication: a wrong
	// key or a forgery. Like the handshake's, it is deliberately opaque.
	ErrDecrypt = errors.New("transport: message authentication failed")
	// ErrReplay reports a packet whose counter has already been seen or has
	// fallen behind the replay window. The packet authenticated, so this is a
	// genuine replay or a badly reordered path, not a forgery.
	ErrReplay = errors.New("transport: replayed or stale counter")
	// ErrExhausted reports that the sending counter has reached
	// RejectAfterMessages: the keypair must be replaced before more can be sent.
	ErrExhausted = errors.New("transport: sending key exhausted, rekey required")
	// ErrShort reports a packet too small to be a transport message.
	ErrShort = errors.New("transport: packet too short")
)

// Session encrypts and decrypts one peer's transport traffic under a single
// handshake's keys. It is safe for concurrent use: Seal is lock-free on an
// atomic counter, and Open serialises only the anti-replay window update.
type Session struct {
	send, recv    cipher.AEAD
	local, remote uint32

	// counter is the next outbound nonce. It only ever increases, so a plain
	// atomic add gives each packet a unique nonce without a lock.
	counter atomic.Uint64

	mu     sync.Mutex
	replay replayFilter
}

// NewSession builds a Session from a completed handshake's keying material:
// sendKey protects our outbound packets, recvKey opens the peer's, local is the
// index the peer addresses us by (and the pump demuxes on), and remote is the
// index we stamp on packets to the peer.
func NewSession(sendKey, recvKey [wire.KeySize]byte, local, remote uint32) (*Session, error) {
	send, err := cryptoutil.NewChaCha20Poly1305(sendKey[:])
	if err != nil {
		return nil, err
	}
	recv, err := cryptoutil.NewChaCha20Poly1305(recvKey[:])
	if err != nil {
		return nil, err
	}
	return &Session{send: send, recv: recv, local: local, remote: remote}, nil
}

// LocalIndex is the receiver index this session is addressed by — its
// dataplane.Tunnel inbound key.
func (s *Session) LocalIndex() uint32 { return s.local }

// RemoteIndex is the index the peer is addressed by.
func (s *Session) RemoteIndex() uint32 { return s.remote }

// nonce builds the 12-octet ChaCha20-Poly1305 nonce for a counter: four zero
// octets followed by the counter little-endian (protocol paper §5.4.6).
func nonce(counter uint64) [12]byte {
	var n [12]byte
	binary.LittleEndian.PutUint64(n[4:], counter)
	return n
}

// Seal encrypts an inner IP packet into a type-4 transport message. A nil or
// empty inner packet produces a keepalive: a message with an empty payload,
// which the peer authenticates and then discards.
func (s *Session) Seal(inner []byte) ([]byte, error) {
	// Reserve this packet's counter. Add returns the post-increment value, so
	// the first packet uses counter 0.
	counter := s.counter.Add(1) - 1
	if counter >= RejectAfterMessages {
		return nil, ErrExhausted
	}

	plaintext := pad(inner)
	// header || AEAD(plaintext) — one allocation sized for the whole message.
	out := make([]byte, wire.TransportHeaderLen, wire.TransportHeaderLen+len(plaintext)+wire.TagSize)
	if err := wire.PutTransportHeader(out, s.remote, counter); err != nil {
		return nil, err
	}
	n := nonce(counter)
	// Additional data is empty for transport packets; only the payload is
	// authenticated (the header's integrity does not matter — a tampered
	// counter simply decrypts to garbage under the wrong nonce and fails).
	return s.send.Seal(out, n[:], plaintext, nil), nil
}

// Open decrypts a type-4 transport message into its inner IP packet, checking
// the anti-replay window. It returns (nil, nil) for a keepalive — an
// authenticated message with no inner packet — which the caller must not write
// to the TUN.
//
// pkt is decrypted in place, so the caller must own the buffer (the pump passes
// a fresh copy).
func (s *Session) Open(pkt []byte) ([]byte, error) {
	if len(pkt) < wire.MinTransportData {
		return nil, ErrShort
	}
	counter, _ := wire.TransportCounter(pkt)
	if counter >= RejectAfterMessages {
		return nil, ErrReplay
	}
	n := nonce(counter)
	body := pkt[wire.TransportHeaderLen:]
	// Decrypt into the ciphertext's own storage: the plaintext is shorter, so it
	// fits, and this keeps the data path allocation-free.
	plain, err := s.recv.Open(body[:0], n[:], body, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	// Only advance the replay window after authentication: a forged packet must
	// never move it, or it could be used to lock out genuine traffic.
	s.mu.Lock()
	fresh := s.replay.validate(counter)
	s.mu.Unlock()
	if !fresh {
		return nil, ErrReplay
	}
	return trimToIP(plain), nil
}

// pad rounds a plaintext up to a 16-octet boundary with zeros, as WireGuard
// requires so that packet lengths leak less about their contents (protocol
// paper §5.4.6). An empty packet stays empty — a keepalive carries no padding.
func pad(inner []byte) []byte {
	const boundary = 16
	if len(inner) == 0 {
		return nil
	}
	rem := len(inner) % boundary
	if rem == 0 {
		return inner
	}
	padded := make([]byte, len(inner)+boundary-rem)
	copy(padded, inner)
	return padded
}

// trimToIP trims a decrypted payload to the length its own IP header declares,
// discarding the zero padding pad added on the far side. WireGuard carries no
// length field of its own for this — the inner packet is self-describing, and a
// payload that is not a well-formed IP packet is dropped (returned as nil).
func trimToIP(plain []byte) []byte {
	if len(plain) == 0 {
		return nil // keepalive
	}
	switch plain[0] >> 4 {
	case 4:
		if len(plain) < 20 {
			return nil
		}
		total := int(binary.BigEndian.Uint16(plain[2:4]))
		if total < 20 || total > len(plain) {
			return nil
		}
		return plain[:total]
	case 6:
		if len(plain) < 40 {
			return nil
		}
		total := 40 + int(binary.BigEndian.Uint16(plain[4:6]))
		if total > len(plain) {
			return nil
		}
		return plain[:total]
	}
	return nil
}
