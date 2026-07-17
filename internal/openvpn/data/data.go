// Package data is the OpenVPN data channel: AES-256-GCM sealing and opening of
// P_DATA_V2 packets, with a replay window over the packet counter.
//
// The wire layout of one AEAD data packet (crypto.c, openvpn_encrypt_aead):
//
//	byte 0        opcode<<3 | key_id   (P_DATA_V2)
//	bytes 1..3    peer-id (24-bit, big-endian)
//	bytes 4..7    packet ID (32-bit, big-endian)
//	bytes 8..23   GCM auth tag (16 bytes)
//	bytes 24..    ciphertext
//
// The 12-byte GCM nonce is the packet ID followed by an 8-byte implicit IV from
// key derivation. The additional authenticated data is the first eight octets —
// the opcode/peer-id header and the packet ID — so a tampered header fails the
// tag. OpenVPN places the tag before the ciphertext, unlike Go's AEAD, so the
// two are swapped on the wire.
package data

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/xen0bit/veepin/internal/openvpn/keys"
)

// Data-channel opcodes and fixed field sizes.
const (
	PDataV1 = 6
	PDataV2 = 9

	opcodeShift = 3
	headerLen   = 4 // opcode byte + 3-byte peer-id (P_DATA_V2)
	packetIDLen = 4
	tagLen      = 16
	nonceLen    = 12

	// aadLen is the header plus packet ID: everything authenticated but not
	// encrypted.
	aadLen = headerLen + packetIDLen
	// Overhead is the per-packet expansion: header, packet ID, and tag.
	Overhead = headerLen + packetIDLen + tagLen
)

var (
	// errShort reports a data packet too small to contain the header, packet ID
	// and tag.
	errShort = errors.New("data: packet too short")
	// errReplay reports a packet whose ID falls outside the replay window or
	// repeats one already seen.
	errReplay = errors.New("data: replayed or too-old packet")
	// errCounterExhausted reports the 32-bit send counter wrapping, which needs a
	// rekey this build does not do.
	errCounterExhausted = errors.New("data: packet counter exhausted, rekey required")
)

// Ping is OpenVPN's keepalive payload: an encrypted data packet carrying these
// exact 16 bytes rather than an IP packet. It is recognised on receipt and
// dropped, and sent to hold the tunnel and any NAT binding open.
var Ping = []byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
}

// IsPing reports whether a decrypted payload is the keepalive ping rather than a
// tunnelled packet.
func IsPing(p []byte) bool { return bytes.Equal(p, Ping) }

// IsDataOpcode reports whether an opcode names a data-channel packet.
func IsDataOpcode(op uint8) bool { return op == PDataV1 || op == PDataV2 }

// Cipher seals and opens data packets for one direction pair. It is safe for
// concurrent use: the send counter is atomic and the replay window is locked.
type Cipher struct {
	send   cipher.AEAD
	recv   cipher.AEAD
	sendIV [keys.ImplicitIVLen]byte
	recvIV [keys.ImplicitIVLen]byte

	header  [headerLen]byte // opcode|key_id and the peer-id, constant per session
	counter atomic.Uint32   // last used send packet ID; first packet is 1

	// recvNonce is a reused inbound nonce buffer (packet ID || implicit IV): its
	// IV tail is fixed, and Open rewrites only the leading packet ID. Open is
	// called from a single goroutine (the pump's inbound loop), so this needs no
	// lock and saves a per-packet allocation the AEAD interface would otherwise
	// force by escaping a stack array.
	recvNonce [nonceLen]byte

	mu     sync.Mutex
	replay replayWindow
}

// New builds a Cipher from derived keys, the peer-id the server assigned (0 if
// none), and the negotiated key_id.
func New(dk keys.DataKeys, peerID uint32, keyID uint8) (*Cipher, error) {
	send, err := newGCM(dk.EncryptKey[:])
	if err != nil {
		return nil, err
	}
	recv, err := newGCM(dk.DecryptKey[:])
	if err != nil {
		return nil, err
	}
	c := &Cipher{send: send, recv: recv, sendIV: dk.EncryptIV, recvIV: dk.DecryptIV}
	c.header[0] = PDataV2<<opcodeShift | keyID&0x07
	c.header[1] = byte(peerID >> 16)
	c.header[2] = byte(peerID >> 8)
	c.header[3] = byte(peerID)
	// The recv nonce's IV tail is fixed; only its packet-ID head changes per open.
	copy(c.recvNonce[packetIDLen:], c.recvIV[:])
	return c, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("data: aes: %w", err)
	}
	return cipher.NewGCM(block)
}

// Seal encrypts one plaintext (an IP packet or the ping payload) into a wire
// data packet, in a single allocation. Seal may run concurrently with keepalive
// pings, so it keeps no shared scratch: the nonce is built into unused tail bytes
// of the output buffer, and the tag reordering is in place.
func (c *Cipher) Seal(plaintext []byte) ([]byte, error) {
	id := c.counter.Add(1)
	if id == 0 {
		return nil, errCounterExhausted
	}
	n := len(plaintext)
	// One allocation: the wire packet plus nonceLen scratch bytes at the tail.
	// The scratch holds the nonce, so it needs no separate heap allocation (the
	// AEAD's []byte nonce parameter would otherwise escape a stack array).
	buf := make([]byte, aadLen+tagLen+n+nonceLen)
	out := buf[:aadLen+tagLen+n]
	copy(out[:headerLen], c.header[:])
	binary.BigEndian.PutUint32(out[headerLen:aadLen], id)

	nonce := buf[aadLen+tagLen+n:]
	binary.BigEndian.PutUint32(nonce[:packetIDLen], id)
	copy(nonce[packetIDLen:], c.sendIV[:])

	// Go's AEAD yields ciphertext||tag; OpenVPN wants the tag first. Seal appends
	// ct||tag after the header+ID, then we rotate the 16-byte tag to the front of
	// the ciphertext in place (a stack-only 16-byte save, no allocation).
	sealed := c.send.Seal(out[:aadLen], nonce, plaintext, out[:aadLen])
	var tag [tagLen]byte
	copy(tag[:], sealed[aadLen+n:])                       // save the trailing tag
	copy(sealed[aadLen+tagLen:], sealed[aadLen:aadLen+n]) // shift ciphertext right
	copy(sealed[aadLen:aadLen+tagLen], tag[:])            // tag to the front
	return sealed, nil
}

// Open decrypts and authenticates a wire data packet in place, returning the
// plaintext. It rejects replays only after the tag verifies, so forged packets
// cannot poison the window. pkt is decrypted in place and must be caller-owned;
// Open is called from a single goroutine (the pump's inbound loop).
func (c *Cipher) Open(pkt []byte) ([]byte, error) {
	if len(pkt) < aadLen+tagLen {
		return nil, errShort
	}
	id := binary.BigEndian.Uint32(pkt[headerLen:aadLen])
	n := len(pkt) - aadLen - tagLen // ciphertext length

	// The wire order is tag||ciphertext; Go's AEAD wants ciphertext||tag. Rotate
	// in place (a stack-only 16-byte save) so the packet can be decrypted without
	// allocating a reassembly buffer.
	var tag [tagLen]byte
	copy(tag[:], pkt[aadLen:aadLen+tagLen])
	copy(pkt[aadLen:aadLen+n], pkt[aadLen+tagLen:]) // shift ciphertext left
	copy(pkt[aadLen+n:], tag[:])                    // tag to the end

	binary.BigEndian.PutUint32(c.recvNonce[:packetIDLen], id)
	// Decrypt in place: dst is the ciphertext's own storage (plaintext is shorter).
	plaintext, err := c.recv.Open(pkt[aadLen:aadLen], c.recvNonce[:], pkt[aadLen:aadLen+n+tagLen], pkt[:aadLen])
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	ok := c.replay.accept(id)
	c.mu.Unlock()
	if !ok {
		return nil, errReplay
	}
	return plaintext, nil
}

// replayWindow is a 64-packet sliding window over the 32-bit packet ID (RFC 6479
// in miniature): it tracks the highest ID accepted and a bitmap of the 63 below
// it, rejecting duplicates and anything older than the window.
type replayWindow struct {
	highest uint32
	bitmap  uint64 // bit i set => (highest - i) has been accepted
	started bool
}

// accept records a packet ID and reports whether it is fresh. ID 0 is never
// valid (packets are numbered from 1).
func (w *replayWindow) accept(id uint32) bool {
	if id == 0 {
		return false
	}
	if !w.started {
		w.started = true
		w.highest = id
		w.bitmap = 1
		return true
	}
	if id > w.highest {
		shift := id - w.highest
		if shift >= 64 {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.bitmap |= 1
		w.highest = id
		return true
	}
	offset := w.highest - id
	if offset >= 64 {
		return false // older than the window
	}
	mask := uint64(1) << offset
	if w.bitmap&mask != 0 {
		return false // already seen
	}
	w.bitmap |= mask
	return true
}
