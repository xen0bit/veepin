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
// data packet.
func (c *Cipher) Seal(plaintext []byte) ([]byte, error) {
	id := c.counter.Add(1)
	if id == 0 {
		return nil, errCounterExhausted
	}
	out := make([]byte, aadLen, aadLen+tagLen+len(plaintext))
	copy(out[:headerLen], c.header[:])
	binary.BigEndian.PutUint32(out[headerLen:aadLen], id)

	nonce := c.nonce(id, c.sendIV)
	// Go returns ciphertext||tag; OpenVPN wants the tag first, so split and
	// reorder to header || packetID || tag || ciphertext.
	sealed := c.send.Seal(nil, nonce[:], plaintext, out[:aadLen])
	ct, tag := sealed[:len(plaintext)], sealed[len(plaintext):]
	out = append(out, tag...)
	out = append(out, ct...)
	return out, nil
}

// Open decrypts and authenticates a wire data packet, returning the plaintext.
// It rejects replays only after the tag verifies, so forged packets cannot
// poison the window.
func (c *Cipher) Open(pkt []byte) ([]byte, error) {
	if len(pkt) < aadLen+tagLen {
		return nil, errShort
	}
	id := binary.BigEndian.Uint32(pkt[headerLen:aadLen])
	tag := pkt[aadLen : aadLen+tagLen]
	ct := pkt[aadLen+tagLen:]

	nonce := c.nonce(id, c.recvIV)
	// Reassemble ciphertext||tag for Go's AEAD.
	sealed := make([]byte, 0, len(ct)+tagLen)
	sealed = append(sealed, ct...)
	sealed = append(sealed, tag...)
	plaintext, err := c.recv.Open(nil, nonce[:], sealed, pkt[:aadLen])
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

// nonce builds the 12-byte GCM nonce: the packet ID followed by the implicit IV.
func (c *Cipher) nonce(id uint32, iv [keys.ImplicitIVLen]byte) [nonceLen]byte {
	var n [nonceLen]byte
	binary.BigEndian.PutUint32(n[:packetIDLen], id)
	copy(n[packetIDLen:], iv[:])
	return n
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
