package ike

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// RFC 7383 IKE fragmentation. A large protected IKE message — an IKE_AUTH
// bearing a certificate chain, say — can exceed the path MTU and be dropped by
// a fragmentation-hostile middlebox before IP reassembly ever runs. IKE
// fragmentation moves the split up into the IKE layer: the message's encrypted
// content is divided into independently encrypted-and-authenticated Fragment
// (SKF) payloads, one per UDP datagram, and reassembled from their plaintext
// once each is verified.
//
// veepin negotiates support (so a peer configured to always fragment
// interoperates) and reassembles inbound fragments, but never fragments its own
// output: its messages — PSK/EAP auth, no certificates — are always small
// enough to send whole, and advertising support while sending unfragmented
// messages is explicitly allowed (RFC 7383 section 2.5.1). This file holds the
// capability notify helpers, the per-fragment decrypt, and the reassembler; the
// negotiation call sites live in sa_init.go (responder) and client.go
// (initiator), and the reassembly dispatch in secured.go / client.go.

// Fragmentation reassembly bounds. A fragmented message is authenticated (it
// rides an established IKE SA, so the sender is not anonymous), but reassembly
// still buffers attacker-influenced state and must be capped.
const (
	maxFragments        = 64
	maxReassembledBytes = 64 * 1024
	fragReassemblyTTL   = 30 * time.Second
)

// skfPrefixLen is the two 16-bit fields (Fragment Number, Total Fragments) that
// precede the IV inside an SKF payload body, after its 4-octet generic payload
// header (RFC 7383 section 2.5).
const skfPrefixLen = 4

// findFragSupported reports whether the peer advertised
// IKE_FRAGMENTATION_SUPPORTED among the given (top-level) payloads.
func findFragSupported(payloads []payload.RawPayload) bool {
	for _, p := range payloads {
		if p.Type != payload.TypeNotify {
			continue
		}
		if n, err := payload.ParseNotify(p.Body); err == nil && n.Type == payload.IKEFragmentationSupported {
			return true
		}
	}
	return false
}

// addFragSupported appends an empty IKE_FRAGMENTATION_SUPPORTED notify to b.
func addFragSupported(b *payload.Builder) {
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.IKEFragmentationSupported,
	}))
}

// decryptSKF verifies and decrypts one SKF (Encrypted Fragment) payload,
// returning its fragment number, the total fragment count, the plaintext chunk,
// and — for the first fragment — the type of the first inner payload (fragments
// after the first carry NextPayload = 0).
//
// Each fragment is an independent unit: its own IV, its own RFC 7296 padding and
// its own ICV, with the associated data spanning the IKE header through the SKF
// payload's Fragment Number / Total Fragments fields (RFC 7383 section 2.5).
// Reassembly concatenates the per-fragment plaintexts in fragment-number order.
func decryptSKF(raw []byte, skf payload.RawPayload,
	suite Suite, keys SAKeys, dir keyDir) (fragNum, total uint16, firstInner payload.PayloadType, plaintext []byte, err error) {

	if len(skf.Body) < skfPrefixLen {
		return 0, 0, 0, nil, fmt.Errorf("ike: SKF payload too short")
	}
	fragNum = binary.BigEndian.Uint16(skf.Body[0:2])
	total = binary.BigEndian.Uint16(skf.Body[2:4])
	ivCtIcv := skf.Body[skfPrefixLen:] // iv || ciphertext || icv

	// AAD is everything before the IV: the IKE header, the SKF generic payload
	// header, and the Fragment Number / Total Fragments fields — i.e. raw up to
	// the start of ivCtIcv.
	bodyStart := len(raw) - len(ivCtIcv)
	if bodyStart < payload.HeaderLen+4+skfPrefixLen {
		return 0, 0, 0, nil, fmt.Errorf("ike: malformed SKF framing")
	}
	aad := raw[:bodyStart]
	// The SKF generic header's NextPayload byte sits 8 octets before the IV: the
	// 4-octet generic header plus the Fragment Number / Total Fragments fields.
	firstInner = payload.PayloadType(raw[bodyStart-4-skfPrefixLen])

	encKey, integKey := encryptKeys(keys, dir)
	padded, err := openSK(suite, encKey, integKey, aad, ivCtIcv)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	plaintext, err = stripRFC7296Pad(padded)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	return fragNum, total, firstInner, plaintext, nil
}

// fragReassembler accumulates the SKF fragments of one IKE message until every
// fragment has arrived, then yields the concatenated inner-payload plaintext.
// One reassembler is embedded per IKE SA (and per client) and reused across
// messages: a fragment for a new message ID resets it. The owner serializes
// access (the responder holds sa.mu; the client is single-threaded per SA).
type fragReassembler struct {
	msgID   uint32
	total   uint16
	parts   [][]byte
	got     int
	bytes   int
	first   payload.PayloadType
	started time.Time
}

// add records one decrypted fragment. Once every fragment of the message has
// arrived it returns the reassembled inner-payload bytes, the first inner
// payload type, and complete=true; otherwise it returns complete=false while
// fragments are still outstanding. A malformed, oversized or over-count fragment
// resets the reassembler and reports an error. Duplicate fragments are ignored.
func (r *fragReassembler) add(msgID uint32, fragNum, total uint16, first payload.PayloadType, chunk []byte) (inner []byte, firstInner payload.PayloadType, complete bool, err error) {
	switch {
	case total == 0 || total > maxFragments:
		return nil, 0, false, fmt.Errorf("ike: bad SKF total-fragments %d", total)
	case fragNum == 0 || fragNum > total:
		return nil, 0, false, fmt.Errorf("ike: bad SKF fragment number %d of %d", fragNum, total)
	}

	// Start fresh for a new message (different ID or a changed total-fragment
	// count), or when a partial reassembly for this same ID has gone stale.
	stale := r.parts != nil && time.Since(r.started) > fragReassemblyTTL
	if r.parts == nil || msgID != r.msgID || total != r.total || stale {
		r.msgID = msgID
		r.total = total
		r.parts = make([][]byte, total)
		r.got = 0
		r.bytes = 0
		r.first = 0
		r.started = time.Now()
	}

	idx := int(fragNum - 1)
	if r.parts[idx] != nil {
		// Duplicate / retransmitted fragment: keep what we have.
		return nil, 0, false, nil
	}
	if r.bytes+len(chunk) > maxReassembledBytes {
		r.reset()
		return nil, 0, false, fmt.Errorf("ike: fragmented message exceeds %d bytes", maxReassembledBytes)
	}
	r.parts[idx] = append([]byte(nil), chunk...)
	r.got++
	r.bytes += len(chunk)
	if fragNum == 1 {
		r.first = first
	}
	if r.got < int(r.total) {
		return nil, 0, false, nil
	}

	// Every fragment is present: concatenate in fragment-number order.
	out := make([]byte, 0, r.bytes)
	for _, p := range r.parts {
		out = append(out, p...)
	}
	firstInner = r.first
	r.reset()
	return out, firstInner, true, nil
}

// reset drops any partial reassembly state.
func (r *fragReassembler) reset() {
	r.parts = nil
	r.got = 0
	r.bytes = 0
	r.total = 0
	r.first = 0
}
