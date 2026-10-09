package esp

import (
	"bytes"
	"errors"
	"testing"
	"unsafe"
)

// suites is every ESP transform the data path can negotiate, each as a
// crossed sender/receiver pair.
func suites(t *testing.T) map[string][2]*SA {
	t.Helper()
	return map[string][2]*SA{
		"AES-GCM-16": {
			{SPIOut: 0xaaaa, SPIIn: 0xbbbb, Out: gcmTransform(t, 0x11), In: gcmTransform(t, 0x22)},
			{SPIOut: 0xbbbb, SPIIn: 0xaaaa, Out: gcmTransform(t, 0x22), In: gcmTransform(t, 0x11)},
		},
		"ChaCha20-Poly1305": {
			{SPIOut: 0xaaaa, SPIIn: 0xbbbb, Out: chachaTransform(t, 0x11), In: chachaTransform(t, 0x22)},
			{SPIOut: 0xbbbb, SPIIn: 0xaaaa, Out: chachaTransform(t, 0x22), In: chachaTransform(t, 0x11)},
		},
		"AES-CBC/HMAC-SHA2-256": {
			{SPIOut: 0xaaaa, SPIIn: 0xbbbb, Out: cbcTransform(t, 0x33, 0x44), In: cbcTransform(t, 0x55, 0x66)},
			{SPIOut: 0xbbbb, SPIIn: 0xaaaa, Out: cbcTransform(t, 0x55, 0x66), In: cbcTransform(t, 0x33, 0x44)},
		},
	}
}

// within reports whether sub lies inside buf's backing array.
func within(sub, buf []byte) bool {
	if len(sub) == 0 {
		return true
	}
	s, b := uintptr(unsafe.Pointer(&sub[0])), uintptr(unsafe.Pointer(&buf[0]))
	return s >= b && s+uintptr(len(sub)) <= b+uintptr(cap(buf))
}

// TestDecapsulateOpensInPlace pins the contract the inbound data path's zero
// allocations rest on, for every suite: the inner packet is a subslice of the
// datagram, and the bytes are right. A suite that quietly fell back to a fresh
// buffer would pass every round-trip test here and put the allocation back.
func TestDecapsulateOpensInPlace(t *testing.T) {
	for name, pair := range suites(t) {
		t.Run(name, func(t *testing.T) {
			sender, receiver := pair[0], pair[1]
			for _, size := range []int{1, 64, 576, 1400} {
				msg := bytes.Repeat([]byte{byte(size)}, size)
				pkt, err := sender.Encapsulate(msg, 4)
				if err != nil {
					t.Fatal(err)
				}
				inner, nh, err := receiver.Decapsulate(pkt)
				if err != nil {
					t.Fatalf("%d octets: %v", size, err)
				}
				if nh != 4 || !bytes.Equal(inner, msg) {
					t.Fatalf("%d octets: the round trip changed the packet", size)
				}
				if !within(inner, pkt) {
					t.Fatalf("%d octets: the inner packet is not inside the datagram; Decapsulate copied", size)
				}
			}
		})
	}
}

// TestAppendEncapsulatedIsEncapsulate: the append form is the outbound path's
// zero-allocation entry, and a packet it builds must open exactly as one
// Encapsulate builds -- including padded, and after bytes already in dst,
// which is how a caller-owned buffer is used.
func TestAppendEncapsulatedIsEncapsulate(t *testing.T) {
	for name, pair := range suites(t) {
		t.Run(name, func(t *testing.T) {
			sender, receiver := pair[0], pair[1]
			msg := bytes.Repeat([]byte{0x5a}, 100)
			prefix := []byte("kept")
			for _, minInner := range []int{0, 600} {
				out, err := sender.AppendEncapsulated(append(make([]byte, 0, 2048), prefix...), msg, 4, minInner)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out[:len(prefix)], prefix) {
					t.Fatal("AppendEncapsulated overwrote what dst already held")
				}
				inner, _, err := receiver.Decapsulate(out[len(prefix):])
				if err != nil {
					t.Fatalf("minInner %d: %v", minInner, err)
				}
				if !bytes.HasPrefix(inner, msg) || len(inner) < minInner {
					t.Fatalf("minInner %d: got %d octets back", minInner, len(inner))
				}
			}
		})
	}
}

// TestAReplayIsRefusedBeforeItIsDecrypted. Decrypting in place destroys the
// datagram, so a sequence number the window has already accepted is turned
// away first -- RFC 4303 §3.4.3's order -- and the packet is left as it came.
// If this fails, a replay costs a full decryption and a garbled buffer for a
// verdict the header alone could give.
func TestAReplayIsRefusedBeforeItIsDecrypted(t *testing.T) {
	pair := suites(t)["AES-GCM-16"]
	sender, receiver := pair[0], pair[1]
	pkt, err := sender.Encapsulate([]byte("hello"), 4)
	if err != nil {
		t.Fatal(err)
	}
	replay := append([]byte(nil), pkt...)
	if _, _, err := receiver.Decapsulate(pkt); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), replay...)
	if _, _, err := receiver.Decapsulate(replay); !errors.Is(err, errReplayed) {
		t.Fatalf("a replayed packet returned %v, want errReplayed", err)
	}
	if !bytes.Equal(replay, before) {
		t.Fatal("a replayed packet was decrypted before the window refused it")
	}
}

// TestAForgedPacketCannotAdvanceTheWindow: the window may be consulted before
// integrity, but it may only move after. A forged packet bearing a far-future
// sequence number that advanced it would lock the real peer out of its own SA.
func TestAForgedPacketCannotAdvanceTheWindow(t *testing.T) {
	pair := suites(t)["AES-GCM-16"]
	sender, receiver := pair[0], pair[1]
	genuine, err := sender.Encapsulate([]byte("first"), 4)
	if err != nil {
		t.Fatal(err)
	}
	forged := append([]byte(nil), genuine...)
	forged[7] = 0xff // sequence number far ahead
	forged[len(forged)-1] ^= 1
	if _, _, err := receiver.Decapsulate(forged); err == nil {
		t.Fatal("a forged packet authenticated")
	}
	if _, _, err := receiver.Decapsulate(genuine); err != nil {
		t.Fatalf("after a forged far-future packet, the genuine one is refused: %v", err)
	}
}

// TestCBCOpensWithoutAllocating holds the legacy encrypt-then-MAC suite to the
// AEAD suites' budget now that it keeps its block modes: building one per
// packet copied the IV every time.
func TestCBCOpensWithoutAllocating(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are perturbed by the race detector")
	}
	pair := suites(t)["AES-CBC/HMAC-SHA2-256"]
	assertAppendAndOpenAllocateNothing(t, pair[0], pair[1], bytes.Repeat([]byte{0xab}, 1400))
}
