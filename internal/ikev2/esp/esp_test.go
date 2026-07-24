package esp

import (
	"bytes"
	"testing"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// keyLen reports the encryption key length an ENCR transform expects, so the
// helpers below size their test keys without hardcoding magic numbers.
func keyLen(t *testing.T, encrID uint16, bits int) int {
	t.Helper()
	c, err := transform.Cipher(encrID, bits)
	if err != nil {
		t.Fatal(err)
	}
	return c.KeyLen()
}

func gcmTransform(t *testing.T, key byte) Transform {
	t.Helper()
	// AEAD: IntegID stays zero, the cipher authenticates. EncKey includes the
	// 4-octet GCM salt, which KeyLen accounts for.
	return Transform{
		EncrID:    payload.ENCR_AES_GCM_16,
		EncrKeyLn: 256,
		EncKey:    bytes.Repeat([]byte{key}, keyLen(t, payload.ENCR_AES_GCM_16, 256)),
	}
}

func chachaTransform(t *testing.T, key byte) Transform {
	t.Helper()
	// AEAD (RFC 7634): no integrity transform, no key-length attribute. EncKey is
	// the 32-octet key plus the 4-octet salt, which KeyLen accounts for.
	return Transform{
		EncrID: payload.ENCR_CHACHA20_P,
		EncKey: bytes.Repeat([]byte{key}, keyLen(t, payload.ENCR_CHACHA20_P, 0)),
	}
}

func cbcTransform(t *testing.T, ek, ik byte) Transform {
	t.Helper()
	integ, err := transform.Integrity(payload.AUTH_HMAC_SHA2_256_128)
	if err != nil {
		t.Fatal(err)
	}
	return Transform{
		EncrID:    payload.ENCR_AES_CBC,
		EncrKeyLn: 256,
		IntegID:   payload.AUTH_HMAC_SHA2_256_128,
		EncKey:    bytes.Repeat([]byte{ek}, keyLen(t, payload.ENCR_AES_CBC, 256)),
		IntegKey:  bytes.Repeat([]byte{ik}, integ.KeyLen),
	}
}

// TestDataPathAllocationsGCM guards the AES-GCM hot path: encapsulate and
// decapsulate must each allocate at most once per packet (the returned buffer).
// A regression here (e.g. an argument escaping through the AEAD interface) means
// extra per-packet garbage on the data path.
func TestDataPathAllocationsGCM(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are perturbed by the race detector")
	}
	kOut := gcmTransform(t, 0x11)
	kIn := gcmTransform(t, 0x22)
	sender := &SA{SPIOut: 0xaaaa, SPIIn: 0xbbbb, Out: kOut, In: kIn}
	receiver := &SA{SPIOut: 0xbbbb, SPIIn: 0xaaaa, Out: kIn, In: kOut}
	msg := bytes.Repeat([]byte{0xab}, 1400)

	// Warm prepared crypters and the scratch pool before measuring.
	if _, err := sender.Encapsulate(msg, 4); err != nil {
		t.Fatal(err)
	}

	if n := testing.AllocsPerRun(200, func() {
		if _, err := sender.Encapsulate(msg, 4); err != nil {
			t.Fatal(err)
		}
	}); n > 1 {
		t.Errorf("Encapsulate allocs/op = %v, want <= 1", n)
	}

	// Decapsulate a valid packet. Reset the replay window each iteration so the
	// decap succeeds (a replayed packet would take the error path, where
	// fmt.Errorf allocates and would mask the data-path allocation we measure).
	pkt, err := sender.Encapsulate(msg, 4)
	if err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(200, func() {
		receiver.ResetReplayWindow()
		if _, _, derr := receiver.Decapsulate(pkt); derr != nil {
			t.Fatal(derr)
		}
	}); n > 1 {
		t.Errorf("Decapsulate allocs/op = %v, want <= 1", n)
	}

	// A misrouted packet (unknown SPI) must be rejected with zero allocations,
	// so a flood of stray datagrams creates no per-packet garbage.
	bad := append([]byte(nil), pkt...)
	bad[0] ^= 0xff // corrupt the SPI so it matches no SA
	if n := testing.AllocsPerRun(200, func() {
		if _, _, derr := receiver.Decapsulate(bad); derr == nil {
			t.Fatal("expected unknown-SPI rejection")
		}
	}); n != 0 {
		t.Errorf("unknown-SPI drop allocs/op = %v, want 0", n)
	}
}

func TestESPRoundTripGCM(t *testing.T) {
	// Shared keys so one SA's Out pairs with the other's In.
	kOut := gcmTransform(t, 0x11)
	kIn := gcmTransform(t, 0x22)

	sender := &SA{SPIOut: 0xaaaa, SPIIn: 0xbbbb, Out: kOut, In: kIn}
	receiver := &SA{SPIOut: 0xbbbb, SPIIn: 0xaaaa, Out: kIn, In: kOut}

	msg := []byte("inner IP packet payload")
	pkt, err := sender.Encapsulate(msg, 4)
	if err != nil {
		t.Fatal(err)
	}
	got, nh, err := receiver.Decapsulate(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if nh != 4 || !bytes.Equal(got, msg) {
		t.Fatalf("gcm esp round trip: nh=%d got=%q", nh, got)
	}
}

func TestESPRoundTripChaCha20(t *testing.T) {
	kOut := chachaTransform(t, 0x11)
	kIn := chachaTransform(t, 0x22)

	sender := &SA{SPIOut: 0xaaaa, SPIIn: 0xbbbb, Out: kOut, In: kIn}
	receiver := &SA{SPIOut: 0xbbbb, SPIIn: 0xaaaa, Out: kIn, In: kOut}

	msg := []byte("inner IP packet over ChaCha20-Poly1305")
	pkt, err := sender.Encapsulate(msg, 4)
	if err != nil {
		t.Fatal(err)
	}
	got, nh, err := receiver.Decapsulate(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if nh != 4 || !bytes.Equal(got, msg) {
		t.Fatalf("chacha esp round trip: nh=%d got=%q", nh, got)
	}
}

// TestDataPathAllocationsChaCha20 guards the ChaCha20-Poly1305 hot path the same
// way TestDataPathAllocationsGCM guards AES-GCM: encap and decap must each
// allocate at most once (the returned buffer).
func TestDataPathAllocationsChaCha20(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are perturbed by the race detector")
	}
	kOut := chachaTransform(t, 0x11)
	kIn := chachaTransform(t, 0x22)
	sender := &SA{SPIOut: 0xaaaa, SPIIn: 0xbbbb, Out: kOut, In: kIn}
	receiver := &SA{SPIOut: 0xbbbb, SPIIn: 0xaaaa, Out: kIn, In: kOut}
	msg := bytes.Repeat([]byte{0xab}, 1400)

	if _, err := sender.Encapsulate(msg, 4); err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(200, func() {
		if _, err := sender.Encapsulate(msg, 4); err != nil {
			t.Fatal(err)
		}
	}); n > 1 {
		t.Errorf("Encapsulate allocs/op = %v, want <= 1", n)
	}

	pkt, err := sender.Encapsulate(msg, 4)
	if err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(200, func() {
		receiver.ResetReplayWindow()
		if _, _, derr := receiver.Decapsulate(pkt); derr != nil {
			t.Fatal(derr)
		}
	}); n > 1 {
		t.Errorf("Decapsulate allocs/op = %v, want <= 1", n)
	}
}

func TestESPRoundTripCBC(t *testing.T) {
	out := cbcTransform(t, 0x33, 0x44)
	in := cbcTransform(t, 0x55, 0x66)
	sender := &SA{SPIOut: 1, SPIIn: 2, Out: out, In: in}
	receiver := &SA{SPIOut: 2, SPIIn: 1, Out: in, In: out}

	msg := bytes.Repeat([]byte("X"), 100)
	pkt, err := sender.Encapsulate(msg, 4)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := receiver.Decapsulate(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("cbc esp round trip mismatch")
	}
}

func TestESPReplayRejection(t *testing.T) {
	out := gcmTransform(t, 0x11)
	in := gcmTransform(t, 0x22)
	sender := &SA{SPIOut: 1, SPIIn: 2, Out: out, In: in}
	receiver := &SA{SPIOut: 2, SPIIn: 1, Out: in, In: out}

	pkt, err := sender.Encapsulate([]byte("hello"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiver.Decapsulate(pkt); err != nil {
		t.Fatal(err)
	}
	// Replaying the exact same packet must be rejected.
	if _, _, err := receiver.Decapsulate(pkt); err == nil {
		t.Fatal("esp accepted a replayed packet")
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	// Fresh sequence numbers accepted and recorded.
	for _, seq := range []uint32{1, 2, 3, 10} {
		if w.check(seq) {
			t.Fatalf("seq %d wrongly flagged as replay", seq)
		}
		w.advance(seq)
	}
	// Old duplicates rejected.
	for _, seq := range []uint32{1, 2, 3, 10} {
		if !w.check(seq) {
			t.Fatalf("seq %d should be a replay now", seq)
		}
	}
	// A gap value still in-window is accepted.
	if w.check(5) {
		t.Fatal("seq 5 should still be acceptable")
	}
}
