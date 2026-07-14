package esp

import (
	"bytes"
	"testing"

	"github.com/example/ikev2-go/internal/crypto"
	"github.com/example/ikev2-go/internal/payload"
)

func gcmTransform(t *testing.T, key byte) Transform {
	t.Helper()
	c, err := crypto.NewSKCipher(payload.ENCR_AES_GCM_16, 256)
	if err != nil {
		t.Fatal(err)
	}
	k := bytes.Repeat([]byte{key}, c.KeyLen())
	return Transform{Cipher: c, EncKey: k}
}

func cbcTransform(t *testing.T, ek, ik byte) Transform {
	t.Helper()
	c, err := crypto.NewSKCipher(payload.ENCR_AES_CBC, 256)
	if err != nil {
		t.Fatal(err)
	}
	integ, err := crypto.NewIntegrity(payload.AUTH_HMAC_SHA2_256_128)
	if err != nil {
		t.Fatal(err)
	}
	return Transform{
		Cipher:   c,
		Integ:    integ,
		EncKey:   bytes.Repeat([]byte{ek}, c.KeyLen()),
		IntegKey: bytes.Repeat([]byte{ik}, integ.KeyLen),
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
