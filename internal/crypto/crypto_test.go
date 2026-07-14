package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/xen0bit/ikennkt/internal/payload"
)

func TestDHAgreement(t *testing.T) {
	for _, id := range []uint16{
		payload.DH_CURVE25519, payload.DH_ECP_256, payload.DH_ECP_384,
		payload.DH_ECP_521, payload.DH_MODP_2048,
	} {
		a, err := NewDHGroup(id)
		if err != nil {
			t.Fatalf("group %d: %v", id, err)
		}
		b, err := NewDHGroup(id)
		if err != nil {
			t.Fatal(err)
		}
		apub, err := a.Generate()
		if err != nil {
			t.Fatalf("group %d generate: %v", id, err)
		}
		bpub, err := b.Generate()
		if err != nil {
			t.Fatal(err)
		}
		as, err := a.ComputeSecret(bpub)
		if err != nil {
			t.Fatalf("group %d a.compute: %v", id, err)
		}
		bs, err := b.ComputeSecret(apub)
		if err != nil {
			t.Fatalf("group %d b.compute: %v", id, err)
		}
		if !bytes.Equal(as, bs) {
			t.Fatalf("group %d shared secrets differ", id)
		}
	}
}

// TestPRFPlusKnownAnswer checks prf+ against a hand-computed HMAC-SHA1 vector
// structure (T1 = prf(K, S|0x01)); we verify length and that T1 prefix matches
// a direct HMAC computation.
func TestPRFPlus(t *testing.T) {
	prf, err := NewPRF(payload.PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("key")
	seed := []byte("seed")
	out := prf.Plus(key, seed, 100)
	if len(out) != 100 {
		t.Fatalf("prf+ length = %d, want 100", len(out))
	}
	// T1 must equal prf(key, seed || 0x01).
	t1 := prf.Apply(key, append(append([]byte(nil), seed...), 0x01))
	if !bytes.Equal(out[:prf.Size], t1) {
		t.Fatalf("prf+ T1 mismatch")
	}
}

func TestGCMRoundTrip(t *testing.T) {
	c, err := NewSKCipher(payload.ENCR_AES_GCM_16, 256)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, c.KeyLen())
	for i := range key {
		key[i] = byte(i)
	}
	aad := []byte("ike-header-and-sk-header")
	pt := []byte("the quick brown fox jumps over the lazy dog")
	sealed, err := c.Seal(key, nil, aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Open(key, nil, aad, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("gcm round trip: got %q", got)
	}
	// Tamper with AAD -> must fail.
	if _, err := c.Open(key, nil, []byte("wrong-aad"), sealed); err == nil {
		t.Fatal("gcm accepted tampered AAD")
	}
}

func TestCBCETMRoundTrip(t *testing.T) {
	c, err := NewSKCipher(payload.ENCR_AES_CBC, 256)
	if err != nil {
		t.Fatal(err)
	}
	cbc := c.(*cbcCipher)
	integ, err := NewIntegrity(payload.AUTH_HMAC_SHA2_256_128)
	if err != nil {
		t.Fatal(err)
	}
	encKey := bytes.Repeat([]byte{0xab}, cbc.KeyLen())
	integKey := bytes.Repeat([]byte{0xcd}, integ.KeyLen)
	aad := []byte("header")
	// SealETM now expects block-aligned input; pad to 48 bytes (3x AES block).
	pt := make([]byte, 48)
	copy(pt, []byte("encrypt-then-mac payload contents"))
	sealed, err := cbc.SealETM(encKey, integKey, aad, pt, integ)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cbc.OpenETM(encKey, integKey, aad, sealed, integ)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("cbc round trip: got %q", got)
	}
	// Flip a ciphertext bit -> MAC must reject.
	sealed[len(sealed)-integ.ICVLen-1] ^= 0x01
	if _, err := cbc.OpenETM(encKey, integKey, aad, sealed, integ); err == nil {
		t.Fatal("cbc accepted tampered ciphertext")
	}
}

func TestPSKAuthDeterministic(t *testing.T) {
	prf, _ := NewPRF(payload.PRF_HMAC_SHA2_256)
	psk := []byte("secret")
	octets := []byte("signed octets")
	a := PSKAuth(prf, psk, octets)
	b := PSKAuth(prf, psk, octets)
	if !bytes.Equal(a, b) {
		t.Fatal("PSKAuth not deterministic")
	}
	if hex.EncodeToString(a) == "" {
		t.Fatal("empty auth")
	}
}
