package ike

import (
	"bytes"
	"testing"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

func TestPSKAuthDeterministic(t *testing.T) {
	prf, err := transform.PRF(payload.PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatal(err)
	}
	psk := []byte("secret")
	octets := []byte("signed octets")
	a := PSKAuth(prf, psk, octets)
	b := PSKAuth(prf, psk, octets)
	if !bytes.Equal(a, b) {
		t.Fatal("PSKAuth not deterministic")
	}
	if len(a) == 0 {
		t.Fatal("empty auth")
	}
}

// TestDeriveIKEKeysLengths checks the SK_* values are sliced out of prf+ at the
// lengths RFC 7296 section 2.14 prescribes.
func TestDeriveIKEKeysLengths(t *testing.T) {
	prf, err := transform.PRF(payload.PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatal(err)
	}
	const encLen, integLen = 32, 16
	_, keys := DeriveIKEKeys(prf, []byte("shared"), []byte("ni"), []byte("nr"),
		1, 2, encLen, integLen)
	for _, tc := range []struct {
		name string
		got  []byte
		want int
	}{
		{"SK_d", keys.SKd, prf.Size},
		{"SK_ai", keys.SKai, integLen},
		{"SK_ar", keys.SKar, integLen},
		{"SK_ei", keys.SKei, encLen},
		{"SK_er", keys.SKer, encLen},
		{"SK_pi", keys.SKpi, prf.Size},
		{"SK_pr", keys.SKpr, prf.Size},
	} {
		if len(tc.got) != tc.want {
			t.Errorf("%s = %d bytes, want %d", tc.name, len(tc.got), tc.want)
		}
	}
}
