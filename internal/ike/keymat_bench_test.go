package ike

import (
	"crypto/rand"
	"testing"

	"github.com/xen0bit/veepin/internal/ikev2/transform"
	"github.com/xen0bit/veepin/internal/payload"
)

// BenchmarkDeriveIKEKeys measures full IKE SA key derivation (SKEYSEED + prf+
// expansion of the seven SK_* keys) — once per handshake.
func BenchmarkDeriveIKEKeys(b *testing.B) {
	prf, _ := transform.PRF(payload.PRF_HMAC_SHA2_256)
	shared := keymatRandBytes(32)
	ni := keymatRandBytes(32)
	nr := keymatRandBytes(32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DeriveIKEKeys(prf, shared, ni, nr, 0x1111, 0x2222, 32, 0)
	}
}

// BenchmarkDeriveChildKeys measures Child SA key derivation — once per Child SA.
func BenchmarkDeriveChildKeys(b *testing.B) {
	prf, _ := transform.PRF(payload.PRF_HMAC_SHA2_256)
	skd := keymatRandBytes(32)
	ni := keymatRandBytes(32)
	nr := keymatRandBytes(32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DeriveChildKeys(prf, skd, nil, ni, nr, 2*36) // two AES-256-GCM keys
	}
}

func keymatRandBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
