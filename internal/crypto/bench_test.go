package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/xen0bit/ikennkt/internal/payload"
)

// BenchmarkDHGenerate measures ephemeral key generation per group — this runs
// once per handshake on each side.
func BenchmarkDHGenerate(b *testing.B) {
	groups := []struct {
		name string
		id   uint16
	}{
		{"Curve25519", payload.DH_CURVE25519},
		{"ECP-256", payload.DH_ECP_256},
		{"ECP-384", payload.DH_ECP_384},
		{"MODP-2048", payload.DH_MODP_2048},
	}
	for _, g := range groups {
		b.Run(g.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				grp, err := NewDHGroup(g.id)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := grp.Generate(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDHComputeSecret measures the shared-secret computation — the
// dominant asymmetric cost of the handshake.
func BenchmarkDHComputeSecret(b *testing.B) {
	groups := []struct {
		name string
		id   uint16
	}{
		{"Curve25519", payload.DH_CURVE25519},
		{"ECP-256", payload.DH_ECP_256},
		{"ECP-384", payload.DH_ECP_384},
		{"MODP-2048", payload.DH_MODP_2048},
	}
	for _, g := range groups {
		b.Run(g.name, func(b *testing.B) {
			a, _ := NewDHGroup(g.id)
			peer, _ := NewDHGroup(g.id)
			_, _ = a.Generate()
			peerPub, _ := peer.Generate()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := a.ComputeSecret(peerPub); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDeriveIKEKeys measures full IKE SA key derivation (SKEYSEED + prf+
// expansion of the seven SK_* keys) — once per handshake.
func BenchmarkDeriveIKEKeys(b *testing.B) {
	prf, _ := NewPRF(payload.PRF_HMAC_SHA2_256)
	shared := randBytes(32)
	ni := randBytes(32)
	nr := randBytes(32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DeriveIKEKeys(prf, shared, ni, nr, 0x1111, 0x2222, 32, 0)
	}
}

// BenchmarkDeriveChildKeys measures Child SA key derivation — once per Child SA.
func BenchmarkDeriveChildKeys(b *testing.B) {
	prf, _ := NewPRF(payload.PRF_HMAC_SHA2_256)
	skd := randBytes(32)
	ni := randBytes(32)
	nr := randBytes(32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DeriveChildKeys(prf, skd, nil, ni, nr, 2*36) // two AES-256-GCM keys
	}
}

// BenchmarkPRFPlus measures prf+ expansion at a representative output length.
func BenchmarkPRFPlus(b *testing.B) {
	for _, id := range []struct {
		name string
		id   uint16
	}{
		{"SHA1", payload.PRF_HMAC_SHA1},
		{"SHA256", payload.PRF_HMAC_SHA2_256},
		{"SHA512", payload.PRF_HMAC_SHA2_512},
	} {
		b.Run(id.name, func(b *testing.B) {
			prf, _ := NewPRF(id.id)
			key := randBytes(prf.Size)
			seed := randBytes(80)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				prf.Plus(key, seed, 128)
			}
		})
	}
}

// BenchmarkCipherSeal measures raw SK-cipher seal throughput on a handshake-
// sized payload (distinct from the ESP data-plane benchmarks).
func BenchmarkCipherSeal(b *testing.B) {
	ciphers := []struct {
		name    string
		encr    uint16
		keyBits int
	}{
		{"AES128-GCM", payload.ENCR_AES_GCM_16, 128},
		{"AES256-GCM", payload.ENCR_AES_GCM_16, 256},
	}
	pt := randBytes(256)
	aad := randBytes(32)
	for _, c := range ciphers {
		b.Run(c.name, func(b *testing.B) {
			sk, err := NewSKCipher(c.encr, c.keyBits)
			if err != nil {
				b.Fatal(err)
			}
			key := randBytes(sk.KeyLen())
			b.SetBytes(int64(len(pt)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := sk.Seal(key, nil, aad, pt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

var _ = fmt.Sprintf
