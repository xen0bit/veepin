package transform

import (
	"testing"

	"github.com/xen0bit/veepin/internal/payload"
)

// TestLookupsCoverNegotiableTransforms asserts every transform ID the IKE layer
// can negotiate resolves to a primitive. A gap here would surface as a handshake
// that completes and then fails on first packet.
func TestLookupsCoverNegotiableTransforms(t *testing.T) {
	t.Run("ENCR", func(t *testing.T) {
		for _, id := range []uint16{payload.ENCR_AES_GCM_16, payload.ENCR_AES_CBC} {
			if _, err := Cipher(id, 256); err != nil {
				t.Errorf("Cipher(%d): %v", id, err)
			}
		}
	})
	t.Run("PRF", func(t *testing.T) {
		for _, id := range []uint16{
			payload.PRF_HMAC_SHA1, payload.PRF_HMAC_SHA2_256,
			payload.PRF_HMAC_SHA2_384, payload.PRF_HMAC_SHA2_512,
		} {
			p, err := PRF(id)
			if err != nil {
				t.Errorf("PRF(%d): %v", id, err)
				continue
			}
			if p.Size == 0 || p.PreferredKeyLen != p.Size {
				t.Errorf("PRF(%d): Size=%d PreferredKeyLen=%d", id, p.Size, p.PreferredKeyLen)
			}
		}
	})
	t.Run("INTEG", func(t *testing.T) {
		// Key and truncated-ICV lengths per RFC 4868 / RFC 2404.
		want := map[uint16][2]int{
			payload.AUTH_HMAC_SHA1_96:      {20, 12},
			payload.AUTH_HMAC_SHA2_256_128: {32, 16},
			payload.AUTH_HMAC_SHA2_384_192: {48, 24},
			payload.AUTH_HMAC_SHA2_512_256: {64, 32},
		}
		for id, w := range want {
			ig, err := Integrity(id)
			if err != nil {
				t.Errorf("Integrity(%d): %v", id, err)
				continue
			}
			if ig.KeyLen != w[0] || ig.ICVLen != w[1] {
				t.Errorf("Integrity(%d) = key %d/icv %d, want key %d/icv %d",
					id, ig.KeyLen, ig.ICVLen, w[0], w[1])
			}
		}
	})
	t.Run("DH", func(t *testing.T) {
		for _, id := range []uint16{
			payload.DH_CURVE25519, payload.DH_ECP_256, payload.DH_ECP_384,
			payload.DH_ECP_521, payload.DH_MODP_2048,
		} {
			if _, err := DH(id); err != nil {
				t.Errorf("DH(%d): %v", id, err)
			}
		}
	})
}

func TestUnsupportedIDsRejected(t *testing.T) {
	if _, err := Cipher(0, 256); err == nil {
		t.Error("Cipher accepted ID 0")
	}
	if _, err := PRF(9999); err == nil {
		t.Error("PRF accepted ID 9999")
	}
	if _, err := Integrity(9999); err == nil {
		t.Error("Integrity accepted ID 9999")
	}
	if _, err := DH(9999); err == nil {
		t.Error("DH accepted ID 9999")
	}
	if _, err := ESPCrypter(9999, 256, make([]byte, 36), 0, nil); err == nil {
		t.Error("ESPCrypter accepted ENCR 9999")
	}
}

// TestESPCrypterHonorsNegotiatedID pins the behavior that replaced esp's old
// inference: the transform ID selects the algorithm, rather than being guessed
// from key length and whether an integrity transform is present. A CBC suite and
// a GCM suite must produce different overheads even though both are reachable
// with a 256-bit key.
func TestESPCrypterHonorsNegotiatedID(t *testing.T) {
	gcm, err := ESPCrypter(payload.ENCR_AES_GCM_16, 256, make([]byte, 36), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gcm.BlockLen() != 1 {
		t.Errorf("GCM BlockLen = %d, want 1 (stream/AEAD)", gcm.BlockLen())
	}

	cbc, err := ESPCrypter(payload.ENCR_AES_CBC, 256, make([]byte, 32),
		payload.AUTH_HMAC_SHA2_256_128, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if cbc.BlockLen() != 16 {
		t.Errorf("CBC BlockLen = %d, want 16", cbc.BlockLen())
	}
	if gcm.Overhead() == cbc.Overhead() {
		t.Errorf("GCM and CBC overheads both %d; the negotiated ID is not selecting the algorithm",
			gcm.Overhead())
	}
}

// TestESPCrypterCBCRequiresIntegrity guards the one combination the old
// inference could silently mis-handle: a CBC suite with no integrity transform
// must be rejected, not treated as AEAD.
func TestESPCrypterCBCRequiresIntegrity(t *testing.T) {
	if _, err := ESPCrypter(payload.ENCR_AES_CBC, 256, make([]byte, 32), 0, nil); err == nil {
		t.Fatal("CBC ESP accepted without an integrity transform")
	}
}
