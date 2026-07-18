package nebula

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The fixtures in testdata were produced by the reference implementation:
//
//	nebula-cert ca   -version 1 -name veepin-test-ca -duration 87600h
//	nebula-cert sign -name host-a -networks 10.42.0.1/24 -groups servers,dev
//	nebula-cert sign -name host-b -networks 10.42.0.2/24
//
// They are what makes these tests worth anything. Testing this codec against
// itself would prove only that it is self-consistent, which is precisely the
// failure mode that matters here: an encoder that round-trips perfectly and
// still disagrees with protobuf-go by one byte produces certificates nebula
// rejects, and the symptom would not show up until interop.

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return b
}

func loadFixtureCert(t *testing.T, name string) *Certificate {
	t.Helper()
	c, _, err := UnmarshalCertificatePEM(readFixture(t, name))
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return c
}

func TestParseReferenceCertificate(t *testing.T) {
	c := loadFixtureCert(t, "host-a.crt")

	if c.Name != "host-a" {
		t.Errorf("Name = %q, want host-a", c.Name)
	}
	if c.IsCA {
		t.Error("IsCA = true, want false for a host certificate")
	}
	if c.Curve != Curve25519 {
		t.Errorf("Curve = %v, want CURVE25519", c.Curve)
	}
	want := netip.MustParsePrefix("10.42.0.1/24")
	if len(c.Networks) != 1 || c.Networks[0] != want {
		t.Errorf("Networks = %v, want [%v]", c.Networks, want)
	}
	if got := []string{"servers", "dev"}; len(c.Groups) != 2 ||
		c.Groups[0] != got[0] || c.Groups[1] != got[1] {
		t.Errorf("Groups = %v, want %v", c.Groups, got)
	}
	if len(c.PublicKey) != X25519KeySize {
		t.Errorf("PublicKey is %d bytes, want %d", len(c.PublicKey), X25519KeySize)
	}
	if len(c.Signature) != ed25519.SignatureSize {
		t.Errorf("Signature is %d bytes, want %d", len(c.Signature), ed25519.SignatureSize)
	}

	addr, ok := c.Address()
	if !ok || addr != netip.MustParseAddr("10.42.0.1") {
		t.Errorf("Address() = %v, %v; want 10.42.0.1, true", addr, ok)
	}
}

// TestMarshalMatchesReferenceBytes is the load-bearing test in this package.
//
// A certificate's signature covers the marshalled details, and nebula verifies
// it by re-marshalling the parsed struct rather than by keeping the received
// bytes. So this encoder has to agree with protobuf-go byte for byte — not just
// produce something that parses back to the same values. Re-encoding a
// reference certificate and comparing against the original bytes is what proves
// field ordering, zero-value omission and packed repeated encoding all match.
func TestMarshalMatchesReferenceBytes(t *testing.T) {
	for _, name := range []string{"ca.crt", "host-a.crt", "host-b.crt"} {
		t.Run(name, func(t *testing.T) {
			block, _ := pem.Decode(readFixture(t, name))
			if block == nil {
				t.Fatalf("no PEM block in %s", name)
			}
			c, err := UnmarshalCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("parsing: %v", err)
			}
			if got := c.Marshal(); !bytes.Equal(got, block.Bytes) {
				t.Errorf("re-marshalled bytes differ from the reference encoding\n got: %x\nwant: %x",
					got, block.Bytes)
			}
		})
	}
}

func TestVerifyAgainstReferenceCA(t *testing.T) {
	pool, err := NewCAPoolFromPEM(readFixture(t, "ca.crt"))
	if err != nil {
		t.Fatalf("building CA pool: %v", err)
	}

	// The fixtures were signed with a ten-year CA, but pinning a time inside
	// the window keeps the test from turning into a time bomb in 2036.
	now := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)

	for _, name := range []string{"host-a.crt", "host-b.crt"} {
		c := loadFixtureCert(t, name)
		ca, err := pool.Verify(c, now)
		if err != nil {
			t.Fatalf("verifying %s: %v", name, err)
		}
		if ca.Name != "veepin-test-ca" {
			t.Errorf("%s: signed by %q, want veepin-test-ca", name, ca.Name)
		}
	}
}

// A certificate sent in a handshake omits its public key, because Noise carries
// the static key already. The receiver has to put it back before the signature
// will verify.
func TestMarshalForHandshakesElidesPublicKey(t *testing.T) {
	c := loadFixtureCert(t, "host-a.crt")

	wire := c.MarshalForHandshakes()
	if bytes.Contains(wire, c.PublicKey) {
		t.Fatal("handshake encoding still carries the public key")
	}

	got, err := UnmarshalCertificate(wire)
	if err != nil {
		t.Fatalf("parsing handshake encoding: %v", err)
	}
	if len(got.PublicKey) != 0 {
		t.Fatalf("parsed public key is %d bytes, want 0", len(got.PublicKey))
	}

	pool, err := NewCAPoolFromPEM(readFixture(t, "ca.crt"))
	if err != nil {
		t.Fatalf("building CA pool: %v", err)
	}
	now := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)

	if _, err := pool.Verify(got, now); err == nil {
		t.Error("verified without the public key restored; the signature check is not covering it")
	}

	// Restoring the key from the Noise handshake is what makes it verifiable.
	got.PublicKey = c.PublicKey
	if _, err := pool.Verify(got, now); err != nil {
		t.Errorf("verifying after restoring the public key: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	poolPEM := readFixture(t, "ca.crt")
	now := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)

	newPool := func(t *testing.T) *CAPool {
		t.Helper()
		p, err := NewCAPoolFromPEM(poolPEM)
		if err != nil {
			t.Fatalf("building CA pool: %v", err)
		}
		return p
	}

	t.Run("tampered field", func(t *testing.T) {
		c := loadFixtureCert(t, "host-a.crt")
		// Claiming a different overlay address is the attack the signature
		// exists to stop: the address is authorization, not just metadata.
		c.Networks = []netip.Prefix{netip.MustParsePrefix("10.42.0.99/24")}
		if _, err := newPool(t).Verify(c, now); err == nil {
			t.Fatal("accepted a certificate whose address was altered")
		}
	})

	t.Run("expired", func(t *testing.T) {
		c := loadFixtureCert(t, "host-a.crt")
		past := c.NotBefore.Add(-time.Hour)
		if _, err := newPool(t).Verify(c, past); err == nil {
			t.Fatal("accepted a certificate before its validity window")
		}
	})

	t.Run("untrusted issuer", func(t *testing.T) {
		c := loadFixtureCert(t, "host-a.crt")
		c.Issuer = bytes.Repeat([]byte{0xaa}, 32)
		if _, err := newPool(t).Verify(c, now); err == nil {
			t.Fatal("accepted a certificate naming an unknown issuer")
		}
	})

	t.Run("CA presented as host", func(t *testing.T) {
		ca := loadFixtureCert(t, "ca.crt")
		if _, err := newPool(t).Verify(ca, now); err == nil {
			t.Fatal("accepted a CA certificate as a host identity")
		}
	})
}

func TestCAFingerprintMatchesIssuer(t *testing.T) {
	ca := loadFixtureCert(t, "ca.crt")
	host := loadFixtureCert(t, "host-a.crt")

	if got, want := ca.Fingerprint(), hex.EncodeToString(host.Issuer); got != want {
		t.Errorf("CA fingerprint = %s, but host names issuer %s", got, want)
	}
}

func TestReadKeyFixtures(t *testing.T) {
	hostKey, err := UnmarshalX25519PrivateKeyPEM(readFixture(t, "host-a.key"))
	if err != nil {
		t.Fatalf("reading host key: %v", err)
	}
	if len(hostKey) != X25519KeySize {
		t.Errorf("host key is %d bytes, want %d", len(hostKey), X25519KeySize)
	}

	caKey, err := UnmarshalEd25519PrivateKeyPEM(readFixture(t, "ca.key"))
	if err != nil {
		t.Fatalf("reading CA key: %v", err)
	}

	// The CA key must actually correspond to the CA certificate, which also
	// confirms the two fixtures came from the same nebula-cert run.
	ca := loadFixtureCert(t, "ca.crt")
	if !bytes.Equal(caKey.Public().(ed25519.PublicKey), ca.PublicKey) {
		t.Error("CA key does not match the public key in ca.crt")
	}

	if _, err := UnmarshalX25519PrivateKeyPEM(readFixture(t, "ca.key")); err == nil {
		t.Error("accepted an Ed25519 key where an X25519 key was required")
	}
}

// Signing with veepin and verifying with veepin proves the Sign path, but the
// byte-exactness test above is what proves nebula would accept the result.
func TestSignRoundTrip(t *testing.T) {
	caKey, err := UnmarshalEd25519PrivateKeyPEM(readFixture(t, "ca.key"))
	if err != nil {
		t.Fatalf("reading CA key: %v", err)
	}
	ca := loadFixtureCert(t, "ca.crt")

	c := &Certificate{
		Name:      "signed-by-veepin",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.7/24")},
		Groups:    []string{"veepin"},
		NotBefore: time.Unix(time.Now().Add(-time.Hour).Unix(), 0),
		NotAfter:  time.Unix(time.Now().Add(24*time.Hour).Unix(), 0),
		PublicKey: bytes.Repeat([]byte{0x42}, X25519KeySize),
		Issuer:    mustHex(t, ca.Fingerprint()),
	}
	if err := c.Sign(caKey); err != nil {
		t.Fatalf("signing: %v", err)
	}

	parsed, err := UnmarshalCertificate(c.Marshal())
	if err != nil {
		t.Fatalf("parsing signed certificate: %v", err)
	}

	pool := NewCAPool()
	if err := pool.Add(ca); err != nil {
		t.Fatalf("adding CA: %v", err)
	}
	if _, err := pool.Verify(parsed, time.Now()); err != nil {
		t.Fatalf("verifying a certificate veepin signed: %v", err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding hex: %v", err)
	}
	return b
}
