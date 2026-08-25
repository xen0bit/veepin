package ike

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// testCA is a throwaway CA that issues leaf certificates for the cert-auth
// tests, plus a root pool that trusts it.
type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "veepin test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue mints a leaf certificate with the given DNS SAN and key, signed by the
// CA, and returns a credential ready to authenticate with.
func (ca *testCA) issue(t *testing.T, dnsName string, key crypto.Signer) *certCredential {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := newCertCredential(leaf, [][]byte{der}, key)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// issueTLS mints a leaf certificate and returns it as a crypto/tls certificate,
// the form both ClientConfig.ClientCert and Config.ServerCert take.
func (ca *testCA) issueTLS(t *testing.T, dnsName string, key crypto.Signer) *tls.Certificate {
	t.Helper()
	cred := ca.issue(t, dnsName, key)
	return &tls.Certificate{
		Certificate: cred.chain,
		PrivateKey:  key,
		Leaf:        cred.leaf,
	}
}

func ecKey(t *testing.T, c elliptic.Curve) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsaKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestDigitalSignatureRoundTrip signs the AuthOctets with method 14 and verifies
// it with the leaf's public key, for both RSA and every ECDSA curve — the core
// proof that our RFC 7427 encoding is self-consistent.
func TestDigitalSignatureRoundTrip(t *testing.T) {
	ca := newTestCA(t)
	octets := []byte("real message | nonce | prf(SKp, ID) — the signed octets")

	cases := []struct {
		name string
		key  crypto.Signer
	}{
		{"RSA-2048", rsaKey(t)},
		{"ECDSA-P256", ecKey(t, elliptic.P256())},
		{"ECDSA-P384", ecKey(t, elliptic.P384())},
		{"ECDSA-P521", ecKey(t, elliptic.P521())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred := ca.issue(t, "peer.example", tc.key)
			// Peer advertises all hashes.
			peerHashes := []uint16{payload.HashSHA256, payload.HashSHA384, payload.HashSHA512}
			method, data, err := signAuthDigital(cred, octets, peerHashes)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if method != payload.AuthDigitalSig {
				t.Fatalf("method = %d, want %d", method, payload.AuthDigitalSig)
			}
			if err := verifyAuthDigital(cred.signer.Public(), octets, data); err != nil {
				t.Fatalf("verify: %v", err)
			}
			// A tampered octet set must fail.
			if err := verifyAuthDigital(cred.signer.Public(), append(octets, '!'), data); err == nil {
				t.Fatal("verify accepted a signature over different octets")
			}
		})
	}
}

// TestDigitalSignatureWrongKey ensures a signature does not verify under an
// unrelated key.
func TestDigitalSignatureWrongKey(t *testing.T) {
	ca := newTestCA(t)
	octets := []byte("octets")
	cred := ca.issue(t, "peer.example", ecKey(t, elliptic.P256()))
	_, data, err := signAuthDigital(cred, octets, nil)
	if err != nil {
		t.Fatal(err)
	}
	other := ecKey(t, elliptic.P256())
	if err := verifyAuthDigital(other.Public(), octets, data); err == nil {
		t.Fatal("signature verified under the wrong key")
	}
}

// TestLegacyRSARoundTrip covers the AUTH method 1 fallback.
func TestLegacyRSARoundTrip(t *testing.T) {
	ca := newTestCA(t)
	octets := []byte("octets for legacy rsa")
	cred := ca.issue(t, "peer.example", rsaKey(t))
	method, sig, err := signAuthRSALegacy(cred, octets)
	if err != nil {
		t.Fatal(err)
	}
	if method != payload.AuthRSASig {
		t.Fatalf("method = %d, want %d", method, payload.AuthRSASig)
	}
	if err := verifyAuthRSALegacy(cred.signer.Public(), octets, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := verifyAuthRSALegacy(cred.signer.Public(), []byte("tampered"), sig); err == nil {
		t.Fatal("legacy verify accepted a signature over different octets")
	}
}

// TestChooseSigAlgHonorsPeerHashes proves the scheme selection respects the
// peer's advertised hash list and the key family.
func TestChooseSigAlgHonorsPeerHashes(t *testing.T) {
	// ECDSA-P256 with a peer that only accepts SHA-512 must fall back to SHA-512.
	k := ecKey(t, elliptic.P256())
	alg, err := chooseSigAlg(k.Public(), []uint16{payload.HashSHA512})
	if err != nil {
		t.Fatal(err)
	}
	if alg.hashID != payload.HashSHA512 || alg.family != famECDSA {
		t.Fatalf("chose %+v, want ECDSA/SHA-512", alg)
	}
	// No common hash → error.
	if _, err := chooseSigAlg(k.Public(), []uint16{99}); err == nil {
		t.Fatal("expected no-common-hash error")
	}
}

// TestVerifyPeerCertChain proves chain verification accepts a CA-issued leaf and
// rejects a self-signed stranger, and that the identity check binds the cert to
// the claimed IKE ID.
func TestVerifyPeerCertChain(t *testing.T) {
	ca := newTestCA(t)
	cred := ca.issue(t, "gateway.example", ecKey(t, elliptic.P256()))

	leaf, err := verifyPeerCertChain(cred.chain[0], nil, ca.pool)
	if err != nil {
		t.Fatalf("trusted leaf rejected: %v", err)
	}
	if err := certMatchesID(leaf, payload.IDPayload{Type: payload.IDFQDN, Data: []byte("gateway.example")}); err != nil {
		t.Fatalf("identity match failed: %v", err)
	}
	if err := certMatchesID(leaf, payload.IDPayload{Type: payload.IDFQDN, Data: []byte("evil.example")}); err == nil {
		t.Fatal("identity check accepted a non-matching FQDN")
	}

	// A leaf from an untrusted CA must not verify against our pool.
	strangerCA := newTestCA(t)
	stranger := strangerCA.issue(t, "gateway.example", ecKey(t, elliptic.P256()))
	if _, err := verifyPeerCertChain(stranger.chain[0], nil, ca.pool); err == nil {
		t.Fatal("untrusted leaf was accepted")
	}
}
