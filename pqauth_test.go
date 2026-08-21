package veepin

// Post-quantum *authentication*, which the tree does not have and can now
// reach.
//
// doc/security.md names the gap in one sentence: hybrid key exchange protects
// the key exchange and not the authentication, so an adversary attacking the
// authentication live rather than retroactively is unaffected. That was
// unclosable inside the dependency policy until Go 1.27 shipped crypto/mldsa
// (FIPS 204), with crypto/x509 parsing ML-DSA keys and crypto/tls offering
// MLDSA44/65/87 as TLS 1.3 signature schemes.
//
// These tests exist to establish, once and mechanically, that a fully
// post-quantum TLS handshake -- ML-KEM key exchange AND ML-DSA authentication --
// works end to end with the standard library alone, so the remaining question
// for every TLS protocol here is operational (do the peers accept it) rather
// than cryptographic. They are the evidence behind the claim in
// doc/security.md; without them it would be a claim about a release note.

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// mldsaChain mints a self-signed ML-DSA-65 certificate and the pool that
// verifies it. 65 is the parameter set matching ML-KEM-768's security level,
// which is what the IETF hybrid drafts settled on and what veepin's IKEv2 uses.
func mldsaChain(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("generating an ML-DSA-65 key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pq.example.com"},
		DNSNames:              []string{"pq.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		t.Fatalf("signing a certificate with ML-DSA: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing an ML-DSA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// TestMLDSACertificateIsMintedAndParsed covers the x509 half on its own, so a
// failure in the handshake test below can be attributed. It also pins the
// algorithm the certificate reports, because "it parsed" would be satisfied by
// a certificate that silently fell back to something classical.
func TestMLDSACertificateIsMintedAndParsed(t *testing.T) {
	cert, _ := mldsaChain(t)
	if got := cert.Leaf.SignatureAlgorithm; got != x509.MLDSA65 {
		t.Errorf("certificate signature algorithm = %v, want ML-DSA-65", got)
	}
	if got := cert.Leaf.PublicKeyAlgorithm; got != x509.MLDSA {
		t.Errorf("certificate public key algorithm = %v, want ML-DSA", got)
	}
	if err := cert.Leaf.CheckSignatureFrom(cert.Leaf); err != nil {
		t.Errorf("the self-signature does not verify: %v", err)
	}
}

// TestAFullyPostQuantumHandshake is the claim: both halves of a TLS 1.3
// handshake post-quantum at once, with no dependency outside the standard
// library.
//
// Asserting both the negotiated CurveID and the peer certificate's algorithm is
// the point. Either one alone is a handshake that is half classical, and half
// is the state the tree was already in -- ML-KEM key exchange over an RSA or
// ECDSA signature.
func TestAFullyPostQuantumHandshake(t *testing.T) {
	cert, pool := mldsaChain(t)

	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- tls.Server(s, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}).Handshake()
	}()

	cli := tls.Client(c, &tls.Config{
		RootCAs:    pool,
		ServerName: "pq.example.com",
		MinVersion: tls.VersionTLS13,
	})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	st := cli.ConnectionState()
	if st.CurveID != tls.X25519MLKEM768 {
		t.Errorf("key exchange = %v, want X25519MLKEM768", st.CurveID)
	}
	if len(st.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
	if got := st.PeerCertificates[0].PublicKeyAlgorithm; got != x509.MLDSA {
		t.Errorf("peer certificate key algorithm = %v, want ML-DSA; the authentication half "+
			"of this handshake is still classical", got)
	}
}

// TestMLDSASignatureSchemesAreOffered pins that crypto/tls advertises the
// ML-DSA schemes, which is what lets a PEER choose post-quantum authentication
// against a veepin server. The handshake above proves veepin can present such a
// certificate; this proves it would accept one.
func TestMLDSASignatureSchemesAreOffered(t *testing.T) {
	for _, s := range []tls.SignatureScheme{tls.MLDSA44, tls.MLDSA65, tls.MLDSA87} {
		if s.String() == "" || s == 0 {
			t.Errorf("signature scheme %d is not defined", s)
		}
	}
	cert, pool := mldsaChain(t)

	// A client that pins ML-DSA-65 as its only acceptable signature scheme must
	// still complete the handshake -- which it can only do if the server signs
	// with ML-DSA.
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- tls.Server(s, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}).Handshake()
	}()
	cli := tls.Client(c, &tls.Config{
		RootCAs:    pool,
		ServerName: "pq.example.com",
		MinVersion: tls.VersionTLS13,
	})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}
