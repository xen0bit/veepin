package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// testPKI mints a CA and a leaf signed by it, returned as PEM, so
// serverTLSConfig has something to load and a client something to present.
func testPKI(t *testing.T) (caPEM, certPEM, keyPEM []byte, clientCert tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "openvpn test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leaf := func(cn string, eku x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
		k, kerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if kerr != nil {
			t.Fatal(kerr)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
			DNSNames:     []string{cn},
		}
		der, derr := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if derr != nil {
			t.Fatal(derr)
		}
		return der, k
	}

	srvDER, srvKey := leaf("server.example.com", x509.ExtKeyUsageServerAuth)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})

	cliDER, cliKey := leaf("client.example.com", x509.ExtKeyUsageClientAuth)
	clientCert = tls.Certificate{Certificate: [][]byte{cliDER}, PrivateKey: cliKey}
	return caPEM, certPEM, keyPEM, clientCert
}

// TestServerNegotiatesTLS13AndMLKEM is the regression guard for a cap that was
// removed on evidence and could be restored on reflex.
//
// serverTLSConfig used to pin MaxVersion to TLS 1.2, because TLS 1.3's
// post-handshake NewSessionTicket stalled clients on OpenVPN's half-duplex
// control channel. SessionTicketsDisabled removes the cause instead of the
// version, which matters beyond tidiness: only TLS 1.3 carries a key_share, so
// at 1.2 this was the one TLS protocol in the tree whose key exchange was
// classical while every other one was hybrid post-quantum.
//
// Asserting the negotiated CurveID rather than the config is the point. A test
// that read back MaxVersion would pass on a config that never completes a
// handshake, and one that read CurvePreferences would say nothing about what
// two peers actually agreed on.
func TestServerNegotiatesTLS13AndMLKEM(t *testing.T) {
	caPEM, certPEM, keyPEM, clientCert := testPKI(t)
	cfg, err := serverTLSConfig(&ServerConfig{CA: caPEM, Cert: certPEM, Key: keyPEM})
	if err != nil {
		t.Fatalf("serverTLSConfig: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("test CA did not parse")
	}

	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	serverErr := make(chan error, 1)
	go func() { serverErr <- tls.Server(s, cfg).Handshake() }()

	cli := tls.Client(c, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		ServerName:   "server.example.com",
		MinVersion:   tls.VersionTLS12,
	})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	st := cli.ConnectionState()
	if st.Version != tls.VersionTLS13 {
		t.Errorf("negotiated TLS version = %#04x, want TLS 1.3 (%#04x); the cap is back and the "+
			"key exchange is classical again", st.Version, tls.VersionTLS13)
	}
	if st.CurveID != tls.X25519MLKEM768 {
		t.Errorf("negotiated key exchange = %v, want X25519MLKEM768", st.CurveID)
	}
}

// TestServerSuppressesSessionTickets pins the mechanism rather than its effect.
// The tickets are what stalled OpenVPN's control channel, and
// SessionTicketsDisabled is the whole reason TLS 1.3 is safe here -- so a
// future edit that drops the field while keeping MaxVersion at 1.3 would
// reintroduce the original stall against clients this repo has no cell for.
func TestServerSuppressesSessionTickets(t *testing.T) {
	caPEM, certPEM, keyPEM, _ := testPKI(t)
	cfg, err := serverTLSConfig(&ServerConfig{CA: caPEM, Cert: certPEM, Key: keyPEM})
	if err != nil {
		t.Fatalf("serverTLSConfig: %v", err)
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("SessionTicketsDisabled is off; TLS 1.3's NewSessionTicket will stall the " +
			"OpenVPN control channel, which is why the version used to be capped at 1.2")
	}
}

// mldsaPEM mints an ML-DSA-65 CA and leaf as PEM, the form every veepin facade
// loads credentials in.
func mldsaPEM(t *testing.T) (caPEM, certPEM, keyPEM []byte, clientCert tls.Certificate) {
	t.Helper()
	mk := func() (*mldsa.PrivateKey, []byte) {
		k, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatalf("marshalling an ML-DSA key to PKCS#8: %v", err)
		}
		return k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}

	caKey, _ := mk()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ML-DSA test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.PublicKey(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leaf := func(cn string, eku x509.ExtKeyUsage) ([]byte, []byte) {
		k, kPEM := mk()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
			DNSNames:     []string{cn},
		}
		der, derr := x509.CreateCertificate(rand.Reader, tmpl, caCert, k.PublicKey(), caKey)
		if derr != nil {
			t.Fatal(derr)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), kPEM
	}

	certPEM, keyPEM = leaf("server.example.com", x509.ExtKeyUsageServerAuth)
	cliCertPEM, cliKeyPEM := leaf("client.example.com", x509.ExtKeyUsageClientAuth)
	clientCert, err = tls.X509KeyPair(cliCertPEM, cliKeyPEM)
	if err != nil {
		t.Fatalf("loading an ML-DSA client keypair: %v", err)
	}
	return caPEM, certPEM, keyPEM, clientCert
}

// TestServerAcceptsMLDSACredentials is post-quantum AUTHENTICATION reaching a
// real veepin facade, rather than a standard-library demonstration.
//
// doc/security.md's boundary is that hybrid key exchange protects the key
// exchange and not the authentication. Go 1.27 makes the other half reachable,
// and the question that then matters is operational: do veepin's own credential
// paths carry an ML-DSA key at all? They load PEM and hand it to
// tls.X509KeyPair, so this exercises PKCS#8 marshalling, PEM round-tripping,
// chain verification against an ML-DSA CA, and a MUTUALLY authenticated
// handshake -- OpenVPN's server requires a client certificate, so both
// signatures here are post-quantum.
//
// Nothing about this is OpenVPN-specific beyond it being the facade whose TLS
// config is reachable from a test. Every TLS protocol in the tree loads
// credentials the same way.
func TestServerAcceptsMLDSACredentials(t *testing.T) {
	caPEM, certPEM, keyPEM, clientCert := mldsaPEM(t)
	cfg, err := serverTLSConfig(&ServerConfig{CA: caPEM, Cert: certPEM, Key: keyPEM})
	if err != nil {
		t.Fatalf("serverTLSConfig with ML-DSA credentials: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the ML-DSA CA did not parse")
	}

	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	serverErr := make(chan error, 1)
	go func() { serverErr <- tls.Server(s, cfg).Handshake() }()

	cli := tls.Client(c, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		ServerName:   "server.example.com",
		MinVersion:   tls.VersionTLS13,
	})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake with ML-DSA credentials: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake with ML-DSA credentials: %v", err)
	}

	st := cli.ConnectionState()
	if st.CurveID != tls.X25519MLKEM768 {
		t.Errorf("key exchange = %v, want X25519MLKEM768", st.CurveID)
	}
	if got := st.PeerCertificates[0].PublicKeyAlgorithm; got != x509.MLDSA {
		t.Errorf("server certificate key algorithm = %v, want ML-DSA; the authentication half "+
			"is still classical", got)
	}
}
