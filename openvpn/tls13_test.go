package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
