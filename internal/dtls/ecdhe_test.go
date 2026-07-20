package dtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedECDSA returns a throwaway ECDSA P-256 certificate and key, as a
// Fortinet gateway presents.
func selfSignedECDSA(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dtls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestECDHEHandshakeAndDataPath drives a full certificate-based ECDHE handshake
// over real UDP sockets and moves datagrams both ways. It exercises the parts a
// PSK handshake does not: the Certificate message, the signed ServerKeyExchange,
// the client's signature check, and the ECDH premaster -- all on top of the same
// record layer and key schedule the PSK path uses.
func TestECDHEHandshakeAndDataPath(t *testing.T) {
	cliConn, srvConn := udpPair(t)
	cert := selfSignedECDSA(t)

	type result struct {
		c   *Conn
		err error
	}
	srvCh := make(chan result, 1)
	go func() {
		c, err := Server(srvConn, Config{Certificate: &cert, HandshakeTimeout: 10 * time.Second})
		srvCh <- result{c, err}
	}()

	// The client skips chain validation (the cert is self-signed) but still
	// verifies the ServerKeyExchange signature against it.
	cli, err := Client(cliConn, Config{InsecureSkipVerify: true, HandshakeTimeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	got := <-srvCh
	if got.err != nil {
		t.Fatalf("server handshake: %v", got.err)
	}
	srv := got.c

	if cli.CipherSuite() != tlsECDHEECDSAWithAES128GCMSHA256 {
		t.Errorf("suite = %#04x, want ECDHE-ECDSA-AES128-GCM", cli.CipherSuite())
	}

	msg := []byte("ecdhe datagram round trip")
	if _, err := cli.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Errorf("server got %q, want %q", buf[:n], msg)
	}

	reply := []byte("and back")
	if _, err := srv.Write(reply); err != nil {
		t.Fatal(err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = cli.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf[:n], reply) {
		t.Errorf("client got %q, want %q", buf[:n], reply)
	}
}

// A client that tampers with nothing but is given a certificate signed by a
// different key must reject the ServerKeyExchange: the signature is what binds
// the ephemeral key to the certificate, so a mismatch is a MITM.
func TestECDHERejectsBadSignature(t *testing.T) {
	// Verify the signature check directly: sign with one key, present another
	// certificate.
	real := selfSignedECDSA(t)
	other := selfSignedECDSA(t)

	_, pub, err := newECDHEKey()
	if err != nil {
		t.Fatal(err)
	}
	params := ecdheServerParams(pub)
	cRand, sRand := make([]byte, 32), make([]byte, 32)
	sig, err := signECDHE(real.PrivateKey.(crypto.Signer), cRand, sRand, params)
	if err != nil {
		t.Fatal(err)
	}
	ske := serverKeyExchangeECDHE{pubkey: pub, params: params, signature: sig}
	if err := verifyECDHESignature(other.Certificate[0], cRand, sRand, ske); err == nil {
		t.Error("a signature made by a different key verified against the wrong certificate")
	}
}

// coalescingConn buffers writes and flushes them as a single datagram when the
// caller next reads. A DTLS peer writes its whole final flight -- here
// ClientKeyExchange, ChangeCipherSpec, Finished -- and then reads for the reply,
// so this turns that burst into one datagram, which is exactly what GnuTLS (and
// thus openconnect) does. It reproduces, without a network, the coalescing that
// made the server drop the client's Finished.
type coalescingConn struct {
	net.Conn
	pending     []byte
	passthrough bool // once the handshake is done, app data must not be buffered
}

func (c *coalescingConn) Write(b []byte) (int, error) {
	if c.passthrough {
		return c.Conn.Write(b)
	}
	c.pending = append(c.pending, b...)
	return len(b), nil
}

func (c *coalescingConn) flush() error {
	if len(c.pending) == 0 {
		return nil
	}
	_, err := c.Conn.Write(c.pending)
	c.pending = c.pending[:0]
	return err
}

func (c *coalescingConn) Read(p []byte) (int, error) {
	if err := c.flush(); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

// The server must complete a handshake with a client that coalesces its
// ClientKeyExchange, ChangeCipherSpec and Finished into one datagram. Before the
// deferred-record fix the server dropped the Finished -- it arrived encrypted in
// the same datagram as the ClientKeyExchange, before the keys were installed --
// and the handshake stalled until it timed out.
func TestECDHEServerAcceptsCoalescedFinalFlight(t *testing.T) {
	cliConn, srvConn := udpPair(t)
	cert := selfSignedECDSA(t)

	type result struct {
		c   *Conn
		err error
	}
	srvCh := make(chan result, 1)
	go func() {
		c, err := Server(srvConn, Config{Certificate: &cert, HandshakeTimeout: 5 * time.Second})
		srvCh <- result{c, err}
	}()

	cc := &coalescingConn{Conn: cliConn}
	cli, err := Client(cc, Config{InsecureSkipVerify: true, HandshakeTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	// The handshake is done; further writes are application data and must go out
	// as they are made rather than wait for a read that may never come.
	cc.passthrough = true
	got := <-srvCh
	if got.err != nil {
		t.Fatalf("server handshake with a coalesced final flight: %v", got.err)
	}
	srv := got.c

	// The link must actually carry data, not merely complete the handshake.
	msg := []byte("coalesced flight round trip")
	if _, err := cli.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatalf("server read after coalesced handshake: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Errorf("server read %q, want %q", buf[:n], msg)
	}
}
