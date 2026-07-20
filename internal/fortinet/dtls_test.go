package fortinet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// selfSignedECDSA builds a certificate valid for 127.0.0.1, plus a pool that
// trusts it -- the same trust the HTTPS login and the DTLS channel share.
func selfSignedECDSA(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "veepin-fortinet-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// dtlsTestServer starts a Fortinet server whose HTTPS control plane and UDP data
// channel share one certificate, and returns it with the client's trust pool.
func dtlsTestServer(t *testing.T, srv *Server, cert tls.Certificate) (base string, udpAddr *net.UDPAddr) {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	serve, err := srv.EnableDTLS(udp)
	if err != nil {
		t.Fatal(err)
	}
	go serve()

	ts := httptest.NewUnstartedServer(srv)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts.URL, udp.LocalAddr().(*net.UDPAddr)
}

// The whole Fortinet stack over the UDP data channel: HTTPS login, a config that
// advertises DTLS, the certificate-based DTLS handshake, the GFtype cookie
// exchange, PPP, and an IP packet each way.
func TestDTLSEndToEnd(t *testing.T) {
	cert, roots := selfSignedECDSA(t)
	pool, gateway, err := newTestPool()
	if err != nil {
		t.Fatal(err)
	}
	serverTUN := newFakeTUN()
	srv, err := NewServer(ServerConfig{
		Users:       map[string]string{"alice": "s3cret"},
		Pool:        pool,
		ServerIP:    gateway,
		DNS:         []net.IP{net.IPv4(1, 1, 1, 1)},
		Certificate: &cert,
	}, serverTUN)
	if err != nil {
		t.Fatal(err)
	}
	go srv.RunTUN()
	defer srv.Close()

	base, udpAddr := dtlsTestServer(t, srv, cert)

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
	}
	cfg, cookie, err := Login(hc, base, "alice", "s3cret", "", nil)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !cfg.DTLS {
		t.Fatal("server with a DTLS channel did not advertise dtls=1")
	}
	clientIP := cfg.AssignedIP

	udp, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	dc, err := DialDTLS(udp, cookie, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("DialDTLS: %v", err)
	}

	clientTUN := newFakeTUN()
	client, err := RunDTLSClient(dc, cfg, clientTUN, nil)
	if err != nil {
		t.Fatalf("RunDTLSClient: %v", err)
	}
	defer client.Close()

	clientTUN.inbound <- ipv4(clientIP, gateway, "ping")
	select {
	case got := <-serverTUN.outbound:
		if string(got[20:]) != "ping" {
			t.Errorf("server TUN payload = %q, want ping", got[20:])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("packet did not reach the server TUN over DTLS")
	}

	serverTUN.inbound <- ipv4(gateway, clientIP, "pong")
	select {
	case got := <-clientTUN.outbound:
		if string(got[20:]) != "pong" {
			t.Errorf("client TUN payload = %q, want pong", got[20:])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("packet did not reach the client TUN over DTLS")
	}
}

// A DTLS session that presents a cookie the login never issued must be refused:
// the certificate proves the server, not the client, so the cookie is the only
// thing standing between a stranger's handshake and a PPP link.
func TestDTLSRejectsUnknownCookie(t *testing.T) {
	cert, roots := selfSignedECDSA(t)
	pool, gateway, err := newTestPool()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{
		Users:       map[string]string{"alice": "s3cret"},
		Pool:        pool,
		ServerIP:    gateway,
		Certificate: &cert,
	}, newFakeTUN())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	_, udpAddr := dtlsTestServer(t, srv, cert)

	udp, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DialDTLS(udp, "not-a-cookie", &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"}); err == nil {
		t.Fatal("DialDTLS succeeded with a cookie the server never issued")
	}
	if n := srv.Clients(); n != 0 {
		t.Errorf("server has %d links after a rejected session, want 0", n)
	}
}

// A client that will not trust the gateway's certificate must not get a session:
// the DTLS channel is not a weaker second door into the same server.
func TestDTLSRejectsUntrustedCertificate(t *testing.T) {
	cert, _ := selfSignedECDSA(t)
	_, otherRoots := selfSignedECDSA(t)
	pool, gateway, err := newTestPool()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{
		Users:       map[string]string{"alice": "s3cret"},
		Pool:        pool,
		ServerIP:    gateway,
		Certificate: &cert,
	}, newFakeTUN())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	_, udpAddr := dtlsTestServer(t, srv, cert)

	udp, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DialDTLS(udp, "cookie", &tls.Config{RootCAs: otherRoots, ServerName: "127.0.0.1"}); err == nil {
		t.Fatal("DialDTLS accepted a certificate signed by an untrusted CA")
	}
}

// EnableDTLS must refuse a server that has no certificate rather than bind a
// socket that could never complete a handshake.
func TestEnableDTLSRequiresCertificate(t *testing.T) {
	pool, gateway, _ := newTestPool()
	srv, err := NewServer(ServerConfig{
		Users: map[string]string{"alice": "s3cret"}, Pool: pool, ServerIP: gateway,
	}, newFakeTUN())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if _, err := srv.EnableDTLS(udp); err == nil {
		t.Fatal("EnableDTLS bound a channel with no certificate")
	}
}

// The path a real client takes: bring the TLS tunnel up first, then attach DTLS
// to the same session and keep going. The PPP session must survive the switch,
// egress must move to UDP, and losing UDP must fall back rather than end the
// tunnel.
func TestDTLSAttachesToTLSTunnel(t *testing.T) {
	cert, roots := selfSignedECDSA(t)
	pool, gateway, err := newTestPool()
	if err != nil {
		t.Fatal(err)
	}
	serverTUN := newFakeTUN()
	srv, err := NewServer(ServerConfig{
		Users:       map[string]string{"alice": "s3cret"},
		Pool:        pool,
		ServerIP:    gateway,
		Certificate: &cert,
	}, serverTUN)
	if err != nil {
		t.Fatal(err)
	}
	go srv.RunTUN()
	defer srv.Close()

	base, udpAddr := dtlsTestServer(t, srv, cert)
	host := strings.TrimPrefix(base, "https://")

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	cfg, cookie, err := Login(hc, base, "alice", "s3cret", "", nil)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	clientIP := cfg.AssignedIP

	conn, err := tls.Dial("tcp", host, &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(TunnelRequest(host, cookie)); err != nil {
		t.Fatal(err)
	}
	clientTUN := newFakeTUN()
	client, err := RunClient(conn, cfg, clientTUN, nil)
	if err != nil {
		t.Fatalf("RunClient: %v", err)
	}
	defer client.Close()

	// The same cookie, now naming an active tunnel, must attach rather than be
	// refused as spent.
	udp, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	dc, err := DialDTLS(udp, cookie, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("DialDTLS onto an established tunnel: %v", err)
	}
	client.AttachDTLS(dc)

	roundTrip(t, clientTUN, serverTUN, clientIP, gateway, "over-dtls")

	// Losing the UDP carrier must detach, not end the tunnel: the same session
	// keeps moving packets over the TLS connection that was never closed.
	//
	// Recovery is eventual, not immediate, and that is the protocol rather than
	// the test being lenient. The far end cannot learn the carrier is gone until
	// its read loop sees the close, and a datagram written to the dead carrier in
	// the meantime is simply lost -- ordinary UDP loss, which is what the inner
	// traffic (a retrying ping, a retransmitting TCP) already copes with. So the
	// proof the link survived is that packets cross again, not that the very next
	// one does.
	_ = dc.Close()
	roundTripEventually(t, clientTUN, serverTUN, clientIP, gateway, "after-detach")

	if n := srv.Clients(); n != 1 {
		t.Errorf("server has %d links, want 1 (the attach must not have made a second)", n)
	}
}

// roundTripEventually retries a round trip until one completes, for the window
// after a carrier is lost in which datagrams may still be written to it.
func roundTripEventually(t *testing.T, clientTUN, serverTUN *fakeTUN, clientIP, gateway net.IP, tag string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		if tryRoundTrip(clientTUN, serverTUN, clientIP, gateway, tag, time.Second) {
			if attempt > 1 {
				t.Logf("%s: crossed on attempt %d, after the detach lost the datagrams in flight", tag, attempt)
			}
			return
		}
	}
	t.Fatalf("%s: no packet crossed in either direction after the carrier was lost", tag)
}

// tryRoundTrip sends a packet each way and reports whether both arrived within
// the timeout.
func tryRoundTrip(clientTUN, serverTUN *fakeTUN, clientIP, gateway net.IP, tag string, timeout time.Duration) bool {
	select {
	case clientTUN.inbound <- ipv4(clientIP, gateway, tag):
	case <-time.After(timeout):
		return false
	}
	select {
	case <-serverTUN.outbound:
	case <-time.After(timeout):
		return false
	}
	select {
	case serverTUN.inbound <- ipv4(gateway, clientIP, tag):
	case <-time.After(timeout):
		return false
	}
	select {
	case <-clientTUN.outbound:
		return true
	case <-time.After(timeout):
		return false
	}
}

// roundTrip sends a packet each way and fails if either does not arrive.
func roundTrip(t *testing.T, clientTUN, serverTUN *fakeTUN, clientIP, gateway net.IP, tag string) {
	t.Helper()
	clientTUN.inbound <- ipv4(clientIP, gateway, tag)
	select {
	case got := <-serverTUN.outbound:
		if string(got[20:]) != tag {
			t.Errorf("server TUN payload = %q, want %q", got[20:], tag)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: packet did not reach the server TUN", tag)
	}
	serverTUN.inbound <- ipv4(gateway, clientIP, tag)
	select {
	case got := <-clientTUN.outbound:
		if string(got[20:]) != tag {
			t.Errorf("client TUN payload = %q, want %q", got[20:], tag)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: packet did not reach the client TUN", tag)
	}
}
