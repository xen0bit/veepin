package sstp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/ppp"
	"github.com/xen0bit/veepin/internal/sstp/wire"
	"github.com/xen0bit/veepin/internal/vlog"
)

// fakeTUN records what the server writes to its TUN.
type fakeTUN struct {
	mu      sync.Mutex
	written [][]byte
	closed  chan struct{}
}

func newFakeTUN() *fakeTUN { return &fakeTUN{closed: make(chan struct{})} }

func (f *fakeTUN) Read([]byte) (int, error) { <-f.closed; return 0, net.ErrClosed }
func (f *fakeTUN) Write(p []byte) (int, error) {
	f.mu.Lock()
	f.written = append(f.written, append([]byte(nil), p...))
	f.mu.Unlock()
	return len(p), nil
}
func (f *fakeTUN) Close() error { close(f.closed); return nil }
func (f *fakeTUN) Name() string { return "fake0" }
func (f *fakeTUN) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.written)
}

// testServer runs a Server over a fake TUN on a loopback TLS listener and
// returns its address.
func testServer(t *testing.T) (*Server, *fakeTUN, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sstp.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"sstp.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	pool, gw, err := dataplane.NewAddrPool("10.9.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	tun := newFakeTUN()
	srv := &Server{
		tlsCfg: tlsCfg, serverCertDER: der, pool: pool, gateway: gw,
		users:  map[string]string{"alice": "correct horse"},
		logger: vlog.Discard(), tun: tun,
		clients: make(map[uint32]*sstpClient), closed: make(chan struct{}),
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); srv.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConn(c.(*tls.Conn))
		}
	}()
	return srv, tun, ln.Addr().String()
}

// openCall runs the TLS, HTTP and CALL_CONNECT steps, the part of the exchange
// that carries no credential at all.
func openCall(t *testing.T, addr string) (*tls.Conn, []byte) {
	t.Helper()
	conn, err := dialTLS(context.Background(), addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test server
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := sstpHandshake(conn, "sstp.test"); err != nil {
		t.Fatal(err)
	}
	if err := sendCallConnectRequest(conn); err != nil {
		t.Fatal(err)
	}
	nonce, err := readCallConnectAck(conn)
	if err != nil {
		t.Fatal(err)
	}
	return conn, nonce
}

func ipFrom(src string) []byte {
	p := make([]byte, 28)
	p[0], p[3], p[8], p[9] = 0x45, 28, 64, 17
	copy(p[12:16], net.ParseIP(src).To4())
	copy(p[16:20], net.IPv4(10, 9, 0, 1).To4())
	return p
}

func sendIP(t *testing.T, conn *tls.Conn, ip []byte) {
	t.Helper()
	pkt, err := wire.EncodeData(ppp.EncapsulateIP(ip))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(pkt); err != nil {
		t.Fatal(err)
	}
}

// TestServerDropsIPBeforeAuthentication: the CALL_CONNECT steps carry no
// credential, so an IP frame sent straight after them must not reach the TUN.
// If this fails, anyone who can open TLS to the server can put packets on its
// network.
func TestServerDropsIPBeforeAuthentication(t *testing.T) {
	_, tun, addr := testServer(t)
	conn, _ := openCall(t, addr)
	sendIP(t, conn, ipFrom("10.9.0.2"))
	sendIP(t, conn, ipFrom("192.0.2.7"))
	time.Sleep(200 * time.Millisecond)
	if n := tun.count(); n != 0 {
		t.Fatalf("%d unauthenticated IP frame(s) reached the TUN", n)
	}
}

// noBinding wraps a client session but never sends CALL_CONNECTED, the
// behaviour of anything relaying PPP between two separate TLS sessions.
type noBinding struct{ *session }

func (noBinding) Authenticated([mschap.NTResponseLen]byte) {}

// dialSession runs the real client PPP stack over a call opened by openCall,
// returning once IPCP is up on the client side.
func dialSession(t *testing.T, addr string, bind bool) *session {
	t.Helper()
	conn, nonce := openCall(t, addr)
	s := &session{
		tlsConn: conn, logger: vlog.Discard(), serverNonce: nonce,
		cfg:  Config{Username: "alice", Password: "correct horse"},
		done: make(chan struct{}), ipReady: make(chan struct{}),
	}
	var h ppp.Handler = s
	if !bind {
		h = noBinding{s}
	}
	s.ppp = ppp.New(s.cfg.Username, s.cfg.Password, s, h)
	s.ppp.Start()
	go s.readLoop()
	t.Cleanup(func() { s.Close() })
	select {
	case <-s.ipReady:
	case <-time.After(5 * time.Second):
		t.Fatal("IPCP did not come up")
	}
	return s
}

func registered(srv *Server) int {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return len(srv.clients)
}

// TestServerRequiresTheCryptoBinding: a client that completes MS-CHAPv2 and
// IPCP but never sends CALL_CONNECTED must not be carried. If this fails, the
// binding that ties PPP authentication to this TLS session is decorative.
func TestServerRequiresTheCryptoBinding(t *testing.T) {
	srv, tun, addr := testServer(t)
	s := dialSession(t, addr, false)
	time.Sleep(200 * time.Millisecond)
	if registered(srv) != 0 {
		t.Fatal("the server routed to a client that sent no crypto binding")
	}
	sendIP(t, s.tlsConn, ipFrom(s.assignedIP.String()))
	time.Sleep(200 * time.Millisecond)
	if n := tun.count(); n != 0 {
		t.Fatalf("%d frame(s) from an unbound client reached the TUN", n)
	}
}

// TestServerCarriesOnlyTheAssignedSource: once the link is fully up, a client
// may send as the address IPCP gave it and as nothing else. If this fails, one
// client can send as another, or as a host behind the server.
func TestServerCarriesOnlyTheAssignedSource(t *testing.T) {
	srv, tun, addr := testServer(t)
	s := dialSession(t, addr, true)
	deadline := time.Now().Add(3 * time.Second)
	for registered(srv) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a bound, authenticated client was never registered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	sendIP(t, s.tlsConn, ipFrom("10.9.0.200"))
	sendIP(t, s.tlsConn, ipFrom(s.assignedIP.String()))
	deadline = time.Now().Add(2 * time.Second)
	for tun.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if n := tun.count(); n != 1 {
		t.Fatalf("TUN received %d packets, want exactly the one from the assigned address", n)
	}
}
