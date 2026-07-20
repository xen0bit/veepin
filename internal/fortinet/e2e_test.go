package fortinet

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
)

// fakeTUN is an in-memory TUN: packets written to inbound are returned by Read,
// and packets written via Write appear on outbound.
type fakeTUN struct {
	inbound  chan []byte
	outbound chan []byte
	closed   chan struct{}
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{inbound: make(chan []byte, 16), outbound: make(chan []byte, 16), closed: make(chan struct{})}
}

func (t *fakeTUN) Read(b []byte) (int, error) {
	select {
	case p := <-t.inbound:
		return copy(b, p), nil
	case <-t.closed:
		return 0, net.ErrClosed
	}
}

func (t *fakeTUN) Write(b []byte) (int, error) {
	p := append([]byte(nil), b...)
	select {
	case t.outbound <- p:
	case <-t.closed:
		return 0, net.ErrClosed
	}
	return len(b), nil
}

func (t *fakeTUN) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

func ipv4(src, dst net.IP, payload string) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 253
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}

// The whole Fortinet stack veepin<->veepin over a real TLS server: HTTPS login,
// the config fetch, the tunnel hijack, PPP with no auth, and an IP packet each
// way.
func TestClientServerEndToEnd(t *testing.T) {
	pool, gateway, err := dataplane.NewAddrPool("10.40.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	serverTUN := newFakeTUN()
	srv, err := NewServer(ServerConfig{
		Users:    map[string]string{"alice": "s3cret"},
		Pool:     pool,
		ServerIP: gateway,
		DNS:      []net.IP{net.IPv4(1, 1, 1, 1)},
	}, serverTUN)
	if err != nil {
		t.Fatal(err)
	}
	go srv.RunTUN()

	ts := httptest.NewTLSServer(srv)
	defer ts.Close()

	// Control plane: an HTTP client that trusts the test cert and keeps cookies.
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	cfg, cookie, err := Login(hc, ts.URL, "alice", "s3cret", "", nil)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if cfg.AssignedIP == nil {
		t.Fatal("no address assigned")
	}
	clientIP := cfg.AssignedIP

	// Data plane: a raw TLS connection carrying the tunnel GET, then framed PPP.
	host := ts.Listener.Addr().String()
	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
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

	// Client -> server: a packet from the assigned address to the gateway must
	// arrive on the server TUN.
	clientTUN.inbound <- ipv4(clientIP, gateway, "ping")
	select {
	case got := <-serverTUN.outbound:
		if string(got[20:]) != "ping" {
			t.Errorf("server TUN payload = %q, want ping", got[20:])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet did not reach the server TUN")
	}

	// Server -> client: a packet addressed to the client must come back out the
	// client TUN.
	serverTUN.inbound <- ipv4(gateway, clientIP, "pong")
	select {
	case got := <-clientTUN.outbound:
		if string(got[20:]) != "pong" {
			t.Errorf("client TUN payload = %q, want pong", got[20:])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet did not reach the client TUN")
	}
}

// A wrong password must be rejected at login, before any tunnel is possible.
func TestLoginRejectsWrongPassword(t *testing.T) {
	pool, gateway, _ := dataplane.NewAddrPool("10.40.0.0/24")
	srv, _ := NewServer(ServerConfig{
		Users: map[string]string{"alice": "s3cret"}, Pool: pool, ServerIP: gateway,
	}, newFakeTUN())
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()

	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	jar, _ := cookiejar.New(nil)
	hc.Jar = jar
	if _, _, err := Login(hc, ts.URL, "alice", "wrong", "", nil); err == nil {
		t.Error("Login accepted a wrong password")
	}
}

// newTestPool is the address pool the tests share.
func newTestPool() (*dataplane.AddrPool, net.IP, error) {
	return dataplane.NewAddrPool("10.40.0.0/24")
}
