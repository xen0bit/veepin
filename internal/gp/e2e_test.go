package gp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
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
	pkt[9] = 253 // an experimental protocol number: nothing tries to interpret it
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}

// harness is a gateway and the pieces a test needs to talk to it.
//
// It builds the listener itself rather than using httptest, because the tunnel
// endpoint is split off in front of net/http (listener.go) and only a gateway
// serving its own TLS listener exercises that. A test that went through
// httptest's handler would take a path no real client takes.
type harness struct {
	srv       *Server
	serverTUN *fakeTUN
	gateway   net.IP
	hc        *http.Client
	host      string
	url       string
	espPort   int
}

// newHarness starts a gateway over a real TLS listener. When esp is true it also
// binds the UDP socket and serves it.
func newHarness(t *testing.T, cfg ServerConfig, esp bool) *harness {
	t.Helper()
	pool, gateway, err := dataplane.NewAddrPool("10.50.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Pool = pool
	cfg.ServerIP = gateway
	if cfg.Users == nil {
		cfg.Users = map[string]string{"alice": "s3cret"}
	}
	cfg.PublicIP = net.IPv4(127, 0, 0, 1)

	serverTUN := newFakeTUN()
	srv, err := NewServer(cfg, serverTUN)
	if err != nil {
		t.Fatal(err)
	}

	h := &harness{srv: srv, serverTUN: serverTUN, gateway: gateway}
	if esp {
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		h.espPort = udp.LocalAddr().(*net.UDPAddr).Port
		srv.cfg.ESPPort = h.espPort
		srv.EnableESP(udp)
		go srv.ServeESP()
	}
	go srv.RunTUN()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	go func() { _ = srv.Serve(tlsLn) }()

	h.host = ln.Addr().String()
	h.url = "https://" + h.host
	h.hc = &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	t.Cleanup(func() { _ = srv.Close() })
	return h
}

// selfSigned is a throwaway keypair for the test listener.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gw.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// dialSSL opens the SSL tunnel for an authenticated session.
func (h *harness) dialSSL(t *testing.T, info LoginInfo, cfg Config, tun *fakeTUN) *Client {
	t.Helper()
	conn, err := tls.Dial("tcp", h.host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(TunnelRequest(h.host, info)); err != nil {
		t.Fatal(err)
	}
	if err := ReadTunnelStart(conn); err != nil {
		t.Fatal(err)
	}
	c, err := RunSSL(conn, cfg, tun, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func mustLogin(t *testing.T, h *harness) (LoginInfo, Config) {
	t.Helper()
	info, cfg, err := Login(h.hc, h.url, "alice", "s3cret", "testhost")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if cfg.AssignedIP == nil {
		t.Fatal("the gateway assigned no address")
	}
	return info, cfg
}

// expectPacket waits for one packet on ch and checks its payload.
func expectPacket(t *testing.T, ch chan []byte, want string) {
	t.Helper()
	select {
	case got := <-ch:
		if len(got) < 20 || string(got[20:20+len(want)]) != want {
			t.Errorf("payload = %q, want %q", got[20:], want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no packet arrived")
	}
}

// TestSSLTunnelEndToEnd is the whole stack veepin<->veepin over a real TLS
// server: login, getconfig, the tunnel hijack, and an IP packet each way.
func TestSSLTunnelEndToEnd(t *testing.T) {
	h := newHarness(t, ServerConfig{DNS: []net.IP{net.IPv4(1, 1, 1, 1)}}, false)
	info, cfg := mustLogin(t, h)

	// With no ESP socket bound, the gateway must not advertise keys for one.
	if cfg.ESP != nil {
		t.Error("a gateway with no ESP socket offered ESP keys")
	}
	if len(cfg.DNS) != 1 || !cfg.DNS[0].Equal(net.IPv4(1, 1, 1, 1)) {
		t.Errorf("DNS = %v", cfg.DNS)
	}

	clientTUN := newFakeTUN()
	c := h.dialSSL(t, info, cfg, clientTUN)
	if c.OverESP() {
		t.Error("the client reports ESP on an SSL tunnel")
	}

	clientTUN.inbound <- ipv4(cfg.AssignedIP, h.gateway, "ping")
	expectPacket(t, h.serverTUN.outbound, "ping")

	h.serverTUN.inbound <- ipv4(h.gateway, cfg.AssignedIP, "pong")
	expectPacket(t, clientTUN.outbound, "pong")
}

// TestESPEndToEnd is the same, over the ESP data path: activation, then a packet
// each way with real UDP on the loopback.
func TestESPEndToEnd(t *testing.T) {
	h := newHarness(t, ServerConfig{}, true)
	info, cfg := mustLogin(t, h)
	_ = info

	if cfg.ESP == nil {
		t.Fatal("the gateway offered no ESP keys")
	}
	if cfg.GatewayAddr == nil {
		t.Fatal("the gateway named no ESP address")
	}
	if cfg.ESP.UDPPort != h.espPort {
		t.Fatalf("the gateway advertised port %d, want %d", cfg.ESP.UDPPort, h.espPort)
	}

	clientTUN := newFakeTUN()
	c, err := RunESP(cfg, clientTUN, nil, 0, 1400)
	if err != nil {
		t.Fatalf("RunESP: %v", err)
	}
	defer c.Close()
	if !c.OverESP() {
		t.Error("the client does not report the ESP path")
	}

	clientTUN.inbound <- ipv4(cfg.AssignedIP, h.gateway, "ping")
	expectPacket(t, h.serverTUN.outbound, "ping")

	h.serverTUN.inbound <- ipv4(h.gateway, cfg.AssignedIP, "pong")
	expectPacket(t, clientTUN.outbound, "pong")
}

// TestESPShapedEndToEnd proves shaping does not break the path: a padded packet
// must arrive as exactly the packet that was sent, because the inner IP header's
// own length delimits it.
func TestESPShapedEndToEnd(t *testing.T) {
	h := newHarness(t, ServerConfig{Shape: 4096}, true)
	_, cfg := mustLogin(t, h)

	clientTUN := newFakeTUN()
	c, err := RunESP(cfg, clientTUN, nil, 4096, 1400)
	if err != nil {
		t.Fatalf("RunESP: %v", err)
	}
	defer c.Close()

	clientTUN.inbound <- ipv4(cfg.AssignedIP, h.gateway, "ping")
	select {
	case got := <-h.serverTUN.outbound:
		if len(got) != 24 || string(got[20:]) != "ping" {
			t.Errorf("the server received %d octets (%q), want the 24-octet packet", len(got), got[20:])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no packet reached the server TUN")
	}

	h.serverTUN.inbound <- ipv4(h.gateway, cfg.AssignedIP, "pong")
	select {
	case got := <-clientTUN.outbound:
		if len(got) != 24 || string(got[20:]) != "pong" {
			t.Errorf("the client received %d octets (%q), want the 24-octet packet", len(got), got[20:])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no packet reached the client TUN")
	}
}

// TestSSLTunnelInvalidatesESPKeys pins the protocol's own exclusion rule: a
// session that opens the SSL tunnel must stop being reachable on the SPIs its
// configuration handed out.
func TestSSLTunnelInvalidatesESPKeys(t *testing.T) {
	h := newHarness(t, ServerConfig{}, true)
	info, cfg := mustLogin(t, h)
	if cfg.ESP == nil {
		t.Fatal("the gateway offered no ESP keys")
	}

	h.srv.mu.Lock()
	_, armed := h.srv.bySPI[cfg.ESP.C2SSPI]
	h.srv.mu.Unlock()
	if !armed {
		t.Fatal("the gateway did not arm the ESP path it offered keys for")
	}

	h.dialSSL(t, info, cfg, newFakeTUN())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.srv.mu.Lock()
		_, still := h.srv.bySPI[cfg.ESP.C2SSPI]
		h.srv.mu.Unlock()
		if !still {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the SPI was still live after the SSL tunnel opened")
}

// TestESPActivationFailsWithoutAGateway covers the fallback trigger: with nothing
// answering on the UDP port, activation must give up rather than hang, so the
// caller can fall back to the SSL tunnel.
func TestESPActivationFailsWithoutAGateway(t *testing.T) {
	// A socket that is bound but never read is the closest local stand-in for a
	// blocked UDP path: the datagrams leave and nothing answers.
	dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()

	esp, err := GenerateESP("aes-128-cbc", "sha1")
	if err != nil {
		t.Fatal(err)
	}
	esp.UDPPort = dead.LocalAddr().(*net.UDPAddr).Port
	cfg := Config{
		AssignedIP:  net.IPv4(10, 50, 0, 7),
		GatewayAddr: net.IPv4(127, 0, 0, 1),
		ESP:         esp,
	}

	start := time.Now()
	if _, err := RunESP(cfg, newFakeTUN(), nil, 0, 1400); err == nil {
		t.Fatal("RunESP succeeded with nothing answering")
	}
	if took := time.Since(start); took > 2*espActivationTimeout {
		t.Errorf("activation took %s, want it bounded by %s", took, espActivationTimeout)
	}
}

func TestRunESPRejectsIncompleteConfig(t *testing.T) {
	esp, err := GenerateESP("aes-128-cbc", "sha1")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no keys", Config{AssignedIP: net.IPv4(10, 50, 0, 7), GatewayAddr: net.IPv4(127, 0, 0, 1)}},
		{"no gateway address", Config{AssignedIP: net.IPv4(10, 50, 0, 7), ESP: esp}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RunESP(tc.cfg, newFakeTUN(), nil, 0, 1400); err == nil {
				t.Error("RunESP accepted an incomplete configuration")
			}
		})
	}
}

// TestServerDropsSpoofedSource: one client must not be able to inject traffic as
// another, on either data path.
func TestServerDropsSpoofedSource(t *testing.T) {
	h := newHarness(t, ServerConfig{}, false)
	info, cfg := mustLogin(t, h)
	clientTUN := newFakeTUN()
	h.dialSSL(t, info, cfg, clientTUN)

	// A packet from someone else's address must never reach the shared TUN.
	clientTUN.inbound <- ipv4(net.IPv4(10, 50, 0, 200), h.gateway, "spoofed")
	// A legitimate packet behind it proves the link is still working, and that
	// the spoofed one was dropped rather than merely delayed.
	clientTUN.inbound <- ipv4(cfg.AssignedIP, h.gateway, "genuine")
	expectPacket(t, h.serverTUN.outbound, "genuine")
}

// TestProbeOverSSLTunnel: the gateway echoes the liveness packet, and a probe
// that gets its echo is what keeps a healthy tunnel up.
func TestProbeOverSSLTunnel(t *testing.T) {
	h := newHarness(t, ServerConfig{}, false)
	info, cfg := mustLogin(t, h)
	c := h.dialSSL(t, info, cfg, newFakeTUN())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Probe(ctx); err != nil {
		t.Errorf("Probe on a live tunnel: %v", err)
	}
}

// TestProbeFailsOnADeadTunnel: once the far end is gone the probe must report it
// rather than block, since that is what tears a blackholed tunnel down.
func TestProbeFailsOnADeadTunnel(t *testing.T) {
	h := newHarness(t, ServerConfig{}, false)
	info, cfg := mustLogin(t, h)
	c := h.dialSSL(t, info, cfg, newFakeTUN())

	_ = c.link.conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Probe(ctx); err == nil {
		t.Error("Probe reported a closed tunnel as healthy")
	}
}

// TestHeaderlessTunnelRequest is the regression guard for the thing that makes
// listener.go necessary. The reference client opens the tunnel with a bare
// request line and no headers at all — not even Host, which HTTP/1.1 requires —
// and Go's net/http rejects exactly that with a 400 before any handler runs. A
// gateway that served the tunnel through net/http would fail against every real
// GlobalProtect client while passing every test written with a well-formed one.
func TestHeaderlessTunnelRequest(t *testing.T) {
	h := newHarness(t, ServerConfig{}, false)
	info, cfg := mustLogin(t, h)

	conn, err := tls.Dial("tcp", h.host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "GET " + PathTunnel + "?user=" + url.QueryEscape(info.User) +
		"&authcookie=" + url.QueryEscape(info.AuthCookie) + " HTTP/1.1\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	if err := ReadTunnelStart(conn); err != nil {
		t.Fatalf("the gateway refused a header-less tunnel request: %v", err)
	}

	// And it must actually carry packets, not merely answer the marker.
	clientTUN := newFakeTUN()
	c, err := RunSSL(conn, cfg, clientTUN, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	clientTUN.inbound <- ipv4(cfg.AssignedIP, h.gateway, "ping")
	expectPacket(t, h.serverTUN.outbound, "ping")
}

// TestControlPlaneStillReachesNetHTTP is the other half: splitting the tunnel off
// must not disturb the ordinary requests, which are replayed into net/http with
// the bytes already read put back in front.
func TestControlPlaneStillReachesNetHTTP(t *testing.T) {
	h := newHarness(t, ServerConfig{}, false)
	resp, err := h.hc.Get(h.url + "/nothing-here")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %s, want 404 from the ordinary handler", resp.Status)
	}
	// A full login round trip is the real proof: three POSTs on one connection.
	mustLogin(t, h)
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	h := newHarness(t, ServerConfig{}, false)
	_, _, err := Login(h.hc, h.url, "alice", "wrong", "testhost")
	if err == nil {
		t.Fatal("Login accepted a wrong password")
	}
	if !errors.Is(err, ErrAuth) {
		t.Errorf("error %v, want it to wrap ErrAuth", err)
	}
}

func TestLoginRejectsUnknownUser(t *testing.T) {
	h := newHarness(t, ServerConfig{}, false)
	if _, _, err := Login(h.hc, h.url, "mallory", "s3cret", "testhost"); err == nil {
		t.Error("Login accepted an unknown user")
	}
}

// TestTunnelRequiresASession: the tunnel endpoint is authorised by the query
// string alone, so it must refuse a cookie it never issued.
func TestTunnelRequiresASession(t *testing.T) {
	h := newHarness(t, ServerConfig{}, false)
	conn, err := tls.Dial("tcp", h.host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(TunnelRequest(h.host, LoginInfo{User: "alice", AuthCookie: "nope"})); err != nil {
		t.Fatal(err)
	}
	if err := ReadTunnelStart(conn); err == nil {
		t.Error("the gateway started a tunnel for a cookie it never issued")
	}
}

// TestGetConfigRequiresASession keeps the keying material behind the login: the
// keys are the tunnel's whole security, so an unauthenticated request must not
// produce any.
func TestGetConfigRequiresASession(t *testing.T) {
	h := newHarness(t, ServerConfig{}, true)
	resp, err := h.hc.Post(h.url+PathGetConfig, "application/x-www-form-urlencoded",
		strings.NewReader("authcookie=made-up&user=alice"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %s, want 403", resp.Status)
	}
}

// TestSessionReleasesItsAddress: a tunnel that ends must return its address, or a
// gateway leaks its pool one reconnect at a time.
func TestSessionReleasesItsAddress(t *testing.T) {
	h := newHarness(t, ServerConfig{}, false)
	info, cfg := mustLogin(t, h)
	c := h.dialSSL(t, info, cfg, newFakeTUN())
	_ = c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.srv.Clients() == 0 {
			// The same address must come back on the next login.
			_, next := mustLogin(t, h)
			if !next.AssignedIP.Equal(cfg.AssignedIP) {
				t.Errorf("the next client got %v, want the released %v", next.AssignedIP, cfg.AssignedIP)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the link was still registered after the client closed it")
}

// TestLogoutEndsTheSession proves the logout endpoint actually tears down, so a
// client that goes away cleanly does not hold its address until the TTL.
func TestLogoutEndsTheSession(t *testing.T) {
	h := newHarness(t, ServerConfig{}, true)
	info, cfg := mustLogin(t, h)
	if err := Logout(h.hc, h.url, info, "testhost"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	h.srv.mu.Lock()
	_, stillArmed := h.srv.bySPI[cfg.ESP.C2SSPI]
	sessions := len(h.srv.sessions)
	h.srv.mu.Unlock()
	if stillArmed {
		t.Error("logout left the ESP path armed")
	}
	if sessions != 0 {
		t.Errorf("%d sessions survived the logout", sessions)
	}
}
