package pulse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
)

// fakeTUN is an in-memory TUN: the engine Reads packets pushed onto in and the
// packets it Writes land on out.
type fakeTUN struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{in: make(chan []byte, 16), out: make(chan []byte, 16), closed: make(chan struct{})}
}

func (f *fakeTUN) Read(p []byte) (int, error) {
	select {
	case pkt := <-f.in:
		return copy(p, pkt), nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakeTUN) Write(p []byte) (int, error) {
	select {
	case f.out <- append([]byte(nil), p...):
	default:
	}
	return len(p), nil
}

func (f *fakeTUN) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

// selfSigned mints a throwaway certificate for the test listener.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pulse.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"pulse.test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// makeIPv4 builds a minimal IPv4 packet whose Total Length is correct, so the
// receive path — which trims a packet to its declared length — accepts it.
func makeIPv4(src, dst net.IP, payload int) []byte {
	p := make([]byte, 20+payload)
	p[0] = 0x45
	p[2] = byte(len(p) >> 8)
	p[3] = byte(len(p))
	p[9] = 1
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	for i := range payload {
		p[20+i] = byte(i)
	}
	return p
}

type harness struct {
	server    *Server
	client    *Client
	clientTUN *fakeTUN
	serverTUN *fakeTUN
	gateway   net.IP
}

// newHarness stands a gateway up on a real TLS listener and connects a client
// to it. withESP arms the UDP data path; shape enables downstream shaping.
func newHarness(t *testing.T, withESP bool, shape int) *harness {
	t.Helper()
	pool, gateway, err := dataplane.NewAddrPool("10.70.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	serverTUN := newFakeTUN()
	_, split, _ := net.ParseCIDR("10.70.0.0/24")

	srv, err := NewServer(ServerConfig{
		Users:    map[string]string{"alice": "hunter2"},
		Pool:     pool,
		ServerIP: gateway,
		DNS:      []net.IP{net.IPv4(10, 70, 0, 1)},
		Domain:   "corp.example",
		Routes:   []Route{{Net: split}},
		NoESP:    !withESP,
		Shape:    shape,
		MTU:      1400,
	}, serverTUN)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, MinVersion: tls.VersionTLS12}
	tlsLn := tls.NewListener(ln, tlsCfg)

	if withESP {
		udp, uerr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if uerr != nil {
			t.Fatal(uerr)
		}
		srv.cfg.ESPPort = udp.LocalAddr().(*net.UDPAddr).Port
		srv.EnableESP(udp)
		go srv.ServeESP()
	}
	go func() { _ = srv.Serve(tlsLn) }()
	go srv.RunTUN()
	t.Cleanup(func() { _ = srv.Close() })

	addr := ln.Addr().String()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // a throwaway test certificate
	if err != nil {
		t.Fatal(err)
	}
	clientTUN := newFakeTUN()
	c, err := Connect(conn, addr, "/", "alice", "hunter2", "testhost", clientTUN, nil, withESP, shape)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	return &harness{server: srv, client: c, clientTUN: clientTUN, serverTUN: serverTUN, gateway: gateway}
}

func TestTunnelOverIFT(t *testing.T)       { runTunnel(t, false, 0) }
func TestTunnelOverIFTShaped(t *testing.T) { runTunnel(t, false, dataplane.DefaultShapeBytes) }
func TestTunnelOverESP(t *testing.T)       { runTunnel(t, true, 0) }
func TestTunnelOverESPShaped(t *testing.T) { runTunnel(t, true, dataplane.DefaultShapeBytes) }

func runTunnel(t *testing.T, withESP bool, shape int) {
	h := newHarness(t, withESP, shape)

	cfg := h.client.AssignedConfig()
	if cfg.Address == nil || !cfg.Address.IsPrivate() {
		t.Fatalf("bad assignment: %+v", cfg)
	}
	if cfg.Domain != "corp.example" {
		t.Errorf("domain = %q", cfg.Domain)
	}
	if cfg.MTU != 1400 {
		t.Errorf("mtu = %d", cfg.MTU)
	}
	if len(cfg.DNS) != 1 || !cfg.DNS[0].Equal(net.IPv4(10, 70, 0, 1)) {
		t.Errorf("dns = %v", cfg.DNS)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Net.String() != "10.70.0.0/24" {
		t.Errorf("routes = %v", cfg.Routes)
	}
	if h.client.OverESP() != withESP {
		t.Fatalf("carrier: over ESP = %v, want %v", h.client.OverESP(), withESP)
	}
	if h.client.Session().Cookie == "" {
		t.Error("no session cookie")
	}

	// Client -> server.
	up := makeIPv4(cfg.Address, net.IPv4(203, 0, 113, 5), 64)
	h.clientTUN.in <- up
	select {
	case got := <-h.serverTUN.out:
		if string(got) != string(up) {
			t.Errorf("gateway TUN got %d octets, want the %d sent", len(got), len(up))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("packet never reached the gateway TUN")
	}

	// Server -> client, routed by the client's assigned address.
	down := makeIPv4(net.IPv4(203, 0, 113, 5), cfg.Address, 128)
	h.serverTUN.in <- down
	select {
	case got := <-h.clientTUN.out:
		if string(got) != string(down) {
			t.Errorf("client TUN got %d octets, want the %d sent", len(got), len(down))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("packet never reached the client TUN")
	}
}

// TestSpoofedSourceIsDropped: a server shares one TUN across every client, so a
// packet whose source is not the address that client was assigned must not
// reach it.
func TestSpoofedSourceIsDropped(t *testing.T) {
	h := newHarness(t, false, 0)
	cfg := h.client.AssignedConfig()

	spoofed := makeIPv4(net.IPv4(10, 70, 0, 254), net.IPv4(203, 0, 113, 5), 32)
	h.clientTUN.in <- spoofed
	select {
	case got := <-h.serverTUN.out:
		t.Fatalf("a spoofed packet reached the gateway TUN: %x", got[:20])
	case <-time.After(500 * time.Millisecond):
	}

	// The honest packet still gets through, so the drop is the source check and
	// not a dead link.
	honest := makeIPv4(cfg.Address, net.IPv4(203, 0, 113, 5), 32)
	h.clientTUN.in <- honest
	select {
	case <-h.serverTUN.out:
	case <-time.After(10 * time.Second):
		t.Fatal("the honest packet did not get through either")
	}
}

// TestWrongPasswordIsRefused checks the failure reaches the caller as an
// authentication error rather than as a broken connection.
func TestWrongPasswordIsRefused(t *testing.T) {
	pool, gateway, err := dataplane.NewAddrPool("10.70.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{
		Users: map[string]string{"alice": "hunter2"}, Pool: pool, ServerIP: gateway, NoESP: true,
	}, newFakeTUN())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, MinVersion: tls.VersionTLS12})
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // a throwaway test certificate
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, cerr := Connect(conn, ln.Addr().String(), "/", "alice", "wrong", "testhost",
		newFakeTUN(), nil, false, 0)
	if cerr == nil {
		t.Fatal("a wrong password was accepted")
	}
	// The classification, not just the refusal: the facade maps this onto
	// client.ErrAuth so a wrong password stops `veepin connect -retry` instead
	// of being replayed at a gateway that counts failures.
	if !errors.Is(cerr, ErrAuth) {
		t.Errorf("Connect error = %v, want one satisfying errors.Is(err, ErrAuth)", cerr)
	}
	if srv.Sessions() != 0 {
		t.Errorf("the gateway kept %d sessions after a rejected login", srv.Sessions())
	}
}
