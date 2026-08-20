package anyconnect

import (
	"context"
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
	in  chan []byte
	out chan []byte
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{in: make(chan []byte, 16), out: make(chan []byte, 16)}
}

func (f *fakeTUN) Read(p []byte) (int, error) {
	pkt, ok := <-f.in
	if !ok {
		return 0, io.EOF
	}
	return copy(p, pkt), nil
}

func (f *fakeTUN) Write(p []byte) (int, error) {
	f.out <- append([]byte(nil), p...)
	return len(p), nil
}

// makeIPv4 builds a minimal IPv4 packet (header only) so the routing on both
// ends can read its addresses. Total Length is set because the receive path
// trims a packet to its declared length — one claiming zero is not a packet the
// kernel would accept either.
func makeIPv4(src, dst net.IP) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	p[2], p[3] = 0, 20 // Total Length
	p[9] = 1           // protocol; irrelevant here
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	return p
}

// selfSignedCert mints a throwaway certificate for the loopback listener.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "veepin-test"},
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

// TestClientServerLoopback drives the whole protocol over a real TLS connection:
// the XML credential exchange, the CONNECT that assigns addressing, and IP in
// both directions through the CSTP framing.
func TestClientServerLoopback(t *testing.T) { runClientServerLoopback(t, 0) }

// TestClientServerLoopbackShaped is the same exchange with downstream shaping
// on. The server pads every downstream packet out to the tunnel MTU, and the
// assertion is unchanged — the packet that reaches the client TUN must still be
// byte-identical to the one the server read — so it is the trim on receive that
// is under test as much as the padding.
func TestClientServerLoopbackShaped(t *testing.T) {
	runClientServerLoopback(t, dataplane.DefaultShapeBytes)
}

func runClientServerLoopback(t *testing.T, shape int) {
	pool, gateway, err := dataplane.NewAddrPool("10.11.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	serverTUN := newFakeTUN()
	srv := NewServer(serverTUN, ServerConfig{
		Users:   map[string]string{"alice": "password"},
		Pool:    pool,
		Gateway: gateway,
		DNS:     []net.IP{net.IPv4(1, 1, 1, 1)},
		Shape:   shape,
	})
	srv.Start()
	defer srv.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(conn)
		}
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // throwaway self-signed test cert
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientTUN := newFakeTUN()
	c := NewClient(conn, clientTUN, ClientConfig{
		Host:     ln.Addr().String(),
		Username: "alice",
		Password: "password",
	})
	defer c.Close()

	cfg, err := c.Handshake()
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if cfg.Address == nil || !pool.Network().Contains(cfg.Address) {
		t.Fatalf("assigned address %v is outside the pool %v", cfg.Address, pool.Network())
	}
	if len(cfg.DNS) != 1 || !cfg.DNS[0].Equal(net.IPv4(1, 1, 1, 1)) {
		t.Errorf("DNS = %v, want [1.1.1.1]", cfg.DNS)
	}
	if cfg.MTU != defaultMTU {
		t.Errorf("MTU = %d, want %d", cfg.MTU, defaultMTU)
	}
	t.Logf("client assigned %s, netmask %s, mtu %d", cfg.Address, cfg.Netmask, cfg.MTU)

	go func() { _ = c.Run(0) }()

	// Client -> server: a packet injected at the client TUN must emerge at the
	// server's, having crossed the CSTP framing.
	up := makeIPv4(cfg.Address, gateway)
	clientTUN.in <- up
	assertPacket(t, "client->server", serverTUN.out, up)

	// Server -> client: a packet addressed to the client must be routed to it.
	down := makeIPv4(gateway, cfg.Address)
	serverTUN.in <- down
	assertPacket(t, "server->client", clientTUN.out, down)
}

// TestBadPasswordIsRejected: the server must refuse a wrong password rather than
// assigning an address, and the client must report it as an authentication
// failure rather than hanging.
func TestBadPasswordIsRejected(t *testing.T) {
	pool, gateway, err := dataplane.NewAddrPool("10.11.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(newFakeTUN(), ServerConfig{
		Users:   map[string]string{"alice": "password"},
		Pool:    pool,
		Gateway: gateway,
	})
	defer srv.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		srv.ServeConn(conn)
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // throwaway self-signed test cert
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(conn, newFakeTUN(), ClientConfig{
		Host:     ln.Addr().String(),
		Username: "alice",
		Password: "wrong",
	})
	defer c.Close()

	if _, err := c.Handshake(); err == nil {
		t.Fatal("handshake succeeded with the wrong password")
	} else {
		t.Logf("rejected as expected: %v", err)
	}
}

func assertPacket(t *testing.T, dir string, out <-chan []byte, want []byte) {
	t.Helper()
	select {
	case got := <-out:
		if string(got) != string(want) {
			t.Errorf("%s: got %x, want %x", dir, got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: timed out waiting for packet", dir)
	}
}

// TestTheClientCanAskWhetherTheServerIsStillThere. This end has always echoed a
// server's DPD request and never sent one, so the mechanism could prove this
// client alive to a server and learn nothing about the server. That matters
// most on the DTLS path: data goes over UDP whenever it is up, and a UDP path
// that silently stops produces no read error, so the read loop never demotes it
// and the healthy idle TLS connection beside it reports the tunnel up.
func TestTheClientCanAskWhetherTheServerIsStillThere(t *testing.T) {
	c, _, _ := dpdLoopback(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Probe(ctx); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	// Twice, so the outstanding-probe slot is proven to release rather than
	// working exactly once per session.
	if err := c.Probe(ctx); err != nil {
		t.Fatalf("second Probe: %v", err)
	}
}

// TestAProbeIgnoresAnEchoThatIsNotItsOwn. The payload is the only thing tying an
// answer to a question here -- CSTP's DPD carries no sequence number -- so a
// response with different contents must not release the probe. Otherwise a
// server's own DPD request, echoed back by this client, could satisfy a probe
// the server never answered.
func TestAProbeIgnoresAnEchoThatIsNotItsOwn(t *testing.T) {
	c := &Client{}
	p := &dpdProbe{payload: []byte("question"), done: make(chan struct{})}
	c.dpd.Store(p)

	c.matchDPD([]byte("something else"))
	select {
	case <-p.done:
		t.Fatal("a mismatched echo released the probe, so any inbound DPD traffic " +
			"would keep a dead tunnel looking alive")
	default:
	}

	c.matchDPD([]byte("question"))
	select {
	case <-p.done:
	default:
		t.Fatal("the matching echo did not release the probe")
	}
}

// TestAProbeAgainstASilentServerGivesUp. The liveness monitor bounds each probe
// with a context, and a probe that ignored it would stall the monitor rather
// than failing a check.
func TestAProbeAgainstASilentServerGivesUp(t *testing.T) {
	// A client whose connection goes to a pipe nobody reads: the request is
	// written and nothing ever answers, which is a black-holed carrier.
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	go func() { _, _ = io.Copy(io.Discard, server) }()

	c := NewClient(client, newFakeTUN(), ClientConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err := c.Probe(ctx)
	if !errors.Is(err, ErrPeerSilent) {
		t.Errorf("Probe against a silent server = %v, want ErrPeerSilent", err)
	}
}

// dpdLoopback brings up a client and server over a real TLS listener and starts
// the client's read loop, which is what delivers a DPD response.
func dpdLoopback(t *testing.T) (*Client, *Server, *fakeTUN) {
	t.Helper()
	pool, gateway, err := dataplane.NewAddrPool("10.11.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_ = gateway
	serverTUN := newFakeTUN()
	srv := NewServer(serverTUN, ServerConfig{
		Users:   map[string]string{"alice": "password"},
		Pool:    pool,
		Gateway: gateway,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Close() })

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(conn)
		}
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // throwaway self-signed test cert
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientTUN := newFakeTUN()
	c := NewClient(conn, clientTUN, ClientConfig{
		Host:     ln.Addr().String(),
		Username: "alice",
		Password: "password",
	})
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	go func() { _ = c.Run(0) }()
	return c, srv, clientTUN
}
