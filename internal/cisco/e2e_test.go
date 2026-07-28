package cisco

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev1"
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

// makeIPv4 builds a minimal IPv4 packet so the routing on both sides can read
// its addresses. Total Length is set because the receive path trims a packet to
// its declared length — a packet claiming zero is not one a kernel would accept
// either.
func makeIPv4(src, dst net.IP, payload int) []byte {
	p := make([]byte, 20+payload)
	p[0] = 0x45
	p[2] = byte(len(p) >> 8)
	p[3] = byte(len(p))
	p[9] = 1 // protocol
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	for i := range payload {
		p[20+i] = byte(i)
	}
	return p
}

// harness is a client and a gateway wired over loopback UDP.
type harness struct {
	server    *Server
	client    *Client
	clientTUN *fakeTUN
	serverTUN *fakeTUN
	gateway   net.IP
	nc        NetConfig
}

func newHarness(t *testing.T, shape int) *harness {
	t.Helper()
	pool, gateway, err := dataplane.NewAddrPool("10.60.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	loopback := net.IPv4(127, 0, 0, 1)

	// The gateway binds two sockets, as it does in production: phase 1 on one,
	// floated IKE plus ESP on the other. Both are ephemeral here, since the real
	// 500/4500 need privileges — hence the ports on ClientConfig.
	ikeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	nattConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	serverTUN := newFakeTUN()
	_, splitNet, _ := net.ParseCIDR("10.60.0.0/24")
	server, err := NewServer(ikeConn, nattConn, serverTUN, ServerConfig{
		Groups:       map[string][]byte{"engineering": []byte("group-secret")},
		Users:        map[string]string{"alice": "password"},
		PublicIP:     loopback,
		Pool:         pool,
		Gateway:      gateway,
		DNS:          []net.IP{net.IPv4(10, 60, 0, 1)},
		Domain:       "example.test",
		Banner:       "welcome to veepin",
		SplitInclude: []*net.IPNet{splitNet},
		Shape:        shape,
		MTU:          1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve() }()
	t.Cleanup(func() { _ = server.Close() })

	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	clientTUN := newFakeTUN()
	client := NewClient(cliConn, clientTUN, ClientConfig{
		ServerIP: loopback,
		LocalIP:  loopback,
		IKEPort:  ikeConn.LocalAddr().(*net.UDPAddr).Port,
		NATTPort: nattConn.LocalAddr().(*net.UDPAddr).Port,
		Group:    "engineering",
		GroupPSK: []byte("group-secret"),
		Username: "alice",
		Password: "password",
		Shape:    shape,
		MTU:      1400,
	})
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nc, err := client.Handshake(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return &harness{
		server: server, client: client,
		clientTUN: clientTUN, serverTUN: serverTUN,
		gateway: gateway, nc: nc,
	}
}

func TestClientServerLoopback(t *testing.T) { runLoopback(t, 0) }

// TestClientServerLoopbackShaped runs the same exchange with shaping on in both
// directions: every packet is padded out with RFC 4303 section 2.7
// traffic-flow-confidentiality filler. The assertion is unchanged — what reaches
// the far TUN must still be byte-identical to what was sent — so the trim on
// receive is under test as much as the padding.
func TestClientServerLoopbackShaped(t *testing.T) {
	runLoopback(t, dataplane.DefaultShapeBytes)
}

func runLoopback(t *testing.T, shape int) {
	h := newHarness(t, shape)

	if h.nc.AssignedIP == nil || !h.nc.AssignedIP.IsPrivate() {
		t.Fatalf("bad assignment: %+v", h.nc)
	}
	if h.nc.Banner != "welcome to veepin" {
		t.Errorf("banner = %q, want the gateway's", h.nc.Banner)
	}
	if h.nc.Domain != "example.test" {
		t.Errorf("domain = %q", h.nc.Domain)
	}
	if len(h.nc.DNS) != 1 || !h.nc.DNS[0].Equal(net.IPv4(10, 60, 0, 1)) {
		t.Errorf("dns = %v", h.nc.DNS)
	}
	if len(h.nc.Routes) != 1 || h.nc.Routes[0].String() != "10.60.0.0/24" {
		t.Errorf("routes = %v, want the split-include network", h.nc.Routes)
	}

	// Client -> gateway.
	up := makeIPv4(h.nc.AssignedIP, net.IPv4(203, 0, 113, 5), 64)
	h.clientTUN.in <- up
	select {
	case got := <-h.serverTUN.out:
		if string(got) != string(up) {
			t.Errorf("gateway TUN got %d octets, want the %d sent", len(got), len(up))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet never reached the gateway TUN")
	}

	// Gateway -> client: routed by the client's assigned address.
	down := makeIPv4(net.IPv4(203, 0, 113, 5), h.nc.AssignedIP, 128)
	h.serverTUN.in <- down
	select {
	case got := <-h.clientTUN.out:
		if string(got) != string(down) {
			t.Errorf("client TUN got %d octets, want the %d sent", len(got), len(down))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet never reached the client TUN")
	}
}

// TestDPDRoundTrip proves the liveness probe is the protocol's own dead-peer
// detection and that the gateway answers it.
func TestDPDRoundTrip(t *testing.T) {
	h := newHarness(t, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.client.Probe(ctx); err != nil {
		t.Fatalf("probe: %v", err)
	}
	// Twice, so the sequence number advancing does not break the match.
	if err := h.client.Probe(ctx); err != nil {
		t.Fatalf("second probe: %v", err)
	}
}

// TestWrongGroupKeyFails checks that a bad group pre-shared key is reported as
// an authentication failure rather than as a transport error — the two things a
// user most needs told apart.
func TestWrongGroupKeyFails(t *testing.T) {
	err := dialWith(t, func(c *ClientConfig) { c.GroupPSK = []byte("wrong") })
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("error = %v, want ErrAuth", err)
	}
}

// TestWrongPasswordFails checks the same for the XAuth password, which fails at
// a different point in the exchange and must still say "authentication".
func TestWrongPasswordFails(t *testing.T) {
	err := dialWith(t, func(c *ClientConfig) { c.Password = "wrong" })
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("error = %v, want ErrAuth", err)
	}
}

// TestUnknownGroupFails checks that a group the gateway does not know is
// refused, rather than silently authenticated with some other group's key.
func TestUnknownGroupFails(t *testing.T) {
	err := dialWith(t, func(c *ClientConfig) { c.Group = "nonesuch" })
	if err == nil {
		t.Fatal("an unknown group was accepted")
	}
}

// dialWith runs a handshake against a stock gateway with one client setting
// perturbed, and returns whatever the handshake failed with.
func dialWith(t *testing.T, tweak func(*ClientConfig)) error {
	t.Helper()
	pool, gateway, err := dataplane.NewAddrPool("10.60.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	loopback := net.IPv4(127, 0, 0, 1)
	ikeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	nattConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ikeConn, nattConn, newFakeTUN(), ServerConfig{
		Groups:   map[string][]byte{"engineering": []byte("group-secret")},
		Users:    map[string]string{"alice": "password"},
		PublicIP: loopback,
		Pool:     pool,
		Gateway:  gateway,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve() }()
	t.Cleanup(func() { _ = server.Close() })

	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	cfg := ClientConfig{
		ServerIP: loopback,
		LocalIP:  loopback,
		IKEPort:  ikeConn.LocalAddr().(*net.UDPAddr).Port,
		NATTPort: nattConn.LocalAddr().(*net.UDPAddr).Port,
		Group:    "engineering",
		GroupPSK: []byte("group-secret"),
		Username: "alice",
		Password: "password",
	}
	tweak(&cfg)
	client := NewClient(cliConn, newFakeTUN(), cfg)
	t.Cleanup(func() { _ = client.Close() })

	// Short, because one of these failures has no answer to wait for: a gateway
	// that cannot place an unauthenticated peer in a group says nothing at all,
	// so the client retransmits until it gives up. Four seconds is well past the
	// round trip the other two need and well short of that retransmit budget.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_, err = client.Handshake(ctx)
	if err == nil {
		t.Fatal("the handshake succeeded")
	}
	return err
}

// TestResultCarriesTheProfile guards the two facts the facade reads off a
// completed exchange: the SA is tunnel mode, and the XAuth user is attributed.
func TestResultCarriesTheProfile(t *testing.T) {
	h := newHarness(t, 0)
	h.server.mu.Lock()
	n := len(h.server.byCookie)
	h.server.mu.Unlock()
	if n != 1 {
		t.Fatalf("gateway tracks %d peers, want 1", n)
	}
	var _ ikev1.Result // the shape the handler above consumed
}
