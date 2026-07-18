package nebula

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// An in-memory UDP fabric. Running the host engine over real sockets would work
// but makes tests slow and flaky under load; this keeps the delivery semantics
// that matter (datagrams, addressed, may be dropped) without the kernel.

type fabric struct {
	mu    sync.Mutex
	conns map[netip.AddrPort]*memConn
	// dropped records datagrams sent to an address nobody is listening on,
	// which is what a NAT-blocked punch packet looks like.
	dropped int
}

func newFabric() *fabric {
	return &fabric{conns: map[netip.AddrPort]*memConn{}}
}

func (f *fabric) listen(addr netip.AddrPort) *memConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &memConn{
		fabric: f,
		local:  addr,
		queue:  make(chan datagram, 256),
		closed: make(chan struct{}),
	}
	f.conns[addr] = c
	return c
}

type datagram struct {
	body []byte
	from netip.AddrPort
}

type memConn struct {
	fabric *fabric
	local  netip.AddrPort
	queue  chan datagram

	once   sync.Once
	closed chan struct{}
}

func (c *memConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	select {
	case d := <-c.queue:
		return copy(b, d.body), d.from, nil
	case <-c.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (c *memConn) WriteTo(b []byte, addr netip.AddrPort) (int, error) {
	c.fabric.mu.Lock()
	dst, ok := c.fabric.conns[addr]
	if !ok {
		c.fabric.dropped++
	}
	c.fabric.mu.Unlock()
	if !ok {
		// Nothing is listening. UDP does not report this, and neither does a
		// real socket, so the write "succeeds".
		return len(b), nil
	}
	select {
	case dst.queue <- datagram{body: append([]byte(nil), b...), from: c.local}:
	case <-dst.closed:
	default: // queue full: drop, as a real socket would
	}
	return len(b), nil
}

func (c *memConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *memConn) LocalAddr() net.Addr { return memAddr{c.local} }

type memAddr struct{ ap netip.AddrPort }

func (memAddr) Network() string            { return "udp" }
func (a memAddr) String() string           { return a.ap.String() }
func (a memAddr) AddrPort() netip.AddrPort { return a.ap }

// memTUN is a fake TUN: packets written to it are readable from Out, and
// packets pushed to In appear to the host as outbound traffic.
type memTUN struct {
	In  chan []byte
	Out chan []byte

	once   sync.Once
	closed chan struct{}
}

func newMemTUN() *memTUN {
	return &memTUN{
		In:     make(chan []byte, 64),
		Out:    make(chan []byte, 64),
		closed: make(chan struct{}),
	}
}

func (t *memTUN) Read(b []byte) (int, error) {
	select {
	case p := <-t.In:
		return copy(b, p), nil
	case <-t.closed:
		return 0, io.EOF
	}
}

func (t *memTUN) Write(b []byte) (int, error) {
	select {
	case t.Out <- append([]byte(nil), b...):
		return len(b), nil
	case <-t.closed:
		return 0, net.ErrClosed
	default:
		return len(b), nil
	}
}

func (t *memTUN) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

// ipv4Packet builds a minimal well-formed IPv4 packet.
func ipv4Packet(src, dst netip.Addr, payload string) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	total := uint16(len(pkt))
	pkt[2], pkt[3] = byte(total>>8), byte(total)
	pkt[8] = 64  // TTL
	pkt[9] = 253 // an experimental protocol number; nothing parses it further
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	copy(pkt[20:], payload)
	return pkt
}

// testHost wires one host onto the fabric.
type testHost struct {
	*Host
	tun  *memTUN
	addr netip.AddrPort
}

func startHost(t *testing.T, f *fabric, certFile, keyFile string, underlay netip.AddrPort, mutate func(*Config)) *testHost {
	t.Helper()

	pool, err := NewCAPoolFromPEM(readFixture(t, "ca.crt"))
	if err != nil {
		t.Fatalf("building CA pool: %v", err)
	}
	cfg := &Config{
		Identity:    loadIdentity(t, certFile, keyFile),
		CAs:         pool,
		StaticHosts: map[netip.Addr][]netip.AddrPort{},
	}
	if mutate != nil {
		mutate(cfg)
	}

	tun := newMemTUN()
	h, err := NewHost(cfg, f.listen(underlay), tun)
	if err != nil {
		t.Fatalf("building host: %v", err)
	}
	// The fixtures are dated, so every host has to judge peers at a time inside
	// their validity window.
	h.hs.now = func() time.Time { return fixtureTime }

	h.Run()
	t.Cleanup(func() { _ = h.Close() })
	return &testHost{Host: h, tun: tun, addr: underlay}
}

func mustAddrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// expectTUN waits for a packet to surface on a host's TUN.
func expectTUN(t *testing.T, h *testHost, want string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case pkt := <-h.tun.Out:
			if len(pkt) >= 20 && bytes.Equal(pkt[20:], []byte(want)) {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q on %v's TUN", want, h.Addr())
		}
	}
}

// sendUntilDelivered pushes a packet repeatedly until it lands. The first
// packet to an address with no tunnel is expected to be lost while the
// handshake runs, which is how nebula behaves; a retry is what a real
// application's retransmission would do.
func sendUntilDelivered(t *testing.T, from *testHost, to *testHost, src, dst netip.Addr, payload string) {
	t.Helper()
	stop := make(chan struct{})
	defer close(stop)

	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			select {
			case from.tun.In <- ipv4Packet(src, dst, payload):
			case <-stop:
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	expectTUN(t, to, payload)
}

func TestTwoHostsExchangeTraffic(t *testing.T) {
	f := newFabric()
	addrA, addrB := mustAddrPort("192.0.2.1:4242"), mustAddrPort("192.0.2.2:4242")
	overlayA, overlayB := netip.MustParseAddr("10.42.0.1"), netip.MustParseAddr("10.42.0.2")

	hostA := startHost(t, f, "host-a.crt", "host-a.key", addrA, func(c *Config) {
		c.StaticHosts[overlayB] = []netip.AddrPort{addrB}
	})
	hostB := startHost(t, f, "host-b.crt", "host-b.key", addrB, func(c *Config) {
		c.StaticHosts[overlayA] = []netip.AddrPort{addrA}
	})

	sendUntilDelivered(t, hostA, hostB, overlayA, overlayB, "hello-from-a")
	sendUntilDelivered(t, hostB, hostA, overlayB, overlayA, "hello-from-b")
}

// Only one side needs to know where the other is: the responder learns the
// initiator's address from the handshake itself.
func TestHandshakeTeachesResponderTheAddress(t *testing.T) {
	f := newFabric()
	addrA, addrB := mustAddrPort("192.0.2.1:4242"), mustAddrPort("192.0.2.2:4242")
	overlayA, overlayB := netip.MustParseAddr("10.42.0.1"), netip.MustParseAddr("10.42.0.2")

	hostA := startHost(t, f, "host-a.crt", "host-a.key", addrA, func(c *Config) {
		c.StaticHosts[overlayB] = []netip.AddrPort{addrB}
	})
	// hostB is told nothing about where hostA is.
	hostB := startHost(t, f, "host-b.crt", "host-b.key", addrB, nil)

	sendUntilDelivered(t, hostA, hostB, overlayA, overlayB, "a-to-b")
	// Now B can reach A, using only what the handshake taught it.
	sendUntilDelivered(t, hostB, hostA, overlayB, overlayA, "b-to-a")
}

// Two hosts that know nothing about each other find one another through a
// lighthouse they both know.
func TestLighthouseDiscovery(t *testing.T) {
	f := newFabric()
	addrLH := mustAddrPort("192.0.2.10:4242")
	addrB, addrC := mustAddrPort("192.0.2.2:4242"), mustAddrPort("192.0.2.3:4242")
	overlayLH := netip.MustParseAddr("10.42.0.1")
	overlayB, overlayC := netip.MustParseAddr("10.42.0.2"), netip.MustParseAddr("10.42.0.3")

	startHost(t, f, "host-a.crt", "host-a.key", addrLH, func(c *Config) {
		c.AmLighthouse = true
	})
	hostB := startHost(t, f, "host-b.crt", "host-b.key", addrB, func(c *Config) {
		c.StaticHosts[overlayLH] = []netip.AddrPort{addrLH}
		c.Lighthouses = []netip.Addr{overlayLH}
	})
	hostC := startHost(t, f, "host-c.crt", "host-c.key", addrC, func(c *Config) {
		c.StaticHosts[overlayLH] = []netip.AddrPort{addrLH}
		c.Lighthouses = []netip.Addr{overlayLH}
	})

	// Neither B nor C has any static entry for the other; the only way this
	// can succeed is through the lighthouse.
	sendUntilDelivered(t, hostB, hostC, overlayB, overlayC, "b-found-c")
	sendUntilDelivered(t, hostC, hostB, overlayC, overlayB, "c-found-b")
}

// A lighthouse must not let one member rewrite another's location: that would
// let any mesh member redirect traffic for any other.
func TestLighthouseRejectsUpdateForAnotherHost(t *testing.T) {
	f := newFabric()
	addrLH, addrB := mustAddrPort("192.0.2.10:4242"), mustAddrPort("192.0.2.2:4242")
	overlayLH := netip.MustParseAddr("10.42.0.1")
	overlayB, overlayC := netip.MustParseAddr("10.42.0.2"), netip.MustParseAddr("10.42.0.3")

	lh := startHost(t, f, "host-a.crt", "host-a.key", addrLH, func(c *Config) {
		c.AmLighthouse = true
	})
	hostB := startHost(t, f, "host-b.crt", "host-b.key", addrB, func(c *Config) {
		c.StaticHosts[overlayLH] = []netip.AddrPort{addrLH}
		c.Lighthouses = []netip.Addr{overlayLH}
	})

	// Wait for B's tunnel to the lighthouse to come up.
	waitFor(t, func() bool {
		p, ok := lh.lookupPeer(overlayB)
		if !ok {
			return false
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.tun != nil
	}, "lighthouse tunnel with host-b")

	// B claims host-c lives at an address B controls.
	p, _ := hostB.lookupPeer(overlayLH)
	hostB.sendMeta(p, metaMessage{
		Type:      metaHostUpdateNotification,
		VpnAddr:   overlayC,
		AddrPorts: []netip.AddrPort{addrB},
	})

	// The lighthouse must not have recorded anything for host-c.
	time.Sleep(200 * time.Millisecond)
	if c, ok := lh.lookupPeer(overlayC); ok {
		c.mu.Lock()
		n := len(c.underlay)
		c.mu.Unlock()
		if n > 0 {
			t.Fatalf("lighthouse accepted host-b's claim about host-c's location")
		}
	}
}

// The certificate bounds which source addresses a peer may use. Without this
// check any authenticated member could impersonate any other.
func TestSpoofedSourceAddressDropped(t *testing.T) {
	f := newFabric()
	addrA, addrB := mustAddrPort("192.0.2.1:4242"), mustAddrPort("192.0.2.2:4242")
	overlayA, overlayB := netip.MustParseAddr("10.42.0.1"), netip.MustParseAddr("10.42.0.2")

	hostA := startHost(t, f, "host-a.crt", "host-a.key", addrA, func(c *Config) {
		c.StaticHosts[overlayB] = []netip.AddrPort{addrB}
	})
	hostB := startHost(t, f, "host-b.crt", "host-b.key", addrB, func(c *Config) {
		c.StaticHosts[overlayA] = []netip.AddrPort{addrA}
	})

	// Establish the tunnel first with a legitimate packet.
	sendUntilDelivered(t, hostA, hostB, overlayA, overlayB, "legitimate")

	// Now A sends a packet claiming to come from host-c, which its certificate
	// does not authorize.
	pa, ok := hostA.lookupPeer(overlayB)
	if !ok {
		t.Fatal("host-a has no peer record for host-b")
	}
	pa.mu.Lock()
	tun := pa.tun
	pa.mu.Unlock()

	spoofed := ipv4Packet(netip.MustParseAddr("10.42.0.3"), overlayB, "spoofed")
	if err := hostA.sendToPeer(pa, tun.encrypt(typeMessage, subTypeNone, spoofed)); err != nil {
		t.Fatalf("sending spoofed packet: %v", err)
	}

	// It must not reach the TUN. Anything that does arrive should be the
	// legitimate traffic, never the spoofed payload.
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case pkt := <-hostB.tun.Out:
			if len(pkt) >= 20 && bytes.Equal(pkt[20:], []byte("spoofed")) {
				t.Fatal("a packet with a source address the certificate forbids reached the TUN")
			}
		case <-deadline:
			return
		}
	}
}

func TestSendPacketWithoutRouteFails(t *testing.T) {
	f := newFabric()
	hostA := startHost(t, f, "host-a.crt", "host-a.key", mustAddrPort("192.0.2.1:4242"), nil)

	err := hostA.sendPacket(ipv4Packet(
		netip.MustParseAddr("10.42.0.1"),
		netip.MustParseAddr("10.42.0.99"),
		"nowhere"))
	if !errors.Is(err, ErrNoRoute) {
		t.Errorf("sendPacket to an unknown host = %v, want ErrNoRoute", err)
	}
}

func TestNonIPv4PacketRejected(t *testing.T) {
	f := newFabric()
	hostA := startHost(t, f, "host-a.crt", "host-a.key", mustAddrPort("192.0.2.1:4242"), nil)

	if err := hostA.sendPacket([]byte{0x60, 0x00, 0x00, 0x00}); err == nil {
		t.Error("accepted a non-IPv4 packet")
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestMetaMessageRoundTrip(t *testing.T) {
	want := metaMessage{
		Type:    metaHostQueryReply,
		VpnAddr: netip.MustParseAddr("10.42.0.7"),
		AddrPorts: []netip.AddrPort{
			mustAddrPort("192.0.2.1:4242"),
			mustAddrPort("198.51.100.9:51820"),
		},
		Counter: 17,
	}
	got, err := parseMetaMessage(want.marshal())
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if got.Type != want.Type || got.VpnAddr != want.VpnAddr || got.Counter != want.Counter {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
	if len(got.AddrPorts) != len(want.AddrPorts) {
		t.Fatalf("got %d addresses, want %d", len(got.AddrPorts), len(want.AddrPorts))
	}
	for i := range want.AddrPorts {
		if got.AddrPorts[i] != want.AddrPorts[i] {
			t.Errorf("address %d = %v, want %v", i, got.AddrPorts[i], want.AddrPorts[i])
		}
	}
}
