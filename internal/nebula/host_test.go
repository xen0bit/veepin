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

func (c *memConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	select {
	case d := <-c.queue:
		return copy(b, d.body), d.from, nil
	case <-c.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (c *memConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
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

// A rehandshake with the same peer must retire the tunnel it replaces. A tunnel
// is usable for as long as it is reachable through the index map, so leaving the
// old entry there would keep its keys live indefinitely and grow the map by one
// entry per handshake -- on exactly the hosts that are already having trouble.
func TestRehandshakeRetiresTheOldTunnel(t *testing.T) {
	f := newFabric()
	addrA, addrB := mustAddrPort("192.0.2.1:4242"), mustAddrPort("192.0.2.2:4242")
	overlayA, overlayB := netip.MustParseAddr("10.42.0.1"), netip.MustParseAddr("10.42.0.2")

	hostA := startHost(t, f, "host-a.crt", "host-a.key", addrA, func(c *Config) {
		c.StaticHosts[overlayB] = []netip.AddrPort{addrB}
	})
	hostB := startHost(t, f, "host-b.crt", "host-b.key", addrB, func(c *Config) {
		c.StaticHosts[overlayA] = []netip.AddrPort{addrA}
	})

	sendUntilDelivered(t, hostA, hostB, overlayA, overlayB, "first-session")

	pb, ok := hostB.lookupPeer(overlayA)
	if !ok {
		t.Fatal("host-b has no peer record for host-a")
	}
	pb.mu.Lock()
	firstTunnel := pb.tun
	pb.mu.Unlock()
	if firstTunnel == nil {
		t.Fatal("host-b has no tunnel after the first session")
	}

	// Force host-a to build a fresh tunnel to the same peer.
	pa, _ := hostA.lookupPeer(overlayB)
	pa.mu.Lock()
	pa.tun = nil
	pa.pending = nil
	pa.lastAttempt = time.Time{}
	pa.mu.Unlock()

	sendUntilDelivered(t, hostA, hostB, overlayA, overlayB, "second-session")

	waitFor(t, func() bool {
		pb.mu.Lock()
		defer pb.mu.Unlock()
		return pb.tun != nil && pb.tun != firstTunnel
	}, "host-b to accept a replacement tunnel")

	hostB.mu.RLock()
	_, stale := hostB.byIndex[firstTunnel.localIndex]
	count := len(hostB.byIndex)
	hostB.mu.RUnlock()

	if stale {
		t.Error("the superseded tunnel is still reachable by index; its keys remain live")
	}
	if count != 1 {
		t.Errorf("host-b holds %d tunnels after a rehandshake, want 1", count)
	}
}

// Simultaneous initiation is routine in a mesh -- a lighthouse answering a
// query also tells the target to punch, so both sides start a handshake at once
// and both complete. The two sides do not see the resulting tunnels in the same
// order, so "keep the newest" would let each keep a different one, and every
// packet would then arrive on an index the other had retired. Both sides must
// therefore reach the same verdict.
func TestCollisionResolvesToTheSameTunnelOnBothSides(t *testing.T) {
	lower := netip.MustParseAddr("10.42.0.1")
	higher := netip.MustParseAddr("10.42.0.2")

	// Build the two views of one collision. On each host, "ours" is the tunnel
	// it initiated and "theirs" the one it answered.
	lowerHost := &Host{addr: lower}
	higherHost := &Host{addr: higher}

	lowerOurs := &tunnel{weInitiated: true, peerAddr: higher, localIndex: 1}
	lowerTheirs := &tunnel{weInitiated: false, peerAddr: higher, localIndex: 2}
	higherOurs := &tunnel{weInitiated: true, peerAddr: lower, localIndex: 3}
	higherTheirs := &tunnel{weInitiated: false, peerAddr: lower, localIndex: 4}

	// The rule names the tunnel initiated by the lower address. For the lower
	// host that is the one it initiated; for the higher host, the one it
	// answered. Check both arrival orders, since that is the whole point.
	for _, tc := range []struct {
		name       string
		host       *Host
		old, fresh *tunnel
		want       *tunnel
	}{
		{"lower host, own tunnel first", lowerHost, lowerOurs, lowerTheirs, lowerOurs},
		{"lower host, peer tunnel first", lowerHost, lowerTheirs, lowerOurs, lowerOurs},
		{"higher host, own tunnel first", higherHost, higherOurs, higherTheirs, higherTheirs},
		{"higher host, peer tunnel first", higherHost, higherTheirs, higherOurs, higherTheirs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.host.resolveCollision(tc.old, tc.fresh); got != tc.want {
				t.Errorf("kept the wrong tunnel: got localIndex %d, want %d",
					got.localIndex, tc.want.localIndex)
			}
		})
	}

	// The two survivors must be the two ends of one tunnel: the lower host kept
	// the one it initiated, so the higher host must have kept the one it
	// answered. If both kept the tunnel they initiated, they would be talking
	// past each other.
	lowerKept := lowerHost.resolveCollision(lowerTheirs, lowerOurs)
	higherKept := higherHost.resolveCollision(higherTheirs, higherOurs)
	if lowerKept.weInitiated == higherKept.weInitiated {
		t.Error("both hosts kept a tunnel with the same initiator; they are not the same tunnel")
	}
}

// An ordinary rehandshake is not a collision -- both tunnels have the same
// initiator, and the newer one simply wins.
func TestRehandshakeKeepsTheNewerTunnel(t *testing.T) {
	h := &Host{addr: netip.MustParseAddr("10.42.0.1")}
	peer := netip.MustParseAddr("10.42.0.2")

	old := &tunnel{weInitiated: true, peerAddr: peer, localIndex: 1}
	fresh := &tunnel{weInitiated: true, peerAddr: peer, localIndex: 2}
	if got := h.resolveCollision(old, fresh); got != fresh {
		t.Errorf("rehandshake kept localIndex %d, want the newer %d", got.localIndex, fresh.localIndex)
	}

	oldR := &tunnel{weInitiated: false, peerAddr: peer, localIndex: 3}
	freshR := &tunnel{weInitiated: false, peerAddr: peer, localIndex: 4}
	if got := h.resolveCollision(oldR, freshR); got != freshR {
		t.Errorf("rehandshake kept localIndex %d, want the newer %d", got.localIndex, freshR.localIndex)
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

// Tunnels that carry nothing are dropped, which is what bounds both the host
// map and a tunnel's key lifetime.
//
// Neither veepin nor nebula rotates keys on a timer or a counter -- nebula's
// tryRehandshake re-keys only when the host's own certificate changes -- so a
// tunnel is re-keyed by going idle and being rebuilt on the next packet. Without
// expiry, veepin held every tunnel it ever built, forever.
func TestIdleTunnelsAreDropped(t *testing.T) {
	f := newFabric()
	addrA, addrB := mustAddrPort("192.0.2.1:4242"), mustAddrPort("192.0.2.2:4242")
	overlayA, overlayB := netip.MustParseAddr("10.42.0.1"), netip.MustParseAddr("10.42.0.2")

	hostA := startHost(t, f, "host-a.crt", "host-a.key", addrA, func(c *Config) {
		c.StaticHosts[overlayB] = []netip.AddrPort{addrB}
	})
	hostB := startHost(t, f, "host-b.crt", "host-b.key", addrB, func(c *Config) {
		c.StaticHosts[overlayA] = []netip.AddrPort{addrA}
	})

	sendUntilDelivered(t, hostA, hostB, overlayA, overlayB, "establish")

	hostB.mu.RLock()
	before := len(hostB.byIndex)
	hostB.mu.RUnlock()
	if before == 0 {
		t.Fatal("no tunnel was established")
	}

	// Age the tunnel past the timeout rather than waiting ten minutes for it.
	hostB.mu.RLock()
	for _, tun := range hostB.byIndex {
		tun.lastSeen.Store(time.Now().Add(-2 * tunnelIdleTimeout).UnixNano())
		tun.established = time.Now().Add(-2 * tunnelIdleTimeout)
	}
	hostB.mu.RUnlock()

	hostB.expireTunnels()

	hostB.mu.RLock()
	after := len(hostB.byIndex)
	hostB.mu.RUnlock()
	if after != 0 {
		t.Errorf("%d idle tunnels survived expiry, want 0", after)
	}

	// The peer record must forget the dropped tunnel too, or an outbound packet
	// would be sealed with keys the far side has thrown away.
	if p, ok := hostB.lookupPeer(overlayA); ok {
		p.mu.Lock()
		stale := p.tun != nil
		p.mu.Unlock()
		if stale {
			t.Error("the peer still points at a tunnel that was expired")
		}
	}
}

// A busy tunnel must not be expired: liveness comes from packets that
// authenticated, so ordinary traffic keeps it alive.
func TestBusyTunnelsSurviveExpiry(t *testing.T) {
	f := newFabric()
	addrA, addrB := mustAddrPort("192.0.2.1:4242"), mustAddrPort("192.0.2.2:4242")
	overlayA, overlayB := netip.MustParseAddr("10.42.0.1"), netip.MustParseAddr("10.42.0.2")

	hostA := startHost(t, f, "host-a.crt", "host-a.key", addrA, func(c *Config) {
		c.StaticHosts[overlayB] = []netip.AddrPort{addrB}
	})
	hostB := startHost(t, f, "host-b.crt", "host-b.key", addrB, func(c *Config) {
		c.StaticHosts[overlayA] = []netip.AddrPort{addrA}
	})

	sendUntilDelivered(t, hostA, hostB, overlayA, overlayB, "establish")
	hostB.expireTunnels()

	hostB.mu.RLock()
	after := len(hostB.byIndex)
	hostB.mu.RUnlock()
	if after == 0 {
		t.Error("a tunnel carrying traffic was expired")
	}
}
