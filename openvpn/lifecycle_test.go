package openvpn

import (
	"log"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/openvpn/control"
	"github.com/xen0bit/veepin/internal/openvpn/data"
	"github.com/xen0bit/veepin/internal/openvpn/keys"
)

// discardTUN is a tunIO that answers the pump's Read forever and records what
// was written to it. Read blocks: nothing in these tests drives the outbound
// direction, and a Read returning immediately would spin the pump.
type discardTUN struct {
	mu      sync.Mutex
	written [][]byte
	block   chan struct{}
}

func newDiscardTUN() *discardTUN { return &discardTUN{block: make(chan struct{})} }

func (d *discardTUN) Read(buf []byte) (int, error) {
	<-d.block
	return 0, net.ErrClosed
}

func (d *discardTUN) Write(pkt []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.written = append(d.written, append([]byte(nil), pkt...))
	return len(pkt), nil
}

func (d *discardTUN) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.written)
}

// testServer is the parts of a Server the lifecycle reaches: a pool, a pump and
// the client map. It deliberately skips the socket and the TUN device, neither
// of which reapClient touches -- and opening a real TUN needs CAP_NET_ADMIN,
// which would make this a root-only test of a plain bookkeeping path.
func testServer(t *testing.T, cidr string) (*Server, *discardTUN) {
	t.Helper()
	pool, gw, err := dataplane.NewAddrPool(cidr)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	tun := newDiscardTUN()
	s := &Server{
		pool:    pool,
		gateway: gw,
		logger:  log.New(&testWriter{t}, "", 0),
		clients: make(map[string]*serverClient),
		closed:  make(chan struct{}),
	}
	s.pump = dataplane.NewPump(tun, func([]byte, *net.UDPAddr) {}, serverDataDemux, s.logger)
	t.Cleanup(func() { close(tun.block) })
	return s, tun
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

// establish brings up one client the way the tail of handshake does: an address
// from the pool, a peer-id, a keyed tunnel in the pump, and a map entry. It
// returns the client and the cipher the *peer* would seal with, so a test can
// put a real packet on the wire in the inbound direction.
func establish(t *testing.T, s *Server, addr string, peerID uint32) (*serverClient, *data.Cipher) {
	t.Helper()
	ip, err := s.pool.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	clientKS, err := keys.NewClientKeySource()
	if err != nil {
		t.Fatalf("client key source: %v", err)
	}
	serverKS, err := keys.NewServerKeySource()
	if err != nil {
		t.Fatalf("server key source: %v", err)
	}
	ks2 := &keys.KeySource2{Client: *clientKS, Server: *serverKS}
	var clientSID, serverSID keys.SessionID
	clientSID[7], serverSID[7] = 1, 2

	serverCipher, err := data.New(ks2.Derive(clientSID, serverSID, true), peerID, 0)
	if err != nil {
		t.Fatalf("server cipher: %v", err)
	}
	peerCipher, err := data.New(ks2.Derive(clientSID, serverSID, false), peerID, 0)
	if err != nil {
		t.Fatalf("peer cipher: %v", err)
	}

	ipAddr, _ := netip.AddrFromSlice(ip.To4())
	tun := &serverTunnel{
		cipher: serverCipher,
		peerID: peerID,
		routes: []netip.Prefix{netip.PrefixFrom(ipAddr, 32)},
	}
	udp, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	tun.peer.Store(udp)

	// A real control channel, because reapClient closes one and a nil here would
	// make the test pass against a teardown that skipped it.
	ch, err := control.NewServer(func([]byte) error { return nil }, 0, controlTimeout, nil)
	if err != nil {
		t.Fatalf("control channel: %v", err)
	}
	cl := &serverClient{ch: ch, addr: udp, tunnel: tun, assignedIP: ip, upAt: time.Now()}
	s.pump.AddTunnel(tun)
	s.mu.Lock()
	s.clients[udp.String()] = cl
	s.mu.Unlock()
	return cl, peerCipher
}

// TestAKeepalivePingIsProofOfLife is the assertion the whole reaper rests on. A
// tunnel carrying no user traffic at all still receives the client's ping every
// ten seconds; if that did not move the liveness clock, the reaper would
// disconnect every idle-but-present client at the one-minute mark -- a far worse
// bug than the leak it was written to fix.
func TestAKeepalivePingIsProofOfLife(t *testing.T) {
	s, _ := testServer(t, "10.8.0.0/24")
	cl, peer := establish(t, s, "198.51.100.7:1194", 7)

	cl.upAt = time.Now().Add(-2 * pingRestart)
	if _, gone := s.silentFor(cl); !gone {
		t.Fatal("a client silent since twice the ping-restart bound reads as alive; the reaper can never fire")
	}

	ping, err := peer.Seal(data.Ping)
	if err != nil {
		t.Fatalf("seal ping: %v", err)
	}
	s.pump.HandleInbound(ping, cl.addr)

	if silent, gone := s.silentFor(cl); gone {
		t.Errorf("a client that just pinged reads as silent for %s; a keepalive is no longer "+
			"proof of life and idle clients will be reaped", silent)
	}
}

// TestASilentClientReleasesEverythingItHeld is the leak this exists to close.
// Before the reaper, an established client that stopped answering kept its pool
// address, its tunnel in the pump's route trie and its map entry until the
// process exited.
func TestASilentClientReleasesEverythingItHeld(t *testing.T) {
	// A /29 is five host addresses past the gateway, so exhaustion is reachable
	// in a test and a released address is visibly reused.
	s, tun := testServer(t, "10.8.0.0/29")
	cl, peer := establish(t, s, "198.51.100.8:1194", 8)
	held := cl.assignedIP.String()

	s.reapClient(cl, "test")

	got, err := s.pool.Allocate()
	if err != nil {
		t.Fatalf("allocate after reap: %v", err)
	}
	if got.String() != held {
		t.Errorf("after reaping the holder of %s the pool handed out %s; the address was not released", held, got)
	}
	s.mu.Lock()
	n := len(s.clients)
	s.mu.Unlock()
	if n != 0 {
		t.Errorf("client map holds %d entries after the only client was reaped", n)
	}
	if _, ok := s.pump.TunnelStats(cl.tunnel); ok {
		t.Error("the pump still has counters for the reaped tunnel; RemoveTunnel did not run")
	}

	// The strongest form of "out of the data path": a packet the tunnel would
	// have decrypted now reaches nothing.
	before := tun.count()
	inner := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 8, 0, 2, 10, 8, 0, 1}
	pkt, err := peer.Seal(inner)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	s.pump.HandleInbound(pkt, cl.addr)
	if tun.count() != before {
		t.Error("a reaped client's packet still reached the TUN; its inbound key is still registered")
	}
}

// TestReapingTwiceCannotReleaseASuccessorsAddress is why the teardown is
// guarded rather than merely idempotent-looking. The liveness tick and a closed
// control channel can both reach reapClient; if the second one released again,
// it would hand back an address that by then belongs to a different client, and
// two clients would be assigned the same one.
func TestReapingTwiceCannotReleaseASuccessorsAddress(t *testing.T) {
	s, _ := testServer(t, "10.8.0.0/29")
	cl, _ := establish(t, s, "198.51.100.9:1194", 9)
	held := cl.assignedIP.String()

	s.reapClient(cl, "first")
	successor, err := s.pool.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if successor.String() != held {
		t.Fatalf("successor got %s, want the released %s", successor, held)
	}

	s.reapClient(cl, "second")

	again, err := s.pool.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if again.String() == successor.String() {
		t.Errorf("a second reap released %s out from under its new owner; two clients now hold it", again)
	}
}

// TestReapingASupersededSessionLeavesTheLiveOneAlone covers the client that
// reconnects from the same address before its old session has been noticed as
// gone. The map key is the address, so the new session owns it; deleting by key
// alone would strand the live session's control channel while leaving its
// tunnel in the pump.
func TestReapingASupersededSessionLeavesTheLiveOneAlone(t *testing.T) {
	s, _ := testServer(t, "10.8.0.0/24")
	const addr = "198.51.100.10:1194"
	old, _ := establish(t, s, addr, 10)

	// The reconnect: same address, new session, and it takes the map entry.
	fresh, _ := establish(t, s, addr, 11)

	s.reapClient(old, "superseded")

	s.mu.Lock()
	cur, ok := s.clients[addr]
	s.mu.Unlock()
	if !ok {
		t.Fatal("reaping the superseded session deleted the live one's map entry")
	}
	if cur != fresh {
		t.Error("the map no longer names the live session")
	}
}

// TestTheReapedFlagIsWhatStopsTheSecondTeardown pins the guard itself, so a
// refactor that drops the CompareAndSwap fails here rather than in the two
// tests above by way of an address collision.
func TestTheReapedFlagIsWhatStopsTheSecondTeardown(t *testing.T) {
	s, _ := testServer(t, "10.8.0.0/24")
	cl, _ := establish(t, s, "198.51.100.11:1194", 12)

	s.reapClient(cl, "first")
	if !cl.reaped.Load() {
		t.Fatal("reapClient left the guard clear; every later tick would tear down again")
	}
}
