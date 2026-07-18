package nebula

// The host engine.
//
// A nebula host is a peer in a mesh rather than a client or a server: it
// listens on one UDP port, and it opens a tunnel directly to any other host it
// has traffic for. Every one of the protocols veepin implemented before this
// was hub-and-spoke, so the shape here is genuinely different — there is no
// concentrator, and the same code runs on both ends.
//
// Two lookups drive everything:
//
//   - by overlay address, to find or create a tunnel for an outbound packet
//   - by local index, to find the tunnel an inbound packet belongs to
//
// The second is why a peer can change underlay address without renegotiating:
// nothing keys off the source address, so a NAT rebinding or a roam onto
// another network is invisible above the socket.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	// maxPacket bounds a datagram read. Nebula's own MTU ceiling is well under
	// this; the slack absorbs the header and AEAD tag.
	maxPacket = 9001

	// handshakeRetry is how often an unanswered handshake is resent. UDP drops
	// happen and there is no other retransmission in this protocol.
	handshakeRetry = 1 * time.Second
	// handshakeTimeout bounds how long a peer stays in handshaking state before
	// the attempt is abandoned.
	handshakeTimeout = 30 * time.Second
)

// ErrNoRoute reports a packet for an overlay address with no known peer.
var ErrNoRoute = errors.New("nebula: no peer for that overlay address")

// errNotIPv4 reports a packet the IPv4-only overlay cannot carry.
var errNotIPv4 = errors.New("nebula: outbound packet is not IPv4")

// packetConn is the UDP socket the host owns, narrowed so tests can substitute
// an in-memory pair.
type packetConn interface {
	ReadFrom(b []byte) (int, netip.AddrPort, error)
	WriteTo(b []byte, addr netip.AddrPort) (int, error)
	Close() error
	LocalAddr() net.Addr
}

// Logger is the subset of logging the host uses.
type Logger interface {
	Printf(format string, v ...any)
}

type nopLogger struct{}

func (nopLogger) Printf(string, ...any) {}

// Config configures a host.
type Config struct {
	// Identity is this host's certificate and key.
	Identity *Identity
	// CAs are the trust anchors peers are verified against.
	CAs *CAPool
	// Cipher selects the AEAD; "chachapoly" or the default, "aes".
	Cipher string
	// StaticHosts maps an overlay address to the underlay addresses it can be
	// reached at, for peers that are not discovered through a lighthouse.
	StaticHosts map[netip.Addr][]netip.AddrPort
	// Lighthouses are the overlay addresses of hosts that answer queries about
	// where other hosts are.
	Lighthouses []netip.Addr
	// AmLighthouse makes this host answer such queries.
	AmLighthouse bool
	// Logger receives operational messages.
	Logger Logger
}

func (c *Config) cipher() noiseCipher {
	if c.Cipher == "chachapoly" {
		return cipherChaChaPoly
	}
	return cipherAESGCM
}

func (c *Config) logger() Logger {
	if c.Logger == nil {
		return nopLogger{}
	}
	return c.Logger
}

// peer is everything known about one other host.
type peer struct {
	// addr is the peer's overlay address, and the key it is looked up by.
	addr netip.Addr

	mu sync.Mutex
	// underlay are the addresses this peer is reachable at, most recently
	// confirmed first.
	underlay []netip.AddrPort
	// tun is the established tunnel, nil until a handshake completes.
	tun *tunnel
	// pending is an in-flight handshake this host initiated.
	pending     *initiatorHandshake
	pendingMsg  []byte
	pendingAt   time.Time
	lastAttempt time.Time
}

// Host is a running nebula node.
type Host struct {
	cfg  *Config
	hs   *handshakeConfig
	conn packetConn
	tun  io.ReadWriteCloser
	log  Logger
	addr netip.Addr // this host's overlay address

	mu      sync.RWMutex
	byAddr  map[netip.Addr]*peer
	byIndex map[uint32]*tunnel
	closed  bool

	// lighthouses are resolved at start from the configured overlay addresses.
	lighthouses []netip.Addr

	wg   sync.WaitGroup
	done chan struct{}
}

// NewHost builds a host around an already-open socket and TUN.
func NewHost(cfg *Config, conn packetConn, tun io.ReadWriteCloser) (*Host, error) {
	if cfg.Identity == nil {
		return nil, errors.New("nebula: no identity configured")
	}
	if cfg.CAs == nil {
		return nil, errors.New("nebula: no certificate authorities configured")
	}
	addr, ok := cfg.Identity.Cert.Address()
	if !ok {
		return nil, errors.New("nebula: certificate carries no overlay address")
	}

	h := &Host{
		cfg: cfg,
		hs: &handshakeConfig{
			cipher:   cfg.cipher(),
			identity: cfg.Identity,
			pool:     cfg.CAs,
		},
		conn:        conn,
		tun:         tun,
		log:         cfg.logger(),
		addr:        addr,
		byAddr:      map[netip.Addr]*peer{},
		byIndex:     map[uint32]*tunnel{},
		lighthouses: append([]netip.Addr(nil), cfg.Lighthouses...),
		done:        make(chan struct{}),
	}

	for overlay, underlay := range cfg.StaticHosts {
		p := h.peerFor(overlay)
		p.mu.Lock()
		p.underlay = append([]netip.AddrPort(nil), underlay...)
		p.mu.Unlock()
	}
	return h, nil
}

// Addr returns this host's overlay address.
func (h *Host) Addr() netip.Addr { return h.addr }

// OverlayBits is the prefix length of the overlay network this host is on, as
// its certificate defines it.
func (h *Host) OverlayBits() int {
	if len(h.cfg.Identity.Cert.Networks) == 0 {
		return h.addr.BitLen()
	}
	return h.cfg.Identity.Cert.Networks[0].Bits()
}

// Run pumps both directions until the host is closed.
func (h *Host) Run() {
	h.wg.Add(3)
	go func() {
		defer h.wg.Done()
		h.readUDP()
	}()
	go func() {
		defer h.wg.Done()
		h.readTUN()
	}()
	go func() {
		defer h.wg.Done()
		h.maintain()
	}()
}

// maintain keeps this host's location current with its lighthouses. Without it
// a host that changes address becomes unreachable until it happens to initiate
// something itself, which in a mesh may never occur.
func (h *Host) maintain() {
	if len(h.lighthouses) == 0 {
		return
	}
	// Report immediately so a freshly started host is reachable straight away
	// rather than after the first full interval.
	h.reportToLighthouses()

	ticker := time.NewTicker(lighthouseUpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			h.reportToLighthouses()
		}
	}
}

// Close shuts the host down and waits for its loops to finish.
func (h *Host) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	close(h.done)
	h.mu.Unlock()

	err := h.conn.Close()
	if h.tun != nil {
		// The TUN read blocks until it is closed, so both have to go.
		_ = h.tun.Close()
	}
	h.wg.Wait()
	return err
}

// peerFor returns the peer record for an overlay address, creating it if needed.
func (h *Host) peerFor(addr netip.Addr) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p, ok := h.byAddr[addr]; ok {
		return p
	}
	p := &peer{addr: addr}
	h.byAddr[addr] = p
	return p
}

// lookupPeer returns an existing peer record, if any.
func (h *Host) lookupPeer(addr netip.Addr) (*peer, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	p, ok := h.byAddr[addr]
	return p, ok
}

// readTUN carries outbound packets from the TUN into tunnels.
func (h *Host) readTUN() {
	buf := make([]byte, maxPacket)
	for {
		n, err := h.tun.Read(buf)
		if err != nil {
			if !h.isClosed() {
				h.log.Printf("nebula: TUN read: %v", err)
			}
			return
		}
		if err := h.sendPacket(buf[:n]); err != nil {
			// A packet with nowhere to go is a dropped packet, not a fatal
			// condition: in a mesh it is entirely normal to have traffic for a
			// host whose tunnel has not been built yet.
			//
			// Non-IPv4 is not worth reporting at all. A version 1 overlay is
			// IPv4 only, and Linux puts IPv6 router solicitations and multicast
			// on any interface that comes up, so logging those would emit a
			// steady stream of drops that never means anything -- and would
			// bury the drops that do.
			if !errors.Is(err, errNotIPv4) {
				h.log.Printf("nebula: dropping outbound packet: %v", err)
			}
		}
	}
}

// sendPacket routes one inner IP packet to its peer.
func (h *Host) sendPacket(pkt []byte) error {
	dst, ok := destinationAddr(pkt)
	if !ok {
		return errNotIPv4
	}

	p, ok := h.lookupPeer(dst)
	if !ok {
		// Nothing is known about this address yet. In a mesh that is the normal
		// starting state rather than an error: if the address is inside the
		// overlay, a lighthouse can say where it lives.
		//
		// The overlay check matters. Without it any stray packet -- a broadcast,
		// something misrouted -- would create a peer record, and the host map
		// would grow without bound on traffic no peer ever answers.
		if !h.inOverlay(dst) || len(h.lighthouses) == 0 {
			return fmt.Errorf("%w: %v", ErrNoRoute, dst)
		}
		p = h.peerFor(dst)
	}

	p.mu.Lock()
	t := p.tun
	p.mu.Unlock()

	if t == nil {
		// Start building the tunnel; this packet is lost, and the next one
		// through will find the tunnel up. That is how nebula behaves too.
		h.beginHandshake(p)
		return fmt.Errorf("nebula: tunnel to %v is not up yet", dst)
	}

	out := t.encrypt(typeMessage, subTypeNone, pkt)
	return h.sendToPeer(p, out)
}

// sendToPeer writes a datagram to the peer's best known underlay address.
func (h *Host) sendToPeer(p *peer, datagram []byte) error {
	p.mu.Lock()
	addrs := append([]netip.AddrPort(nil), p.underlay...)
	p.mu.Unlock()

	if len(addrs) == 0 {
		return fmt.Errorf("%w: %v has no known underlay address", ErrNoRoute, p.addr)
	}
	// Only the first candidate is used for data; the others exist so a
	// handshake can probe them.
	_, err := h.conn.WriteTo(datagram, addrs[0])
	return err
}

// beginHandshake starts an exchange with a peer if one is not already running.
func (h *Host) beginHandshake(p *peer) {
	p.mu.Lock()
	if p.tun != nil {
		p.mu.Unlock()
		return
	}
	now := time.Now()
	if p.pending != nil && now.Sub(p.lastAttempt) < handshakeRetry {
		p.mu.Unlock()
		return
	}
	if p.pending != nil && now.Sub(p.pendingAt) > handshakeTimeout {
		// Give up on the old attempt and start fresh, so a handshake that was
		// answered by nothing does not wedge the peer forever.
		p.pending = nil
	}

	if p.pending == nil {
		pending, msg, err := h.hs.initiate()
		if err != nil {
			p.mu.Unlock()
			h.log.Printf("nebula: starting handshake with %v: %v", p.addr, err)
			return
		}
		p.pending = pending
		p.pendingMsg = msg
		p.pendingAt = now
	}
	p.lastAttempt = now
	msg := p.pendingMsg
	addrs := append([]netip.AddrPort(nil), p.underlay...)
	p.mu.Unlock()

	if len(addrs) == 0 {
		h.queryLighthouses(p.addr)
		return
	}
	// Probe every candidate: with hole punching, only one may work, and which
	// one is not knowable in advance.
	for _, a := range addrs {
		if _, err := h.conn.WriteTo(msg, a); err != nil {
			h.log.Printf("nebula: sending handshake to %v: %v", a, err)
		}
	}
}

// readUDP demultiplexes inbound datagrams.
func (h *Host) readUDP() {
	buf := make([]byte, maxPacket)
	for {
		n, from, err := h.conn.ReadFrom(buf)
		if err != nil {
			if !h.isClosed() {
				h.log.Printf("nebula: UDP read: %v", err)
			}
			return
		}
		h.handleDatagram(append([]byte(nil), buf[:n]...), from)
	}
}

func (h *Host) handleDatagram(pkt []byte, from netip.AddrPort) {
	hdr, err := parseHeader(pkt)
	if err != nil {
		return
	}
	if hdr.Version != headerVersion {
		return
	}

	switch hdr.Type {
	case typeHandshake:
		h.handleHandshake(pkt, hdr, from)
	case typeMessage:
		h.handleMessage(pkt, hdr, from)
	case typeLightHouse:
		h.handleLighthouse(pkt, hdr, from)
	case typeTest:
		h.handleTest(pkt, hdr, from)
	case typeCloseTunnel:
		h.handleClose(pkt, hdr)
	default:
		// Unknown types are ignored rather than treated as an error: a newer
		// peer may send something this build does not implement.
	}
}

// handleHandshake completes either role of an exchange.
func (h *Host) handleHandshake(pkt []byte, hdr header, from netip.AddrPort) {
	if hdr.RemoteIndex == 0 {
		// No remote index means this is a first message and we are responding.
		reply, t, err := h.hs.respond(pkt)
		if err != nil {
			h.log.Printf("nebula: handshake from %v rejected: %v", from, err)
			return
		}
		if _, err := h.conn.WriteTo(reply, from); err != nil {
			h.log.Printf("nebula: replying to handshake from %v: %v", from, err)
			return
		}
		h.install(t, from)
		h.log.Printf("nebula: tunnel up with %v (%s) at %v",
			t.PeerAddr(), t.peerCert.Name, from)
		return
	}

	// Otherwise it answers a handshake this host started. The remote index the
	// peer echoed identifies which one.
	p, ok := h.peerAwaiting(hdr.RemoteIndex)
	if !ok {
		return
	}
	p.mu.Lock()
	pending := p.pending
	p.mu.Unlock()
	if pending == nil {
		return
	}

	t, err := pending.complete(pkt)
	if err != nil {
		h.log.Printf("nebula: completing handshake with %v: %v", p.addr, err)
		return
	}

	p.mu.Lock()
	p.pending = nil
	p.pendingMsg = nil
	p.mu.Unlock()

	h.install(t, from)
	h.log.Printf("nebula: tunnel up with %v (%s) at %v", t.PeerAddr(), t.peerCert.Name, from)
}

// peerAwaiting finds the peer whose in-flight handshake used a local index.
func (h *Host) peerAwaiting(localIndex uint32) (*peer, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, p := range h.byAddr {
		p.mu.Lock()
		match := p.pending != nil && p.pending.localIndex == localIndex
		p.mu.Unlock()
		if match {
			return p, true
		}
	}
	return nil, false
}

// install registers a completed tunnel under both lookups, retiring whatever
// tunnel to the same peer it replaces.
//
// Retiring the old one is not just housekeeping. A tunnel stays usable for as
// long as it is reachable through byIndex, so leaving the superseded entry there
// would keep its keys live indefinitely — a peer that rehandshakes would go on
// having its previous session accepted, and the map would grow by one entry
// every time. Handshakes recur whenever a tunnel is lost, so this accumulates on
// exactly the hosts that are having trouble.
func (h *Host) install(t *tunnel, from netip.AddrPort) {
	p := h.peerFor(t.PeerAddr())

	p.mu.Lock()
	old := p.tun
	keep := t
	if old != nil {
		keep = h.resolveCollision(old, t)
	}
	p.tun = keep
	// The address the handshake actually arrived from is authoritative: it is
	// where the peer can be reached right now, whatever configuration said.
	p.underlay = append([]netip.AddrPort{from}, filterOut(p.underlay, from)...)
	p.mu.Unlock()

	loser := t
	if keep == t {
		loser = old
	}

	h.mu.Lock()
	if loser != nil && loser != keep {
		delete(h.byIndex, loser.localIndex)
	}
	h.byIndex[keep.localIndex] = keep
	h.mu.Unlock()
}

// resolveCollision picks which of two tunnels to the same peer survives.
//
// Two hosts routinely key a tunnel to each other simultaneously here: a
// lighthouse answering a query also tells the target to punch, and the target
// starts its own handshake while the asker is starting one. Both complete, and
// each side ends up holding two.
//
// Simply keeping the newer one is not enough, because the two sides do not see
// them in the same order -- each could keep a different tunnel, and then every
// packet one sends arrives on an index the other has retired. So the winner has
// to be chosen by a rule both sides evaluate to the same answer using only what
// they both know: the tunnel initiated by the numerically lower overlay address
// wins. Whichever host is asking, that names the same tunnel.
//
// When both tunnels were initiated by the same side there is no collision to
// resolve -- it is an ordinary rehandshake -- and the newer one wins.
func (h *Host) resolveCollision(old, fresh *tunnel) *tunnel {
	if old.weInitiated == fresh.weInitiated {
		return fresh
	}
	// True when this host is the one whose initiations win.
	// True when this host is the one whose initiations win.
	oursWins := h.addr.Compare(fresh.PeerAddr()) < 0
	if fresh.weInitiated == oursWins {
		return fresh
	}
	return old
}

func filterOut(addrs []netip.AddrPort, drop netip.AddrPort) []netip.AddrPort {
	out := addrs[:0:0]
	for _, a := range addrs {
		if a != drop {
			out = append(out, a)
		}
	}
	return out
}

// handleMessage decrypts data traffic and hands it to the TUN.
func (h *Host) handleMessage(pkt []byte, hdr header, from netip.AddrPort) {
	h.mu.RLock()
	t, ok := h.byIndex[hdr.RemoteIndex]
	h.mu.RUnlock()
	if !ok {
		return
	}

	_, payload, err := t.decrypt(pkt)
	if err != nil {
		h.log.Printf("nebula: dropping packet from %v: %v", from, err)
		return
	}

	// The peer's certificate says which source addresses it may use. Enforcing
	// it here is what stops an authenticated host from impersonating another:
	// without this, any valid member could inject traffic claiming to come from
	// any address in the mesh.
	if src, ok := sourceAddr(payload); !ok || !certAllows(t.peerCert, src) {
		h.log.Printf("nebula: dropping packet from %v (%s): source address not permitted by its certificate",
			t.PeerAddr(), t.peerCert.Name)
		return
	}

	h.noteRoam(t, from)

	if _, err := h.tun.Write(payload); err != nil {
		// A TUN that will not take a packet is a dropped packet, not a dead
		// host: the interface may still be coming up.
		h.log.Printf("nebula: TUN write: %v", err)
	}
}

// noteRoam records a peer that has started arriving from a new address.
func (h *Host) noteRoam(t *tunnel, from netip.AddrPort) {
	p, ok := h.lookupPeer(t.PeerAddr())
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.underlay) > 0 && p.underlay[0] == from {
		return
	}
	// This only runs after the packet authenticated, so the new address is
	// attested by the tunnel's keys rather than merely claimed.
	p.underlay = append([]netip.AddrPort{from}, filterOut(p.underlay, from)...)
}

// handleTest answers nebula's reachability probe.
func (h *Host) handleTest(pkt []byte, hdr header, _ netip.AddrPort) {
	h.mu.RLock()
	t, ok := h.byIndex[hdr.RemoteIndex]
	h.mu.RUnlock()
	if !ok {
		return
	}
	_, payload, err := t.decrypt(pkt)
	if err != nil {
		return
	}
	if hdr.Subtype != subTypeTestRequest {
		return
	}
	p, ok := h.lookupPeer(t.PeerAddr())
	if !ok {
		return
	}
	if err := h.sendToPeer(p, t.encrypt(typeTest, subTypeTestReply, payload)); err != nil {
		h.log.Printf("nebula: replying to test from %v: %v", t.PeerAddr(), err)
	}
}

// handleClose tears a tunnel down at the peer's request.
func (h *Host) handleClose(pkt []byte, hdr header) {
	h.mu.RLock()
	t, ok := h.byIndex[hdr.RemoteIndex]
	h.mu.RUnlock()
	if !ok {
		return
	}
	// Authenticate before acting: an unauthenticated close would be a trivial
	// way to knock tunnels down.
	if _, _, err := t.decrypt(pkt); err != nil {
		return
	}

	h.mu.Lock()
	delete(h.byIndex, t.localIndex)
	h.mu.Unlock()

	if p, ok := h.lookupPeer(t.PeerAddr()); ok {
		p.mu.Lock()
		if p.tun == t {
			p.tun = nil
		}
		p.mu.Unlock()
	}
	h.log.Printf("nebula: tunnel with %v closed by peer", t.PeerAddr())
}

func (h *Host) isClosed() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.closed
}

// inOverlay reports whether an address falls inside one of the networks this
// host's own certificate places it on, which is the mesh it can ask about.
func (h *Host) inOverlay(addr netip.Addr) bool {
	for _, n := range h.cfg.Identity.Cert.Networks {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// certAllows reports whether a certificate authorizes an inner source address.
func certAllows(c *Certificate, src netip.Addr) bool {
	for _, n := range c.Networks {
		if n.Addr() == src {
			return true
		}
	}
	// A host may also route for the unsafe networks its certificate names.
	for _, n := range c.UnsafeNetworks {
		if n.Contains(src) {
			return true
		}
	}
	return false
}

// sourceAddr reads the source address of an IPv4 packet.
func sourceAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[12:16])), true
}

// destinationAddr reads the destination address of an IPv4 packet.
func destinationAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[16:20])), true
}
