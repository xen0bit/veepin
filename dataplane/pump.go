package dataplane

import (
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/internal/vlog"
)

// Tunnel is the data-path view of one established security association. A
// protocol package supplies an implementation that encapsulates/decapsulates
// with the negotiated keys and reports the peer transport address to send to.
//
// Nothing here is ESP-specific: for IKEv2 the inbound key is the ESP SPI, but a
// protocol whose demux key sits elsewhere in the packet (WireGuard's receiver
// index, say) implements the same interface and supplies a matching Demux.
type Tunnel interface {
	// InboundKey identifies this tunnel on the wire: inbound packets whose Demux
	// yields this key belong here. It must agree with the pump's Demux.
	InboundKey() uint32
	// Routes are the inner destinations this tunnel carries. An outbound TUN
	// packet goes to the tunnel whose route matches its destination most
	// specifically; a packet matching none is dropped.
	//
	// A server-side IKEv2 tunnel returns its peer's assigned address as a /32; a
	// client returns 0.0.0.0/0, because everything leaving its TUN belongs to the
	// one server. WireGuard returns the peer's AllowedIPs.
	Routes() []netip.Prefix
	// PeerAddr is where encapsulated packets are sent (the peer's UDP address,
	// which may have floated to :4500 after IKEv2 NAT-T).
	PeerAddr() *net.UDPAddr

	// Encapsulate turns an inner IP packet into a protected payload.
	Encapsulate(ipPacket []byte) ([]byte, error)
	// Decapsulate turns a protected payload back into the inner IP packet.
	Decapsulate(pkt []byte) ([]byte, error)
}

// PaddingTunnel is an optional Tunnel capability: encapsulating a packet whose
// plaintext has been padded out to a requested size, as filler the peer
// authenticates and then discards.
//
// It is separate from Tunnel because the padding has to live inside each
// protocol's own wire format — ESP's traffic-flow-confidentiality padding
// (RFC 4303 §2.7), the trailing octets of a WireGuard transport message — and
// because a protocol without such a vehicle must still work. The pump discovers
// it by type assertion, the way it discovers SetPeerAddr, and a Tunnel that
// does not implement it is simply sent unpadded: the shaper degrades to a
// no-op rather than to an error.
//
// minInner is a floor, not an exact size. An implementation that cannot reach
// it must still return a valid packet.
type PaddingTunnel interface {
	Tunnel
	EncapsulatePadded(ipPacket []byte, minInner int) ([]byte, error)
}

// MultiTunnel is a Tunnel whose datagrams can carry more than one inner packet.
// Most cannot -- one datagram in, one packet out -- but an aggregating format
// such as RFC 9347 AGGFRAG puts several in each one, and returning only the
// first would silently drop the rest.
//
// DecapsulateMulti appends the inner packets to out and returns it, so a caller
// with a scratch slice reassembles without allocating. The returned packets are
// only valid until the next call.
type MultiTunnel interface {
	Tunnel
	DecapsulateMulti(pkt []byte, out [][]byte) ([][]byte, error)
}

// Sender writes an encapsulated datagram to a peer. Any protocol-specific
// framing (IKEv2's non-ESP marker, for instance) is the sender's business.
type Sender func(pkt []byte, to *net.UDPAddr)

// PacedTunnel is a Tunnel that transmits on its OWN schedule rather than on the
// pump's. The pump hands it each outbound packet and does not send anything;
// the tunnel decides when a datagram goes out, and how many.
//
// It exists for RFC 9347 constant-rate IP-TFS, where the whole security claim
// is that the datagram stream is independent of the traffic inside it. A
// read-encapsulate-send loop cannot provide that at any level of tuning: its
// output is one datagram per input packet, at the moment the input arrived,
// which is precisely the signal constant-rate transmission removes. So the
// schedule has to move, not the shaping.
//
// The pump keeps the socket and lends it: StartPacing receives the Sender when
// the tunnel is added, StopPacing is called when it is removed. A tunnel that
// held its own socket would not see MOBIKE's address changes, and would have to
// duplicate the batching the pump already does.
type PacedTunnel interface {
	Tunnel
	// Enqueue offers one inner packet for transmission, reporting whether it
	// was taken. False means the queue is full and the packet is dropped --
	// counted as DropPacerFull, which is the operator's signal that the offered
	// load exceeds the configured rate.
	//
	// pkt is only valid for the duration of the call: an implementation that
	// keeps it must copy.
	Enqueue(pkt []byte) bool
	// StartPacing begins transmission, writing each datagram through send.
	StartPacing(send Sender)
	// StopPacing ends it and releases whatever StartPacing began. It must be
	// safe to call without a preceding StartPacing, and safe to call twice.
	StopPacing()
}

// Demux extracts the tunnel-identifying key from an inbound packet, reporting
// false if the packet carries none and should be dropped. It is the one part of
// inbound routing that is protocol-specific: ESP puts its SPI in the first four
// octets, whereas WireGuard's receiver index sits at offset 4 and only on
// transport-data messages.
type Demux func(pkt []byte) (key uint32, ok bool)

// SPIDemux reads an ESP SPI from the first four octets (RFC 4303).
func SPIDemux(pkt []byte) (uint32, bool) {
	if len(pkt) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[:4]), true
}

// tunIO is the minimal TUN device interface the pump needs; *TUN satisfies it.
// It exists so the pump can be tested with an in-memory device.
type tunIO interface {
	Read(buf []byte) (int, error)
	Write(pkt []byte) (int, error)
}

// Pump moves packets between a TUN device and a set of tunnels.
type Pump struct {
	tun   tunIO
	log   *vlog.Logger
	send  Sender
	demux Demux

	// batchSend, when set (SetBatchSender), flushes a burst of encapsulated
	// packets bound for one peer in as few syscalls as the transport allows.
	// Only the GSO egress path produces bursts; without it every packet goes
	// through send one at a time.
	batchSend func(pkts [][]byte, to *net.UDPAddr)

	// vnet is true when tun is a GSO device (gsoTUN below): reads carry a
	// virtio-net header and may be super-frames for Run to segment, and every
	// write must be vnet-framed through vnetWrite. vnetWriteGSO writes a
	// GRO-coalesced super-frame with its own virtio-net header.
	vnet         bool
	vnetWrite    func(pkt []byte) (int, error)
	vnetWriteGSO func(hdr, pkt []byte) (int, error)

	// gro is the inbound-coalescing scratch (gro_linux.go), owned by the one
	// goroutine that calls HandleInboundBatch, like every per-pump scratch.
	gro groTable

	// shaper, when set (SetShaper), pads outbound packets so the inner
	// traffic's size pattern does not survive encapsulation (shape.go). Like
	// gro it is owned by the single TUN-reader goroutine and carries no lock.
	// Nil means no shaping, which is the default.
	shaper *Shaper

	// lastInbound is the unix-nanos time of the most recent *authenticated*
	// inbound packet on any tunnel — data or keepalive. It is the pump-level
	// liveness signal: a peer that has died stops producing authenticated
	// packets (its periodic keepalives included), so IdleFor grows without
	// bound. A protocol whose peer sends periodic keepalives turns this into a
	// client.Prober with a few lines (see IdleFor).
	lastInbound atomic.Int64

	// multiScratch is the reusable packet slice DecapsulateMulti appends into.
	// Only the single inbound goroutine touches it, so it needs no lock.
	multiScratch [][]byte

	// drops counts discarded packets by reason (counters.go). Indexed by
	// DropReason, so the increment is an array offset rather than a map write:
	// this sits on the drop path, which a flood of bad packets makes the
	// hottest path in the pump.
	drops [numDropReasons]atomic.Uint64
	// retired accumulates the counters of tunnels that have been removed, so
	// the pump-wide total does not go down when a peer disconnects. A total
	// that goes down is a total nobody can reason about.
	retired   TunnelStats
	retiredMu sync.Mutex

	mu     sync.RWMutex
	byKey  map[uint32]bound // inbound demux, with that tunnel's counters
	stats  map[Tunnel]*TunnelCounters
	routes routeTable // outbound, by longest-prefix match
	// mtu is the largest inner packet this path can carry; zero disables the
	// check entirely.
	mtu int

	closing bool
}

// bound is a registered tunnel and its counters, held together in the inbound
// demux map so that counting an inbound packet costs nothing beyond the lookup
// decapInbound was already doing.
//
// The Tunnel is a field rather than an embedded interface deliberately. The
// inbound path type-asserts it for SetPeerAddr and MultiTunnel, and embedding
// an interface promotes only that interface's own methods -- so a wrapper would
// silently stop satisfying both, turning an aggregating tunnel into one that
// delivers the first inner packet and drops the rest.
type bound struct {
	t Tunnel
	c *TunnelCounters
}

// gsoTUN is the optional GSO surface of the TUN device. *TUN provides it on
// Linux; the in-memory devices tests substitute may, to exercise the vnet
// path without a kernel. writeVnetGSO takes a pre-encoded virtio-net header so
// this interface stays portable (the header codec is Linux-only).
type gsoTUN interface {
	tunIO
	GSO() bool
	writeVnet(pkt []byte) (int, error)
	writeVnetGSO(hdr, pkt []byte) (int, error)
}

// NewPump creates a data-path pump over tun. send transmits encapsulated
// packets to peers; demux extracts the tunnel key from inbound packets, and a
// nil demux defaults to SPIDemux (ESP).
func NewPump(tun tunIO, send Sender, demux Demux, logger *slog.Logger) *Pump {
	if demux == nil {
		demux = SPIDemux
	}
	p := &Pump{
		tun: tun,
		// Wrapped here rather than taken as a vlog.Logger: dataplane is a
		// public package, and an internal type in an exported signature is one
		// no caller outside this module could satisfy.
		log:   vlog.From(logger),
		send:  send,
		demux: demux,
		byKey: make(map[uint32]bound),
		stats: make(map[Tunnel]*TunnelCounters),
	}
	// Seed the liveness clock so a freshly-built tunnel does not read as idle
	// before its first inbound packet arrives.
	p.lastInbound.Store(time.Now().UnixNano())
	if g, ok := tun.(gsoTUN); ok && g.GSO() {
		p.vnet = true
		p.vnetWrite = g.writeVnet
		p.vnetWriteGSO = g.writeVnetGSO
	}
	return p
}

// SetBatchSender registers a transport that can flush a burst of encapsulated
// packets bound for one peer in fewer syscalls (sendmmsg) than sending them
// one at a time. Bursts only arise on the GSO egress path — a TUN super-frame
// segments into many packets for the same tunnel — so a protocol without a
// batch-capable transport simply never calls this and loses nothing else.
func (p *Pump) SetBatchSender(f func(pkts [][]byte, to *net.UDPAddr)) {
	p.batchSend = f
}

// SetShaper installs downstream flow shaping (shape.go). A nil shaper, which is
// the default, sends every packet at its natural size.
//
// It must be called before Run, and only from the goroutine that will run the
// pump: the Shaper is unlocked scratch owned by the TUN reader.
func (p *Pump) SetShaper(s *Shaper) {
	p.shaper = s
}

// encap encapsulates one inner packet, padding it when the shaper asks for a
// size and the tunnel can produce one. A tunnel that implements no padding, or
// a shaper that wants none, takes the plain path with one type assertion of
// overhead.
func (p *Pump) encap(t Tunnel, pkt []byte, mtu int) ([]byte, error) {
	if target := p.shaper.Target(pkt, mtu); target > 0 {
		if pt, ok := t.(PaddingTunnel); ok {
			return pt.EncapsulatePadded(pkt, target)
		}
	}
	return t.Encapsulate(pkt)
}

// writeTUN writes one inner IP packet to the TUN, vnet-framed when the device
// requires it.
func (p *Pump) writeTUN(pkt []byte) (int, error) {
	if p.vnet {
		return p.vnetWrite(pkt)
	}
	return p.tun.Write(pkt)
}

// AddTunnel registers an established tunnel's data path: its inbound key for
// demux, and its routes for outbound.
func (p *Pump) AddTunnel(t Tunnel) {
	p.mu.Lock()
	c := p.counters(t)
	p.byKey[t.InboundKey()] = bound{t: t, c: c}
	for _, r := range t.Routes() {
		p.routes.insert(r, t)
	}
	p.mu.Unlock()

	// Started outside the lock: StartPacing spawns a goroutine that sends, and
	// send may take the pump's own locks. Holding mu across it is the kind of
	// deadlock that only appears once the tunnel is busy.
	if pt, ok := t.(PacedTunnel); ok {
		pt.StartPacing(p.send)
	}
}

// counters returns t's counter block, creating it on first registration. Called
// with mu held. A rekey that re-registers the same Tunnel keeps its counts,
// which is what an operator watching a peer's byte total expects.
func (p *Pump) counters(t Tunnel) *TunnelCounters {
	c := p.stats[t]
	if c == nil {
		c = &TunnelCounters{}
		p.stats[t] = c
	}
	return c
}

// RemoveTunnel unregisters a tunnel's data path: all of its inbound keys and its
// routes. Inbound keys are removed by identity rather than by t.InboundKey(),
// because a protocol whose demux key rotates (WireGuard on rekey) may have
// registered several keys through AddInboundKey since AddTunnel ran.
//
// Routes are removed by identity too, and for the same reason: a rekey installs
// the replacement SA before deleting the old one (so no packet is ever without
// an SA), and the replacement claims the very same prefixes — the client's /32
// on a server, 0.0.0.0/0 on a client. Retiring the old tunnel must not take the
// successor's routes with it.
func (p *Pump) RemoveTunnel(t Tunnel) {
	p.mu.Lock()
	for key, reg := range p.byKey {
		if reg.t == t {
			delete(p.byKey, key)
		}
	}
	for _, r := range t.Routes() {
		p.routes.removeOwned(r, t)
	}
	// Fold the departing tunnel's counts into the retired total before dropping
	// them, so the pump-wide figure keeps growing across a peer's whole life
	// rather than resetting when it disconnects.
	if c := p.stats[t]; c != nil {
		p.retiredMu.Lock()
		p.retired.add(c.Snapshot())
		p.retiredMu.Unlock()
		delete(p.stats, t)
	}
	p.mu.Unlock()

	// Outside the lock, as AddTunnel starts it: StopPacing waits for the send
	// goroutine to finish, and that goroutine may be inside send.
	if pt, ok := t.(PacedTunnel); ok {
		pt.StopPacing()
	}
}

// AddInboundKey routes inbound packets whose Demux yields key to t, in addition
// to any keys t already has. It exists for protocols whose inbound demux key
// changes over a tunnel's life — WireGuard's receiver index rotates on every
// rekey — so the new key can be registered without disturbing the old one, which
// must keep decrypting in-flight packets until it is removed.
func (p *Pump) AddInboundKey(key uint32, t Tunnel) {
	p.mu.Lock()
	p.byKey[key] = bound{t: t, c: p.counters(t)}
	p.mu.Unlock()
}

// RemoveInboundKey stops routing key to any tunnel. It is used to retire a
// WireGuard keypair's receiver index once its keys are no longer live.
func (p *Pump) RemoveInboundKey(key uint32) {
	p.mu.Lock()
	delete(p.byKey, key)
	p.mu.Unlock()
}

// IdleFor reports how long it has been since the last authenticated inbound
// packet (data or keepalive) on any tunnel. It is the raw material for a
// liveness probe: for a protocol whose peer sends periodic keepalives, an
// IdleFor beyond a few keepalive intervals means the peer is gone. It is
// meaningful from the moment NewPump returns (seeded to construction time), so a
// probe never reads a brand-new tunnel as dead.
func (p *Pump) IdleFor() time.Duration {
	return time.Since(time.Unix(0, p.lastInbound.Load()))
}

// HandleInbound processes an inbound protected datagram (already stripped of any
// protocol framing, such as IKEv2's UDP-encap marker). It demuxes to a tunnel,
// decapsulates, and writes the inner IP packet to the TUN device. from, when
// non-nil, is the datagram's UDP source: the tunnel's return address is updated
// to it so replies reach the peer's actual data socket (a road-warrior client
// sends ESP from a different port than IKE, so the IKE peer address is not a
// valid ESP return address). Pass nil on a connected socket where the source is
// implicit (client mode).
func (p *Pump) HandleInbound(pkt []byte, from *net.UDPAddr) {
	if t, c, ok := p.multiTunnelFor(pkt, from); ok {
		p.handleInboundMulti(t, c, pkt)
		return
	}
	inner, c, ok := p.decapInbound(pkt, from)
	if !ok {
		return
	}
	c.countRx(len(inner))
	if _, err := p.writeTUN(inner); err != nil {
		p.drops[DropTUNWrite].Add(1)
		if p.log != nil {
			p.log.Warnf("dataplane: TUN write failed: %v", err)
		}
	}
}

// multiTunnelFor resolves an inbound datagram to a MultiTunnel, if its tunnel is
// one. It is the only extra work an ordinary tunnel pays for the aggregating
// case: one map lookup that decapInbound would have done anyway.
func (p *Pump) multiTunnelFor(pkt []byte, from *net.UDPAddr) (MultiTunnel, *TunnelCounters, bool) {
	key, ok := p.demux(pkt)
	if !ok {
		return nil, nil, false
	}
	p.mu.RLock()
	b := p.byKey[key]
	p.mu.RUnlock()
	mt, ok := b.t.(MultiTunnel)
	if !ok {
		return nil, nil, false
	}
	if from != nil {
		if u, ok := b.t.(interface{ SetPeerAddr(*net.UDPAddr) }); ok {
			u.SetPeerAddr(from)
		}
	}
	return mt, b.c, true
}

// noteInbound records authenticated inbound activity for the liveness check.
// It exists so the two aggregated-decap paths -- the plain one here and the GRO
// one in gro_linux.go -- cannot drift on which of them remembers to.
func (p *Pump) noteInbound() { p.lastInbound.Store(time.Now().UnixNano()) }

// handleInboundMulti delivers every inner packet one aggregated datagram holds.
func (p *Pump) handleInboundMulti(t MultiTunnel, c *TunnelCounters, pkt []byte) {
	inners, err := t.DecapsulateMulti(pkt, p.multiScratch[:0])
	if err != nil {
		p.drops[DropDecapFailed].Add(1)
		if p.log != nil {
			p.log.Warnf("dataplane: aggregated decap failed: %v", err)
		}
		return
	}
	p.multiScratch = inners[:0]
	p.noteInbound()
	for _, inner := range inners {
		if len(inner) == 0 {
			continue
		}
		// Counted per inner packet, not per datagram: an aggregating format
		// carries several, and counting the datagram would make an IP-TFS
		// tunnel report a fraction of the packets it actually delivered.
		c.countRx(len(inner))
		if _, err := p.writeTUN(inner); err != nil {
			p.drops[DropTUNWrite].Add(1)
			if p.log != nil {
				p.log.Warnf("dataplane: TUN write failed: %v", err)
			}
			return
		}
	}
}

// HandleInboundBatch processes one read batch of inbound protected datagrams —
// the same contract as HandleInbound per packet, with froms[i] as packet i's
// source (froms may be nil for a connected socket). On a GSO device it also
// coalesces consecutive same-flow TCP segments back into super-frames written
// to the TUN once (gro_linux.go); the batch is the coalescing window, so
// nothing is ever held past this call and idle traffic gains no latency.
//
// Like HandleInbound, it must be called from the transport's single inbound
// goroutine.
func (p *Pump) HandleInboundBatch(pkts [][]byte, froms []*net.UDPAddr) {
	if p.vnet && p.handleInboundBatchGRO(pkts, froms) {
		return
	}
	for i, pkt := range pkts {
		var from *net.UDPAddr
		if froms != nil {
			from = froms[i]
		}
		p.HandleInbound(pkt, from)
	}
}

// decapInbound demuxes and decapsulates one inbound protected datagram,
// updating the tunnel's return address from from when given. It returns the
// inner IP packet and whether there is one to deliver.
func (p *Pump) decapInbound(pkt []byte, from *net.UDPAddr) ([]byte, *TunnelCounters, bool) {
	key, ok := p.demux(pkt)
	if !ok {
		p.drops[DropNoKey].Add(1)
		return nil, nil, false // no tunnel key in this packet
	}
	p.mu.RLock()
	b := p.byKey[key]
	p.mu.RUnlock()
	if b.t == nil {
		p.drops[DropUnknownKey].Add(1)
		return nil, nil, false // unknown key
	}
	if from != nil {
		if u, ok := b.t.(interface{ SetPeerAddr(*net.UDPAddr) }); ok {
			u.SetPeerAddr(from)
		}
	}
	inner, err := b.t.Decapsulate(pkt)
	if err != nil {
		p.drops[DropDecapFailed].Add(1)
		if p.log != nil {
			p.log.Warnf("dataplane: decap key %#x failed: %v", key, err)
		}
		return nil, nil, false
	}
	// Authenticated inbound activity — record it for liveness before the
	// keepalive short-circuit below, so a keepalive counts as proof of life.
	p.lastInbound.Store(time.Now().UnixNano())
	if len(inner) == 0 {
		// An authenticated packet with no inner payload: a WireGuard keepalive.
		// It kept the tunnel and any NAT binding alive by arriving; there is
		// nothing to deliver to the TUN -- but it is proof of life, so the
		// tunnel's last-seen moves even though its byte count does not.
		b.c.countRx(0)
		return nil, nil, false
	}
	return inner, b.c, true
}

// Run reads packets from the TUN device, routes each to the tunnel whose client
// owns the destination address, encapsulates, and sends. It blocks until the
// TUN device is closed. On a GSO device (OpenTUNGSO) it runs the vnet-aware
// loop instead, which segments TCP super-frames and flushes them in batches.
func (p *Pump) Run() {
	if p.vnet {
		p.runVnet()
		return
	}
	buf := make([]byte, 65535)
	for {
		n, err := p.tun.Read(buf)
		if err != nil {
			p.mu.RLock()
			closing := p.closing
			p.mu.RUnlock()
			if closing {
				return
			}
			if p.log != nil {
				p.log.Warnf("dataplane: TUN read error: %v", err)
			}
			return
		}
		pkt := buf[:n]
		p.routeOutbound(pkt)
	}
}

// routeOutbound routes one inner IP packet from the TUN to the tunnel whose
// route matches its destination most specifically, encapsulates it, and sends
// it. Packets that are neither IPv4 nor IPv6, and packets matching no route, are
// dropped.
func (p *Pump) routeOutbound(pkt []byte) {
	dst, ok := innerDest(pkt)
	if !ok {
		p.drops[DropNotIP].Add(1)
		return // not an IP packet we can route
	}
	p.mu.RLock()
	t := p.routes.lookup(dst)
	// One pointer-keyed map read, in the RLock the lookup already takes. The
	// route trie stores a bare Tunnel and threading counters through it would
	// ripple into its own tests for no gain -- this path allocates in
	// Encapsulate regardless, so it is not the allocation-free one.
	var c *TunnelCounters
	if t != nil {
		c = p.stats[t]
	}
	p.mu.RUnlock()
	if t == nil {
		p.drops[DropNoRoute].Add(1)
		return // no tunnel carries this destination
	}

	// Tell the host when a packet cannot fit, instead of dropping it silently.
	//
	// This is what stops MTU black-holing: the sending stack has set DF, so it
	// is waiting to be told the path MTU, and an ICMP fragmentation-needed
	// written back to the TUN is how it learns. Without it the tunnel comes up,
	// small packets work, and anything large hangs forever with no diagnostic.
	mtu := p.innerMTU()
	if mtu > 0 && NeedsFragmentation(pkt, mtu) {
		p.drops[DropTooBig].Add(1)
		if reply := FragNeeded(pkt, mtu); reply != nil {
			if _, err := p.writeTUN(reply); err != nil && p.log != nil {
				p.log.Printf("dataplane: writing ICMP frag-needed: %v", err)
			}
		}
		return
	}

	// A paced tunnel sends on its own schedule, so the pump's job ends at the
	// hand-off. Counting the packet here rather than at the wire is deliberate:
	// TxPackets is what the caller offered the tunnel, and a constant-rate
	// tunnel's datagram count is a property of its configured rate rather than
	// of the traffic -- reporting the latter as TxPackets would make an idle
	// IP-TFS tunnel look like it was moving traffic.
	if pt, ok := t.(PacedTunnel); ok {
		if !pt.Enqueue(pkt) {
			p.drops[DropPacerFull].Add(1)
			return
		}
		c.countTx(len(pkt))
		return
	}

	// Encapsulate copies the inner packet into its own plaintext buffer, so
	// passing the read buffer slice directly is safe and avoids a copy.
	out, err := p.encap(t, pkt, mtu)
	if err != nil {
		p.drops[DropEncapFailed].Add(1)
		if p.log != nil {
			p.log.Warnf("dataplane: encap failed: %v", err)
		}
		return
	}
	c.countTx(len(pkt))
	p.send(out, t.PeerAddr())
}

// Stats reports what this pump has moved: the sum over every tunnel it has ever
// carried, how many are registered now, and the drops by reason.
//
// The total includes tunnels that have since been removed. A peer that
// disconnected still carried what it carried, and a counter that goes down is
// one nobody -- and no time-series database -- can reason about.
func (p *Pump) Stats() PumpStats {
	out := PumpStats{Drops: make(map[string]uint64, numDropReasons)}
	for r := DropReason(0); r < numDropReasons; r++ {
		out.Drops[r.String()] = p.drops[r].Load()
	}
	p.retiredMu.Lock()
	out.Total = p.retired
	p.retiredMu.Unlock()

	p.mu.RLock()
	out.Tunnels = len(p.stats)
	for _, c := range p.stats {
		out.Total.add(c.Snapshot())
	}
	p.mu.RUnlock()
	return out
}

// TunnelStats reports one tunnel's counters, and whether the pump has any for
// it. A protocol's PeerDescriber calls this to fill in client.PeerInfo, which
// is what puts a byte count in front of an operator.
func (p *Pump) TunnelStats(t Tunnel) (TunnelStats, bool) {
	p.mu.RLock()
	c := p.stats[t]
	p.mu.RUnlock()
	if c == nil {
		return TunnelStats{}, false
	}
	return c.Snapshot(), true
}

// SetInnerMTU sets the largest inner packet this data path can carry. Zero
// disables the check, which is the behaviour from before it existed.
//
// It is a setter rather than a constructor argument because the value can change
// after the pump is running: an ICMP fragmentation-needed arriving from the
// underlay lowers it, which is the outbound half of path MTU discovery.
func (p *Pump) SetInnerMTU(mtu int) {
	p.mu.Lock()
	p.mtu = mtu
	p.mu.Unlock()
}

// innerMTU reads the current inner MTU.
func (p *Pump) innerMTU() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.mtu
}

// Close stops the pump.
func (p *Pump) Close() {
	p.mu.Lock()
	p.closing = true
	p.mu.Unlock()
}

// innerDest extracts the destination address from an inner IP packet, for either
// family. The version nibble selects the layout: IPv4's 4-byte destination sits
// at offset 16, IPv6's 16-byte destination at offset 24.
func innerDest(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	default:
		return netip.Addr{}, false
	}
}
