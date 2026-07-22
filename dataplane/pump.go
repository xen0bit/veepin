package dataplane

import (
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"sync"
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

// Sender writes an encapsulated datagram to a peer. Any protocol-specific
// framing (IKEv2's non-ESP marker, for instance) is the sender's business.
type Sender func(pkt []byte, to *net.UDPAddr)

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
	log   *log.Logger
	send  Sender
	demux Demux

	// batchSend, when set (SetBatchSender), flushes a burst of encapsulated
	// packets bound for one peer in as few syscalls as the transport allows.
	// Only the GSO egress path produces bursts; without it every packet goes
	// through send one at a time.
	batchSend func(pkts [][]byte, to *net.UDPAddr)

	// vnet is true when tun is a GSO device (gsoTUN below): reads carry a
	// virtio-net header and may be super-frames for Run to segment, and every
	// write must be vnet-framed through vnetWrite.
	vnet      bool
	vnetWrite func(pkt []byte) (int, error)

	mu     sync.RWMutex
	byKey  map[uint32]Tunnel // inbound demux
	routes routeTable        // outbound, by longest-prefix match
	// mtu is the largest inner packet this path can carry; zero disables the
	// check entirely.
	mtu int

	closing bool
}

// gsoTUN is the optional GSO surface of the TUN device. *TUN provides it on
// Linux; the in-memory devices tests substitute may, to exercise the vnet
// path without a kernel.
type gsoTUN interface {
	tunIO
	GSO() bool
	writeVnet(pkt []byte) (int, error)
}

// NewPump creates a data-path pump over tun. send transmits encapsulated
// packets to peers; demux extracts the tunnel key from inbound packets, and a
// nil demux defaults to SPIDemux (ESP).
func NewPump(tun tunIO, send Sender, demux Demux, logger *log.Logger) *Pump {
	if demux == nil {
		demux = SPIDemux
	}
	p := &Pump{
		tun:   tun,
		log:   logger,
		send:  send,
		demux: demux,
		byKey: make(map[uint32]Tunnel),
	}
	if g, ok := tun.(gsoTUN); ok && g.GSO() {
		p.vnet = true
		p.vnetWrite = g.writeVnet
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
	defer p.mu.Unlock()
	p.byKey[t.InboundKey()] = t
	for _, r := range t.Routes() {
		p.routes.insert(r, t)
	}
}

// RemoveTunnel unregisters a tunnel's data path: all of its inbound keys and its
// routes. Inbound keys are removed by identity rather than by t.InboundKey(),
// because a protocol whose demux key rotates (WireGuard on rekey) may have
// registered several keys through AddInboundKey since AddTunnel ran.
func (p *Pump) RemoveTunnel(t Tunnel) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, reg := range p.byKey {
		if reg == t {
			delete(p.byKey, key)
		}
	}
	for _, r := range t.Routes() {
		p.routes.remove(r)
	}
}

// AddInboundKey routes inbound packets whose Demux yields key to t, in addition
// to any keys t already has. It exists for protocols whose inbound demux key
// changes over a tunnel's life — WireGuard's receiver index rotates on every
// rekey — so the new key can be registered without disturbing the old one, which
// must keep decrypting in-flight packets until it is removed.
func (p *Pump) AddInboundKey(key uint32, t Tunnel) {
	p.mu.Lock()
	p.byKey[key] = t
	p.mu.Unlock()
}

// RemoveInboundKey stops routing key to any tunnel. It is used to retire a
// WireGuard keypair's receiver index once its keys are no longer live.
func (p *Pump) RemoveInboundKey(key uint32) {
	p.mu.Lock()
	delete(p.byKey, key)
	p.mu.Unlock()
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
	key, ok := p.demux(pkt)
	if !ok {
		return // no tunnel key in this packet
	}
	p.mu.RLock()
	t := p.byKey[key]
	p.mu.RUnlock()
	if t == nil {
		return // unknown key
	}
	if from != nil {
		if u, ok := t.(interface{ SetPeerAddr(*net.UDPAddr) }); ok {
			u.SetPeerAddr(from)
		}
	}
	inner, err := t.Decapsulate(pkt)
	if err != nil {
		if p.log != nil {
			p.log.Printf("dataplane: decap key %#x failed: %v", key, err)
		}
		return
	}
	if len(inner) == 0 {
		// An authenticated packet with no inner payload: a WireGuard keepalive.
		// It kept the tunnel and any NAT binding alive by arriving; there is
		// nothing to deliver to the TUN.
		return
	}
	if _, err := p.writeTUN(inner); err != nil {
		if p.log != nil {
			p.log.Printf("dataplane: TUN write failed: %v", err)
		}
	}
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
				p.log.Printf("dataplane: TUN read error: %v", err)
			}
			return
		}
		pkt := buf[:n]
		p.routeOutbound(pkt)
	}
}

// routeOutbound routes one inner IP packet from the TUN to the tunnel whose
// route matches its destination most specifically, encapsulates it, and sends
// it. Non-IPv4 packets and packets matching no route are dropped.
func (p *Pump) routeOutbound(pkt []byte) {
	dst, ok := ipv4Dest(pkt)
	if !ok {
		return // not IPv4; this build tunnels IPv4 only
	}
	p.mu.RLock()
	t := p.routes.lookup(dst)
	p.mu.RUnlock()
	if t == nil {
		return // no tunnel carries this destination
	}

	// Tell the host when a packet cannot fit, instead of dropping it silently.
	//
	// This is what stops MTU black-holing: the sending stack has set DF, so it
	// is waiting to be told the path MTU, and an ICMP fragmentation-needed
	// written back to the TUN is how it learns. Without it the tunnel comes up,
	// small packets work, and anything large hangs forever with no diagnostic.
	if mtu := p.innerMTU(); mtu > 0 && NeedsFragmentation(pkt, mtu) {
		if reply := FragNeeded(pkt, mtu); reply != nil {
			if _, err := p.writeTUN(reply); err != nil && p.log != nil {
				p.log.Printf("dataplane: writing ICMP frag-needed: %v", err)
			}
		}
		return
	}

	// Encapsulate copies the inner packet into its own plaintext buffer, so
	// passing the read buffer slice directly is safe and avoids a copy.
	out, err := t.Encapsulate(pkt)
	if err != nil {
		if p.log != nil {
			p.log.Printf("dataplane: encap failed: %v", err)
		}
		return
	}
	p.send(out, t.PeerAddr())
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

// ipv4Dest extracts the destination address from an IPv4 packet header.
func ipv4Dest(pkt []byte) (uint32, bool) {
	if len(pkt) < 20 {
		return 0, false
	}
	if pkt[0]>>4 != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[16:20]), true
}
