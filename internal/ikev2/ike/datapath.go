package ike

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
)

// Inbound drop sentinels. Like the esp package's, these are pre-built rather
// than formatted per packet: they are returned on the data path's hot reject
// route, where a flood of stray datagrams must create no garbage.
var (
	errDummyPacket = errors.New("ike: ESP dummy packet (next-header 59)")
	errBadInner    = errors.New("ike: inner packet does not match its declared length")
)

// hostRoute expresses one assigned IPv4 address as a single-host /32 route. It
// returns nil for a non-IPv4 (or nil) address, which leaves that family unrouted
// rather than routing it wrongly.
func hostRoute(ip net.IP) []netip.Prefix {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	addr, ok := netip.AddrFromSlice(v4)
	if !ok {
		return nil
	}
	return []netip.Prefix{netip.PrefixFrom(addr, 32)}
}

// hostRoute6 expresses one assigned IPv6 address as a single-host /128 route,
// or nil when no v6 address was assigned.
func hostRoute6(ip net.IP) []netip.Prefix {
	if ip == nil {
		return nil
	}
	addr, ok := netip.AddrFromSlice(ip.To16())
	if !ok || addr.Is4() {
		return nil
	}
	return []netip.Prefix{netip.PrefixFrom(addr, 128)}
}

// defaultRoute is every IPv4 destination: what a client's single tunnel to its
// server carries.
func defaultRoute() []netip.Prefix {
	return []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
}

// defaultRoute6 is every IPv6 destination, the v6 half of a full tunnel.
func defaultRoute6() []netip.Prefix {
	return []netip.Prefix{netip.PrefixFrom(netip.IPv6Unspecified(), 0)}
}

// espTunnel adapts an established Child SA to the dataplane.Tunnel interface,
// wrapping an esp.SA plus the routing metadata the pump needs. The tunnel key
// the pump demuxes on is the Child SA's inbound ESP SPI.
//
// peer is atomic: it is read on the pump's outbound goroutine (PeerAddr) and
// updated on the server's inbound-ESP goroutine (SetPeerAddr) as ESP arrives, so
// return traffic tracks the peer's real ESP source address rather than the IKE
// address it authenticated from.
type espTunnel struct {
	espSA  *esp.SA
	inSPI  uint32
	routes []netip.Prefix
	peer   atomic.Pointer[net.UDPAddr]
}

func (t *espTunnel) InboundKey() uint32     { return t.inSPI }
func (t *espTunnel) Routes() []netip.Prefix { return t.routes }
func (t *espTunnel) PeerAddr() *net.UDPAddr { return t.peer.Load() }

// SetPeerAddr updates the ESP return address, but only when it actually changes,
// to keep the inbound data-path hot loop free of needless atomic stores.
func (t *espTunnel) SetPeerAddr(a *net.UDPAddr) {
	if a == nil {
		return
	}
	if cur := t.peer.Load(); cur != nil && cur.Port == a.Port && cur.IP.Equal(a.IP) {
		return
	}
	t.peer.Store(a)
}

// Encapsulate protects one inner IP datagram as ESP (tunnel mode). The inner
// packet's own version nibble sets the ESP next-header — IPv4 (4) or IPv6 (41) —
// so one dual-stack Child SA carries both families.
func (t *espTunnel) Encapsulate(ipPacket []byte) ([]byte, error) {
	return t.espSA.Encapsulate(ipPacket, espNextHeader(ipPacket))
}

// EncapsulatePadded is Encapsulate with RFC 4303 §2.7 traffic-flow-
// confidentiality padding, implementing dataplane.PaddingTunnel.
func (t *espTunnel) EncapsulatePadded(ipPacket []byte, minInner int) ([]byte, error) {
	return t.espSA.EncapsulatePadded(ipPacket, espNextHeader(ipPacket), minInner)
}

// espNextHeader picks the ESP next-header for an inner packet from its own
// version nibble — IPv4 (4) or IPv6 (41) — so one dual-stack Child SA carries
// both families.
func espNextHeader(ipPacket []byte) byte {
	if len(ipPacket) > 0 && ipPacket[0]>>4 == 6 {
		return 41
	}
	return 4
}

// Decapsulate opens an ESP packet back to the inner IP datagram, stripping any
// traffic-flow-confidentiality padding (RFC 4303 §2.7) the sender added.
//
// No ESP field delimits TFC padding — only the inner packet's own header does,
// which is exactly what lets a sender pad without the receiver having agreed to
// anything. So the trim happens here, where the next-header value is
// interpreted, rather than in the esp codec which only carries it.
func (t *espTunnel) Decapsulate(espPkt []byte) ([]byte, error) {
	inner, nextHeader, err := t.espSA.Decapsulate(espPkt)
	if err != nil {
		return nil, err
	}
	switch nextHeader {
	case 59: // NoNextHeader: a pure filler packet, with nothing inside at all.
		return nil, errDummyPacket
	case 4, 41: // Tunnel mode, either family.
		if inner = dataplane.TrimToIP(inner); inner == nil {
			return nil, errBadInner
		}
	}
	return inner, nil
}

// PumpDataPath connects the IKE layer's Child SA lifecycle to a dataplane.Pump.
// It implements ike.DataPath (AddChild/RemoveChild) and the espReceiver
// interface (HandleESP) the server uses for inbound ESP on port 4500.
//
// The pump is protocol-agnostic, so this is where ESP-specific knowledge stops:
// it demuxes with dataplane.SPIDemux and adapts Child SAs to dataplane.Tunnel.
type PumpDataPath struct {
	pump *dataplane.Pump

	mu   sync.Mutex
	byIn map[uint32]*espTunnel
}

// NewPumpDataPath wires Child SA events into pump.
func NewPumpDataPath(pump *dataplane.Pump) *PumpDataPath {
	return &PumpDataPath{
		pump: pump,
		byIn: make(map[uint32]*espTunnel),
	}
}

// AddChild builds an ESP data path for a newly established Child SA.
func (d *PumpDataPath) AddChild(sa *IKESA, child *ChildSA) {
	espSA, err := BuildESPSA(child)
	if err != nil {
		return
	}
	t := &espTunnel{
		espSA: espSA,
		inSPI: child.InboundSPI,
		// Server side: this tunnel carries exactly the address(es) the peer was
		// assigned, so its routes are that host's /32 and, for a dual-stack peer,
		// its /128.
		routes: append(hostRoute(child.ClientIP), hostRoute6(child.ClientIP6)...),
	}
	t.peer.Store(child.PeerAddr) // initial return address, refined per inbound ESP
	d.mu.Lock()
	d.byIn[child.InboundSPI] = t
	d.mu.Unlock()
	d.pump.AddTunnel(t)
}

// RemoveChild tears down the ESP data path for a Child SA.
func (d *PumpDataPath) RemoveChild(sa *IKESA, child *ChildSA) {
	d.mu.Lock()
	t := d.byIn[child.InboundSPI]
	delete(d.byIn, child.InboundSPI)
	d.mu.Unlock()
	if t != nil {
		d.pump.RemoveTunnel(t)
	}
}

// UpdatePeerAddr repoints every tunnel belonging to sa at addr, so ESP return
// traffic follows a MOBIKE UPDATE_SA_ADDRESSES at once instead of waiting for
// the first inbound ESP datagram from the new address. The caller holds sa.mu,
// which guards sa.Children; d.mu guards byIn — the same lock order AddChild
// takes (sa.mu already held, then d.mu).
func (d *PumpDataPath) UpdatePeerAddr(sa *IKESA, addr *net.UDPAddr) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for inSPI := range sa.Children {
		if t := d.byIn[inSPI]; t != nil {
			t.SetPeerAddr(addr)
		}
	}
}

// HandleESP forwards an inbound ESP datagram (with its UDP source address, so
// the return path can track the peer's real ESP socket) to the pump.
func (d *PumpDataPath) HandleESP(espPkt []byte, from *net.UDPAddr) {
	d.pump.HandleInbound(espPkt, from)
}

// HandleESPBatch forwards one read batch of ESP datagrams at once, letting the
// pump coalesce inbound TCP (GRO) with the batch as its window.
func (d *PumpDataPath) HandleESPBatch(espPkts [][]byte, froms []*net.UDPAddr) {
	d.pump.HandleInboundBatch(espPkts, froms)
}
