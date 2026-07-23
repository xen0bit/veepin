package ike

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
)

// hostRoute expresses one assigned address as a single-host route. It returns
// nil for an address that is not IPv4, which leaves the tunnel unrouted rather
// than routing it wrongly.
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

// defaultRoute is every IPv4 destination: what a client's single tunnel to its
// server carries.
func defaultRoute() []netip.Prefix {
	return []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
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

// Encapsulate protects an inner IPv4 packet as ESP (tunnel mode: the inner
// packet is a whole IP datagram, next-header = IPv4 = 4).
func (t *espTunnel) Encapsulate(ipPacket []byte) ([]byte, error) {
	return t.espSA.Encapsulate(ipPacket, 4)
}

// Decapsulate opens an ESP packet back to the inner IPv4 datagram.
func (t *espTunnel) Decapsulate(espPkt []byte) ([]byte, error) {
	inner, _, err := t.espSA.Decapsulate(espPkt)
	return inner, err
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
		// Server side: this tunnel carries exactly the one address the peer was
		// assigned, so its route is that host's /32.
		routes: hostRoute(child.ClientIP),
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
