package ike

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/xen0bit/ikennkt/internal/dataplane"
	"github.com/xen0bit/ikennkt/internal/esp"
)

// espTunnel adapts an established Child SA to the dataplane.ESPTunnel interface,
// wrapping an esp.SA plus the routing metadata the pump needs.
//
// peer is atomic: it is read on the pump's outbound goroutine (PeerAddr) and
// updated on the server's inbound-ESP goroutine (SetPeerAddr) as ESP arrives, so
// return traffic tracks the peer's real ESP source address rather than the IKE
// address it authenticated from.
type espTunnel struct {
	espSA    *esp.SA
	inSPI    uint32
	clientIP net.IP
	peer     atomic.Pointer[net.UDPAddr]
	udpEncap bool
}

func (t *espTunnel) InboundSPI() uint32     { return t.inSPI }
func (t *espTunnel) ClientIP() net.IP       { return t.clientIP }
func (t *espTunnel) PeerAddr() *net.UDPAddr { return t.peer.Load() }
func (t *espTunnel) UDPEncap() bool         { return t.udpEncap }

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
		espSA:    espSA,
		inSPI:    child.InboundSPI,
		clientIP: child.ClientIP,
		udpEncap: child.UDPEncap,
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

// HandleESP forwards an inbound ESP datagram (with its UDP source address, so
// the return path can track the peer's real ESP socket) to the pump.
func (d *PumpDataPath) HandleESP(espPkt []byte, from *net.UDPAddr) {
	d.pump.HandleESP(espPkt, from)
}
