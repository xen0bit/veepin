package ike

import (
	"net"
	"sync"

	"github.com/example/ikev2-go/internal/dataplane"
	"github.com/example/ikev2-go/internal/esp"
)

// espTunnel adapts an established Child SA to the dataplane.ESPTunnel interface,
// wrapping an esp.SA plus the routing metadata the pump needs.
type espTunnel struct {
	espSA    *esp.SA
	inSPI    uint32
	clientIP net.IP
	peer     *net.UDPAddr
	udpEncap bool
}

func (t *espTunnel) InboundSPI() uint32     { return t.inSPI }
func (t *espTunnel) ClientIP() net.IP       { return t.clientIP }
func (t *espTunnel) PeerAddr() *net.UDPAddr { return t.peer }
func (t *espTunnel) UDPEncap() bool         { return t.udpEncap }

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
		peer:     child.PeerAddr,
		udpEncap: child.UDPEncap,
	}
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

// HandleESP forwards an inbound ESP datagram to the pump for demux + TUN write.
func (d *PumpDataPath) HandleESP(espPkt []byte) {
	d.pump.HandleESP(espPkt)
}
