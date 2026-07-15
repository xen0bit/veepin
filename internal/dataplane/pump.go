package dataplane

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
)

// ESPTunnel is the data-path view of one established Child SA. The ike package
// supplies an implementation that performs ESP encapsulation/decapsulation with
// the negotiated keys, and reports the peer transport address to send to.
type ESPTunnel interface {
	// InboundSPI is our SPI: inbound ESP packets carrying it belong here.
	InboundSPI() uint32
	// ClientIP is the internal tunnel address assigned to the peer; outbound
	// TUN packets destined to it are routed through this tunnel.
	ClientIP() net.IP
	// PeerAddr is where encapsulated ESP is sent (the peer's UDP address, which
	// may have floated to :4500 after NAT-T).
	PeerAddr() *net.UDPAddr
	// UDPEncap reports whether ESP must be wrapped in UDP (NAT-T, port 4500).
	UDPEncap() bool

	// Encapsulate turns an inner IP packet into an ESP payload (SPI|Seq|...).
	Encapsulate(ipPacket []byte) ([]byte, error)
	// Decapsulate turns an ESP payload back into the inner IP packet.
	Decapsulate(esp []byte) ([]byte, error)
}

// ESPSender writes an encapsulated ESP datagram to a peer. On NAT-T the caller
// wraps with the non-ESP/ESP marker as required; here we pass the ESP bytes and
// the target address, and whether UDP encap (port 4500) is in effect.
type ESPSender func(espBytes []byte, to *net.UDPAddr, udpEncap bool)

// tunIO is the minimal TUN device interface the pump needs; *TUN satisfies it.
// It exists so the pump can be tested with an in-memory device.
type tunIO interface {
	Read(buf []byte) (int, error)
	Write(pkt []byte) (int, error)
}

// Pump moves packets between a TUN device and a set of ESP tunnels.
type Pump struct {
	tun  tunIO
	log  *log.Logger
	send ESPSender

	mu       sync.RWMutex
	bySPI    map[uint32]ESPTunnel // inbound demux
	byIP     map[uint32]ESPTunnel // outbound routing by client IP (server mode)
	defRoute ESPTunnel            // outbound default tunnel (client mode)

	closing bool
}

// NewPump creates a data-path pump over tun. send is used to transmit
// encapsulated ESP to peers.
func NewPump(tun tunIO, send ESPSender, logger *log.Logger) *Pump {
	return &Pump{
		tun:   tun,
		log:   logger,
		send:  send,
		bySPI: make(map[uint32]ESPTunnel),
		byIP:  make(map[uint32]ESPTunnel),
	}
}

// AddTunnel registers an established Child SA data path.
func (p *Pump) AddTunnel(t ESPTunnel) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bySPI[t.InboundSPI()] = t
	if ip := t.ClientIP().To4(); ip != nil {
		p.byIP[binary.BigEndian.Uint32(ip)] = t
	}
}

// SetDefaultRoute makes t the outbound tunnel for all TUN traffic regardless of
// destination address. This is used in client mode, where every packet leaving
// the local TUN must be sent to the single VPN server SA. In server mode this
// is left unset and outbound packets are routed per destination via AddTunnel.
func (p *Pump) SetDefaultRoute(t ESPTunnel) {
	p.mu.Lock()
	p.defRoute = t
	p.mu.Unlock()
}
func (p *Pump) RemoveTunnel(t ESPTunnel) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.bySPI, t.InboundSPI())
	if ip := t.ClientIP().To4(); ip != nil {
		delete(p.byIP, binary.BigEndian.Uint32(ip))
	}
}

// HandleESP processes an inbound ESP datagram (already stripped of any UDP-encap
// marker). It demuxes by SPI, decapsulates, and writes the inner IP packet to
// the TUN device. from, when non-nil, is the datagram's UDP source: the tunnel's
// return address is updated to it so replies reach the peer's actual ESP socket
// (a road-warrior client sends ESP from a different port than IKE, so the IKE
// peer address is not a valid ESP return address). Pass nil on a connected
// socket where the source is implicit (client mode).
func (p *Pump) HandleESP(esp []byte, from *net.UDPAddr) {
	if len(esp) < 4 {
		return
	}
	spi := binary.BigEndian.Uint32(esp[:4])
	p.mu.RLock()
	t := p.bySPI[spi]
	p.mu.RUnlock()
	if t == nil {
		return // unknown SPI
	}
	if from != nil {
		if u, ok := t.(interface{ SetPeerAddr(*net.UDPAddr) }); ok {
			u.SetPeerAddr(from)
		}
	}
	inner, err := t.Decapsulate(esp)
	if err != nil {
		if p.log != nil {
			p.log.Printf("dataplane: decap SPI %#x failed: %v", spi, err)
		}
		return
	}
	if _, err := p.tun.Write(inner); err != nil {
		if p.log != nil {
			p.log.Printf("dataplane: TUN write failed: %v", err)
		}
	}
}

// Run reads packets from the TUN device, routes each to the tunnel whose client
// owns the destination address, encapsulates, and sends. It blocks until the
// TUN device is closed.
func (p *Pump) Run() {
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

// routeOutbound routes one inner IP packet from the TUN to the tunnel that owns
// its destination address, encapsulates it, and sends it. Non-IPv4 packets and
// packets with no matching tunnel are dropped.
func (p *Pump) routeOutbound(pkt []byte) {
	dst, ok := ipv4Dest(pkt)
	if !ok {
		return // not IPv4; this build tunnels IPv4 only
	}
	p.mu.RLock()
	t := p.defRoute // client mode: single default tunnel
	if t == nil {
		t = p.byIP[dst] // server mode: route by destination
	}
	p.mu.RUnlock()
	if t == nil {
		return // no tunnel for this destination
	}
	// Encapsulate copies the inner packet into its own plaintext buffer, so
	// passing the read buffer slice directly is safe and avoids a copy.
	esp, err := t.Encapsulate(pkt)
	if err != nil {
		if p.log != nil {
			p.log.Printf("dataplane: encap failed: %v", err)
		}
		return
	}
	p.send(esp, t.PeerAddr(), t.UDPEncap())
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
