package l2tpv3

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SessionIDDemux extracts the L2TPv3 Session ID from offset 4 of a data packet
// (right after the 4-octet flags+version header).
func SessionIDDemux(pkt []byte) (uint32, bool) {
	if len(pkt) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[4:]), true
}

// Sender writes an encapsulated L2TPv3 datagram to a peer.
type Sender func(pkt []byte, to *net.UDPAddr)

// Pump moves Ethernet frames between a TAP device and an L2TPv3 tunnel. It
// does not use dataplane.Pump because that pump's innerDest reads the first
// nibble as an IP version, which is meaningless for Ethernet frames.
type Pump struct {
	tap   tapIO
	log   *log.Logger
	send  Sender
	demux func(pkt []byte) (uint32, bool)

	sessionID uint32
	peer      *net.UDPAddr
	cfg       *SessionConfig

	mu       sync.RWMutex
	sessions map[uint32]*SessionConfig // inbound demux keyed by session ID

	lastInbound atomic.Int64
	closing     bool
}

// tapIO is the minimal TAP device interface.
type tapIO interface {
	Read(buf []byte) (int, error)
	Write(pkt []byte) (int, error)
}

// NewPump creates a pump for a static L2TPv3 Ethernet pseudowire.
func NewPump(tap tapIO, send Sender, localSessionID uint32, cfg *SessionConfig, logger *log.Logger) *Pump {
	p := &Pump{
		tap:       tap,
		log:       logger,
		send:      send,
		demux:     SessionIDDemux,
		sessionID: localSessionID,
		peer:      cfg.PeerAddr,
		cfg:       cfg,
		sessions:  map[uint32]*SessionConfig{cfg.LocalSessionID: cfg},
	}
	return p
}

// Run starts the pump. It reads Ethernet frames from the TAP, encapsulates
// them, and sends them to the peer. It blocks until Close is called.
func (p *Pump) Run() {
	buf := make([]byte, 65535)
	for {
		n, err := p.tap.Read(buf)
		if err != nil {
			if p.closing {
				return
			}
			p.log.Printf("l2tpv3: TAP read error: %v", err)
			continue
		}
		frame := buf[:n]

		// Encapsulate and send.
		enc := EncodeData(nil, p.cfg.RemoteSessionID, p.cfg.RemoteCookie, p.cfg.Sublayer, frame)
		p.send(enc, p.peer)
	}
}

// HandleInbound decodes one L2TPv3 data packet and writes the inner Ethernet
// frame to the TAP.
func (p *Pump) HandleInbound(pkt []byte) {
	sid, ok := p.demux(pkt)
	if !ok {
		return
	}
	p.mu.RLock()
	cfg, ok := p.sessions[sid]
	p.mu.RUnlock()
	if !ok {
		return
	}

	hdr, err := DecodeData(pkt, len(cfg.LocalCookie), cfg.Sublayer)
	if err != nil {
		return
	}
	p.lastInbound.Store(time.Now().UnixNano())
	_, _ = p.tap.Write(hdr.Frame)
}

// HandleInboundBatch decodes a batch of L2TPv3 data packets and writes each
// inner Ethernet frame to the TAP.
func (p *Pump) HandleInboundBatch(pkts [][]byte) {
	for _, pkt := range pkts {
		p.HandleInbound(pkt)
	}
}

// AddSession registers a remote peer session for inbound demux.
func (p *Pump) AddSession(cfg *SessionConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessions[cfg.LocalSessionID] = cfg
}

// RemoveSession unregisters a session.
func (p *Pump) RemoveSession(sessionID uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sessions, sessionID)
}

// IdleFor returns how long it has been since the last authenticated inbound
// packet, or 0 if none has ever arrived.
func (p *Pump) IdleFor() time.Duration {
	if t := p.lastInbound.Load(); t > 0 {
		return time.Since(time.Unix(0, t))
	}
	return 0
}

// Close stops the pump.
func (p *Pump) Close() {
	p.closing = true
}
