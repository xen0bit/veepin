package dataplane

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// idleTunnel is a minimal Tunnel: it "decapsulates" to a fixed inner packet, or
// to an empty payload when keepalive is set (modelling a keepalive datagram
// that authenticates but carries nothing for the TUN).
type idleTunnel struct{ keepalive bool }

func (t idleTunnel) InboundKey() uint32 { return 1 }
func (t idleTunnel) Routes() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
}
func (t idleTunnel) PeerAddr() *net.UDPAddr               { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (t idleTunnel) Encapsulate(p []byte) ([]byte, error) { return p, nil }
func (t idleTunnel) Decapsulate([]byte) ([]byte, error) {
	if t.keepalive {
		return nil, nil
	}
	return []byte("inner"), nil
}

// idleDemux maps any non-empty packet to key 1 so idleTunnel receives it.
func idleDemux(pkt []byte) (uint32, bool) { return 1, len(pkt) > 0 }

// TestPumpIdleForSeeded confirms a freshly built pump does not read as idle for
// long before any packet arrives — it is seeded to construction time.
func TestPumpIdleForSeeded(t *testing.T) {
	p := NewPump(&recordingTUN{}, func([]byte, *net.UDPAddr) {}, idleDemux, nil)
	if idle := p.IdleFor(); idle > time.Second {
		t.Fatalf("a new pump reports idle %v; want ~0 (seeded at construction)", idle)
	}
}

// TestPumpIdleForTracksInbound confirms an authenticated inbound packet resets
// the idle clock, so decapInbound's liveness stamp works.
func TestPumpIdleForTracksInbound(t *testing.T) {
	p := NewPump(&recordingTUN{}, func([]byte, *net.UDPAddr) {}, idleDemux, nil)
	p.AddTunnel(idleTunnel{})

	p.lastInbound.Store(time.Now().Add(-time.Hour).UnixNano())
	if idle := p.IdleFor(); idle < 30*time.Minute {
		t.Fatalf("backdated idle = %v; setup wrong", idle)
	}
	p.HandleInbound([]byte("data"), nil)
	if idle := p.IdleFor(); idle > time.Second {
		t.Fatalf("IdleFor after inbound = %v; want ~0", idle)
	}
}

// TestPumpIdleForCountsKeepalive confirms an authenticated *empty* packet (a
// keepalive, which is not written to the TUN) still counts as proof of life.
func TestPumpIdleForCountsKeepalive(t *testing.T) {
	p := NewPump(&recordingTUN{}, func([]byte, *net.UDPAddr) {}, idleDemux, nil)
	p.AddTunnel(idleTunnel{keepalive: true})

	p.lastInbound.Store(time.Now().Add(-time.Hour).UnixNano())
	p.HandleInbound([]byte("ka"), nil)
	if idle := p.IdleFor(); idle > time.Second {
		t.Fatalf("a keepalive did not refresh the liveness clock: idle = %v", idle)
	}
}
