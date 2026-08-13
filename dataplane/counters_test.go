package dataplane

import (
	"io"
	"log"
	"net"
	"net/netip"
	"testing"
)

// countingTunnel is a Tunnel that moves bytes without touching them, so a test
// can assert on what the pump counted rather than on what a cipher produced.
type countingTunnel struct {
	key    uint32
	routes []netip.Prefix
	fail   bool // Decapsulate/Encapsulate return an error
}

func (t *countingTunnel) InboundKey() uint32     { return t.key }
func (t *countingTunnel) Routes() []netip.Prefix { return t.routes }
func (t *countingTunnel) PeerAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4500}
}

func (t *countingTunnel) Encapsulate(p []byte) ([]byte, error) {
	if t.fail {
		return nil, io.ErrUnexpectedEOF
	}
	return append([]byte(nil), p...), nil
}

func (t *countingTunnel) Decapsulate(p []byte) ([]byte, error) {
	if t.fail {
		return nil, io.ErrUnexpectedEOF
	}
	// The demux reads the first four octets as the key; the rest is the inner
	// packet, which must be a real IP packet for the outbound path to route it.
	return append([]byte(nil), p[4:]...), nil
}

// ipv4Packet builds a minimal IPv4 header with the given src/dst and a payload
// padded out to total, so the pump's innerDest can route it.
func ipv4Packet(dst string, total int) []byte {
	if total < 20 {
		total = 20
	}
	p := make([]byte, total)
	p[0] = 0x45
	p[2], p[3] = byte(total>>8), byte(total)
	copy(p[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(p[16:20], net.ParseIP(dst).To4())
	return p
}

func newTestPump(t *testing.T) (*Pump, *fakeTUN) {
	t.Helper()
	tun := newFakeTUN()
	return NewPump(tun, func([]byte, *net.UDPAddr) {}, SPIDemux, log.New(io.Discard, "", 0)), tun
}

// The claim the whole item exists for: after traffic crosses, the pump can say
// how much, in both directions, per tunnel.
func TestPumpCountsBytesAndPacketsBothWays(t *testing.T) {
	p, _ := newTestPump(t)
	tun := &countingTunnel{key: 0x11223344, routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	p.AddTunnel(tun)

	// Inbound: four octets of key, then a 100-byte inner packet.
	inner := ipv4Packet("10.0.0.2", 100)
	pkt := append([]byte{0x11, 0x22, 0x33, 0x44}, inner...)
	p.HandleInbound(pkt, nil)
	p.HandleInbound(pkt, nil)

	// Outbound: a 60-byte packet for a destination this tunnel routes.
	p.routeOutbound(ipv4Packet("10.0.0.9", 60))

	st, ok := p.TunnelStats(tun)
	if !ok {
		t.Fatal("the pump has no counters for a tunnel it was given")
	}
	if st.RxPackets != 2 || st.RxBytes != 200 {
		t.Errorf("rx = %d packets / %d bytes, want 2 / 200", st.RxPackets, st.RxBytes)
	}
	if st.TxPackets != 1 || st.TxBytes != 60 {
		t.Errorf("tx = %d packets / %d bytes, want 1 / 60", st.TxPackets, st.TxBytes)
	}
	if st.LastSeen.IsZero() {
		t.Error("LastSeen is zero after two authenticated inbound packets")
	}
}

// Drops are counted by reason, because "1,412 packets dropped" tells an
// operator nothing they can act on. Each reason is provoked separately so a
// failure names the bucket that is wrong.
func TestDropsAreCountedByReason(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   DropReason
		action func(p *Pump, tun *countingTunnel)
	}{
		{"no key", DropNoKey, func(p *Pump, _ *countingTunnel) {
			p.HandleInbound([]byte{0x01, 0x02}, nil) // too short for a key
		}},
		{"unknown key", DropUnknownKey, func(p *Pump, _ *countingTunnel) {
			p.HandleInbound([]byte{0xde, 0xad, 0xbe, 0xef, 0x45}, nil)
		}},
		{"decap failed", DropDecapFailed, func(p *Pump, tun *countingTunnel) {
			tun.fail = true
			p.HandleInbound(append([]byte{0x11, 0x22, 0x33, 0x44}, ipv4Packet("10.0.0.2", 40)...), nil)
		}},
		{"not ip", DropNotIP, func(p *Pump, _ *countingTunnel) {
			p.routeOutbound([]byte{0x00, 0x01, 0x02})
		}},
		{"no route", DropNoRoute, func(p *Pump, _ *countingTunnel) {
			p.routeOutbound(ipv4Packet("192.0.2.55", 40)) // outside the tunnel's /8
		}},
		{"too big", DropTooBig, func(p *Pump, _ *countingTunnel) {
			// DF set: without it the stack is willing to fragment, so the
			// packet is not "too big" and no ICMP is owed.
			p.SetInnerMTU(100)
			pkt := ipv4Packet("10.0.0.9", 500)
			pkt[6] |= 0x40
			p.routeOutbound(pkt)
		}},
		{"encap failed", DropEncapFailed, func(p *Pump, tun *countingTunnel) {
			tun.fail = true
			p.routeOutbound(ipv4Packet("10.0.0.9", 40))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newTestPump(t)
			tun := &countingTunnel{key: 0x11223344, routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
			p.AddTunnel(tun)
			tc.action(p, tun)

			drops := p.Stats().Drops
			if drops[tc.want.String()] == 0 {
				t.Errorf("no %s drop recorded; drops = %v", tc.want, drops)
			}
			for r := DropReason(0); r < numDropReasons; r++ {
				if r != tc.want && drops[r.String()] != 0 {
					t.Errorf("%d packets landed in %s as well as %s", drops[r.String()], r, tc.want)
				}
			}
		})
	}
}

// A peer that disconnected still carried what it carried. A total that goes
// down when a tunnel is removed is one no operator -- and no time-series
// database, which reads a decrease as a counter reset -- can reason about.
func TestPumpTotalSurvivesTunnelRemoval(t *testing.T) {
	p, _ := newTestPump(t)
	tun := &countingTunnel{key: 0x11223344, routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	p.AddTunnel(tun)
	p.HandleInbound(append([]byte{0x11, 0x22, 0x33, 0x44}, ipv4Packet("10.0.0.2", 100)...), nil)

	before := p.Stats()
	if before.Total.RxBytes != 100 || before.Tunnels != 1 {
		t.Fatalf("before removal: %+v", before)
	}

	p.RemoveTunnel(tun)
	after := p.Stats()
	if after.Total.RxBytes != 100 {
		t.Errorf("total rx = %d after removing the tunnel, want 100 held", after.Total.RxBytes)
	}
	if after.Tunnels != 0 {
		t.Errorf("tunnels = %d after removal, want 0", after.Tunnels)
	}
	if _, ok := p.TunnelStats(tun); ok {
		t.Error("a removed tunnel still has per-tunnel counters")
	}
}

// A rekey re-registers the same Tunnel under a new inbound key. Its counts must
// carry over, or a peer's byte total resets every two minutes and the number an
// operator is watching means nothing.
func TestRekeyKeepsATunnelsCounts(t *testing.T) {
	p, _ := newTestPump(t)
	tun := &countingTunnel{key: 0x11223344, routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	p.AddTunnel(tun)
	p.HandleInbound(append([]byte{0x11, 0x22, 0x33, 0x44}, ipv4Packet("10.0.0.2", 100)...), nil)

	p.AddInboundKey(0x55667788, tun)
	p.HandleInbound(append([]byte{0x55, 0x66, 0x77, 0x88}, ipv4Packet("10.0.0.2", 40)...), nil)

	st, _ := p.TunnelStats(tun)
	if st.RxPackets != 2 || st.RxBytes != 140 {
		t.Errorf("after rekey rx = %d / %d, want 2 / 140 — the counters reset", st.RxPackets, st.RxBytes)
	}
}

// A keepalive is an authenticated packet with no inner payload. It is proof of
// life, so it must move LastSeen -- and it carried no user traffic, so it must
// not move the byte count.
func TestAKeepaliveMovesLastSeenButNotBytes(t *testing.T) {
	p, _ := newTestPump(t)
	tun := &countingTunnel{key: 0x11223344, routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	p.AddTunnel(tun)

	p.HandleInbound([]byte{0x11, 0x22, 0x33, 0x44}, nil) // key only: zero-length inner

	st, _ := p.TunnelStats(tun)
	if st.LastSeen.IsZero() {
		t.Error("a keepalive did not move LastSeen; a live idle peer reads as never seen")
	}
	if st.RxBytes != 0 {
		t.Errorf("a keepalive counted %d bytes of user traffic", st.RxBytes)
	}
	if st.RxPackets != 1 {
		t.Errorf("rx packets = %d, want the keepalive counted as one packet", st.RxPackets)
	}
}

// Every reason has a distinct, stable label. A duplicate would silently merge
// two buckets, and an empty one would produce an unparseable exposition.
func TestEveryDropReasonHasItsOwnLabel(t *testing.T) {
	seen := map[string]DropReason{}
	for r := DropReason(0); r < numDropReasons; r++ {
		s := r.String()
		if s == "" || s == "unknown" {
			t.Errorf("DropReason(%d) has no label", int(r))
		}
		if prev, dup := seen[s]; dup {
			t.Errorf("DropReason(%d) and DropReason(%d) share the label %q", int(prev), int(r), s)
		}
		seen[s] = r
	}
}
