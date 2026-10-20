package dataplane

import (
	"net"
	"net/netip"
	"testing"
)

// checkedTunnel is a countingTunnel that asks for its inbound sources to be
// checked, the way a server-side tunnel does.
type checkedTunnel struct{ countingTunnel }

func (t *checkedTunnel) VerifyInboundSource() bool { return true }

func ipv4From(src, dst string) []byte {
	p := ipv4Packet(dst, 40)
	copy(p[12:16], net.ParseIP(src).To4())
	return p
}

// TestPumpDropsASpoofedSourceFromACheckedTunnel: a client that authenticates
// under its own keys must not be able to put a packet on the shared TUN as
// another client's address. If this fails, one client can send as another.
func TestPumpDropsASpoofedSourceFromACheckedTunnel(t *testing.T) {
	p, tun := newTestPump(t)
	tn := &checkedTunnel{countingTunnel{key: 0x01020304, routes: []netip.Prefix{netip.MustParsePrefix("10.9.0.5/32")}}}
	p.AddTunnel(tn)
	key := []byte{0x01, 0x02, 0x03, 0x04}

	p.HandleInbound(append(key, ipv4From("10.9.0.7", "10.0.0.1")...), nil)
	if n := len(tun.written); n != 0 {
		t.Fatalf("a packet sourced from another client's address reached the TUN (%d writes)", n)
	}
	if got := p.Stats().Drops[DropSpoofedSource.String()]; got != 1 {
		t.Fatalf("spoofed_source drops = %d, want 1", got)
	}

	p.HandleInbound(append(key, ipv4From("10.9.0.5", "10.0.0.1")...), nil)
	if n := len(tun.written); n != 1 {
		t.Fatalf("the tunnel's own address was not delivered (%d writes)", n)
	}
}

// TestPumpLeavesAnUncheckedTunnelAlone: a client tunnel routes 0.0.0.0/0 and
// receives from the whole internet, so the check must stay opt-in.
func TestPumpLeavesAnUncheckedTunnelAlone(t *testing.T) {
	p, tun := newTestPump(t)
	tn := &countingTunnel{key: 0x01020304, routes: []netip.Prefix{netip.MustParsePrefix("10.9.0.5/32")}}
	p.AddTunnel(tn)
	p.HandleInbound(append([]byte{0x01, 0x02, 0x03, 0x04}, ipv4From("198.51.100.9", "10.0.0.1")...), nil)
	if n := len(tun.written); n != 1 {
		t.Fatalf("an unchecked tunnel's packet was dropped (%d writes)", n)
	}
}

// TestSourceWithinRefusesWhatIsNotIP: a payload with no IP source has no
// address to vouch for.
func TestSourceWithinRefusesWhatIsNotIP(t *testing.T) {
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	for _, pkt := range [][]byte{nil, {0x45}, {0x00, 0x01, 0x02}, make([]byte, 39)} {
		if SourceWithin(pkt, all) {
			t.Fatalf("SourceWithin accepted %x", pkt)
		}
	}
}

func TestSourceIsComparesUnmappedAddresses(t *testing.T) {
	pkt := ipv4From("10.9.0.5", "10.0.0.1")
	if !SourceIs(pkt, netip.MustParseAddr("::ffff:10.9.0.5")) {
		t.Fatal("a v4-mapped address did not match its IPv4 packet")
	}
	if SourceIs(pkt, netip.Addr{}) {
		t.Fatal("the zero address matched")
	}
}
