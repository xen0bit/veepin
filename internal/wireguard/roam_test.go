package wireguard

import (
	"net"
	"net/netip"
	"testing"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// discardTUN accepts the pump's writes and never yields a read.
type discardTUN struct{}

func (discardTUN) Read([]byte) (int, error)    { select {} }
func (discardTUN) Write(p []byte) (int, error) { return len(p), nil }

func samePeer(got, want *net.UDPAddr) bool {
	return got != nil && got.Port == want.Port && got.IP.Equal(want.IP)
}

// TestAServerPeerRoamsOnlyOnAnAuthenticatedPacket runs a real wgTunnel through
// the server's pump. The receiver index a transport packet is demuxed on sits in
// cleartext at offset 4, so anyone on the path can address a datagram to this
// peer. If this fails, one such datagram -- forged, or a genuine one replayed
// from elsewhere -- repoints every reply for the peer at whoever sent it, which
// WireGuard's paper rules out by updating the endpoint from authenticated
// packets only (§2.1).
func TestAServerPeerRoamsOnlyOnAnAuthenticatedPacket(t *testing.T) {
	us, peer := sessionPair(t, 9, 100, 200)
	home := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 51820}
	away := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 44), Port: 61000}
	forger := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 66), Port: 51820}

	tunnel := newTunnel(us, []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}, home, true)
	pump := dataplane.NewPump(discardTUN{}, func([]byte, *net.UDPAddr) {}, wire.Demux, nil)
	pump.AddTunnel(tunnel)

	genuine, err := peer.Seal(ipv4Packet("10.0.0.2", "10.0.0.1", 64))
	if err != nil {
		t.Fatal(err)
	}
	// Copies taken before the pump sees anything: it opens in place.
	forged := append([]byte(nil), genuine...)
	forged[len(forged)-1] ^= 1
	replayed := append([]byte(nil), genuine...)

	pump.HandleInbound(forged, forger)
	if !samePeer(tunnel.PeerAddr(), home) {
		t.Fatalf("a packet that failed authentication moved the peer to %v", tunnel.PeerAddr())
	}

	pump.HandleInbound(genuine, away)
	if !samePeer(tunnel.PeerAddr(), away) {
		t.Fatalf("an authenticated packet from %v left the peer at %v: roaming itself is broken", away, tunnel.PeerAddr())
	}

	pump.HandleInbound(replayed, forger)
	if !samePeer(tunnel.PeerAddr(), away) {
		t.Fatalf("a genuine packet replayed from %v moved the peer there", forger)
	}
}
