package ike

import (
	"net"
	"testing"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
)

// discardTUN accepts the pump's writes and never yields a read.
type discardTUN struct{}

func (discardTUN) Read([]byte) (int, error)    { select {} }
func (discardTUN) Write(p []byte) (int, error) { return len(p), nil }

func samePeer(got, want *net.UDPAddr) bool {
	return got != nil && got.Port == want.Port && got.IP.Equal(want.IP)
}

// TestAnESPPeerRoamsOnlyOnAnAuthenticatedPacket runs the server's real espTunnel
// through a pump, the way HandleESP feeds it. The SPI is the first four octets
// of every ESP packet, in cleartext. If this fails, a forged datagram carrying a
// client's SPI -- or a genuine one replayed from another address -- repoints the
// server's ESP for that client at the sender, which RFC 7296 §2.23 forbids:
// the address is to be updated only from a packet that has authenticated.
func TestAnESPPeerRoamsOnlyOnAnAuthenticatedPacket(t *testing.T) {
	kOut, kIn := gcmESPTransform(t, 0x11), gcmESPTransform(t, 0x22)
	server := &esp.SA{SPIOut: 0xaaaa, SPIIn: 0xbbbb, Out: kOut, In: kIn}
	client := &esp.SA{SPIOut: 0xbbbb, SPIIn: 0xaaaa, Out: kIn, In: kOut}

	home := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 4500}
	away := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 44), Port: 61000}
	forger := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 66), Port: 4500}

	tunnel := &espTunnel{espSA: server, inSPI: 0xbbbb}
	tunnel.peer.Store(home)
	pump := dataplane.NewPump(discardTUN{}, func([]byte, *net.UDPAddr) {}, dataplane.SPIDemux, nil)
	pump.AddTunnel(tunnel)

	genuine, err := client.Encapsulate(espIP(t, 4, 64), 4)
	if err != nil {
		t.Fatal(err)
	}
	forged := append([]byte(nil), genuine...)
	forged[len(forged)-1] ^= 1
	replayed := append([]byte(nil), genuine...)

	pump.HandleInbound(forged, forger)
	if !samePeer(tunnel.PeerAddr(), home) {
		t.Fatalf("an ESP packet that failed its ICV moved the peer to %v", tunnel.PeerAddr())
	}

	pump.HandleInbound(genuine, away)
	if !samePeer(tunnel.PeerAddr(), away) {
		t.Fatalf("an authenticated ESP packet from %v left the peer at %v: NAT rebinding is broken", away, tunnel.PeerAddr())
	}

	pump.HandleInbound(replayed, forger)
	if !samePeer(tunnel.PeerAddr(), away) {
		t.Fatalf("a genuine ESP packet replayed from %v moved the peer there", forger)
	}
}
