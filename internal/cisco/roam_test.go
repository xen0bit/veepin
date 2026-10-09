package cisco

import (
	"net"
	"testing"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev1"
)

// discardTUN accepts the pump's writes and never yields a read.
type discardTUN struct{}

func (discardTUN) Read([]byte) (int, error)    { select {} }
func (discardTUN) Write(p []byte) (int, error) { return len(p), nil }

func samePeer(got, want *net.UDPAddr) bool {
	return got != nil && got.Port == want.Port && got.IP.Equal(want.IP)
}

// TestTheGatewayRoamsOnlyOnAnAuthenticatedPacket runs the gateway's Tunnel
// through a pump with the AES-CBC/HMAC-SHA2 suite Quick Mode settles on, the
// non-AEAD path. The SPI that selects the tunnel is cleartext, so if this fails
// a forged or replayed datagram carrying it redirects the client's ESP to
// whoever sent it.
func TestTheGatewayRoamsOnlyOnAnAuthenticatedPacket(t *testing.T) {
	gw := benchTunnel()
	// The client's half of benchTunnel's SA: the SPIs crossed, and the same
	// (zero) keys, which benchTunnel uses in both directions.
	client := newESPSA(ikev1.Result{
		EncrID: 12, EncrKeyLn: 256, IntegID: 12,
		OutSPI: 0x22222222, InSPI: 0x11111111,
		OutEncKey: make([]byte, 32), OutIntegKey: make([]byte, 32),
		InEncKey: make([]byte, 32), InIntegKey: make([]byte, 32),
	})

	home := gw.PeerAddr()
	away := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 44), Port: 61000}
	forger := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 66), Port: 4500}

	pump := dataplane.NewPump(discardTUN{}, func([]byte, *net.UDPAddr) {}, dataplane.SPIDemux, nil)
	pump.AddTunnel(gw)

	genuine, err := client.Encapsulate(ciscoPayload(64), 4)
	if err != nil {
		t.Fatal(err)
	}
	forged := append([]byte(nil), genuine...)
	forged[len(forged)-1] ^= 1
	replayed := append([]byte(nil), genuine...)

	pump.HandleInbound(forged, forger)
	if !samePeer(gw.PeerAddr(), home) {
		t.Fatalf("an ESP packet that failed its ICV moved the peer to %v", gw.PeerAddr())
	}
	pump.HandleInbound(genuine, away)
	if !samePeer(gw.PeerAddr(), away) {
		t.Fatalf("an authenticated ESP packet from %v left the peer at %v", away, gw.PeerAddr())
	}
	pump.HandleInbound(replayed, forger)
	if !samePeer(gw.PeerAddr(), away) {
		t.Fatalf("a genuine ESP packet replayed from %v moved the peer there", forger)
	}
}
