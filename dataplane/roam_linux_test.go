//go:build linux

package dataplane

import (
	"net"
	"testing"
)

// TestTheGROPathDoesNotRoamOnAForgery covers the third inbound path. The vnet
// batch path decapsulates through its own loop rather than through
// HandleInbound, and every veepin client and server that negotiates GSO reads
// through it -- so a fix that reached only HandleInbound would leave the
// deployed path exactly as it was, with the plain-TUN tests above all passing.
func TestTheGROPathDoesNotRoamOnAForgery(t *testing.T) {
	for _, multi := range []bool{false, true} {
		name := "single-packet tunnel"
		var tunnel interface {
			Tunnel
			SetPeerAddr(*net.UDPAddr)
		} = newRoamTunnel(7, roamHome)
		if multi {
			name = "aggregating tunnel"
			tunnel = &roamMultiTunnel{*newRoamTunnel(7, roamHome)}
		}
		t.Run(name, func(t *testing.T) {
			pump := NewPump(newFakeGSOTUN(), func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
			pump.AddTunnel(tunnel)

			pump.HandleInboundBatch([][]byte{roamDatagram(7, 0x00)}, []*net.UDPAddr{roamForger})
			if got := tunnel.PeerAddr(); !samePeer(got, roamHome) {
				t.Fatalf("a forged datagram on the GRO path moved the peer to %v", got)
			}

			pump.HandleInboundBatch([][]byte{roamDatagram(7, authTag)}, []*net.UDPAddr{roamAway})
			if got := tunnel.PeerAddr(); !samePeer(got, roamAway) {
				t.Fatalf("an authenticated datagram on the GRO path left the peer at %v", got)
			}
		})
	}
}
