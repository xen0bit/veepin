package dataplane

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

// The roaming tests share one fake: a tunnel whose datagrams are a 4-octet SPI,
// one "tag" octet, and the inner packet. The tag stands in for a real AEAD tag:
// authTag opens, anything else fails exactly the way a forged datagram fails a
// real Decapsulate. What the forger controls is everything a real forger
// controls -- the SPI, which is cleartext on the wire, and the source address.

const authTag = 0xa5

var errForged = errors.New("roam test: datagram did not authenticate")

type roamTunnel struct {
	key  uint32
	peer atomic.Pointer[net.UDPAddr]
}

func newRoamTunnel(key uint32, peer *net.UDPAddr) *roamTunnel {
	t := &roamTunnel{key: key}
	t.peer.Store(peer)
	return t
}

func (t *roamTunnel) InboundKey() uint32 { return t.key }
func (t *roamTunnel) Routes() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}
}
func (t *roamTunnel) PeerAddr() *net.UDPAddr               { return t.peer.Load() }
func (t *roamTunnel) SetPeerAddr(a *net.UDPAddr)           { t.peer.Store(a) }
func (t *roamTunnel) Encapsulate(p []byte) ([]byte, error) { return p, nil }
func (t *roamTunnel) Decapsulate(p []byte) ([]byte, error) {
	if len(p) < 5 || p[4] != authTag {
		return nil, errForged
	}
	return p[5:], nil
}

// roamMultiTunnel is the same shape behind MultiTunnel, whose inbound path is a
// separate branch of the pump and so a separate place to get the order wrong.
type roamMultiTunnel struct{ roamTunnel }

func (t *roamMultiTunnel) DecapsulateMulti(p []byte, out [][]byte) ([][]byte, error) {
	inner, err := t.Decapsulate(p)
	if err != nil {
		return out, err
	}
	return append(out, inner), nil
}

// roamDatagram builds a datagram for key carrying a minimal IPv4 packet, with
// tag as its authentication octet.
func roamDatagram(key uint32, tag byte) []byte {
	inner := makeIPv4(net.IPv4(10, 0, 0, 1), []byte("x"))
	pkt := []byte{byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key), tag}
	return append(pkt, inner...)
}

var (
	roamHome   = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 4500}
	roamForger = &net.UDPAddr{IP: net.IPv4(203, 0, 113, 66), Port: 4500}
	roamAway   = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 44), Port: 61000}
)

func samePeer(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

// TestAForgedDatagramDoesNotMoveThePeer: if this fails, anyone who can see a
// client's traffic can redirect the server's replies to that client with one
// datagram carrying the tunnel's cleartext demux key, and keep them redirected
// for as long as they keep sending.
func TestAForgedDatagramDoesNotMoveThePeer(t *testing.T) {
	cases := []struct {
		name   string
		tunnel interface {
			Tunnel
			SetPeerAddr(*net.UDPAddr)
		}
	}{
		{"single-packet tunnel", newRoamTunnel(7, roamHome)},
		{"aggregating tunnel", &roamMultiTunnel{*newRoamTunnel(7, roamHome)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pump := NewPump(newFakeTUN(), func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
			pump.AddTunnel(tc.tunnel)

			pump.HandleInbound(roamDatagram(7, 0x00), roamForger)
			if got := tc.tunnel.PeerAddr(); !samePeer(got, roamHome) {
				t.Fatalf("a datagram that failed to authenticate moved the peer to %v", got)
			}
			if d := pump.Stats().Drops[DropDecapFailed.String()]; d != 1 {
				t.Fatalf("DropDecapFailed = %d, want 1: the forged datagram was not even rejected", d)
			}
		})
	}
}

// TestAnAuthenticatedDatagramStillMovesThePeer is the other half: the fix must
// not cost roaming itself. A client whose NAT rebinds keeps working only because
// the first authenticated datagram from its new address repoints the replies.
func TestAnAuthenticatedDatagramStillMovesThePeer(t *testing.T) {
	cases := []struct {
		name   string
		tunnel interface {
			Tunnel
			SetPeerAddr(*net.UDPAddr)
		}
	}{
		{"single-packet tunnel", newRoamTunnel(7, roamHome)},
		{"aggregating tunnel", &roamMultiTunnel{*newRoamTunnel(7, roamHome)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tun := newFakeTUN()
			pump := NewPump(tun, func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
			pump.AddTunnel(tc.tunnel)

			pump.HandleInbound(roamDatagram(7, authTag), roamAway)
			if got := tc.tunnel.PeerAddr(); !samePeer(got, roamAway) {
				t.Fatalf("an authenticated datagram from %v left the peer at %v", roamAway, got)
			}
			<-tun.writeSig // and it was delivered, not merely used to roam
		})
	}
}

// TestAForgedDatagramInABatchMovesNothing drives the batch entry point that
// every single-socket server reads through, with the forgery interleaved
// between genuine datagrams the way a flood would arrive. Each datagram must be
// judged on its own: the genuine ones roam, the forged one does not, and the
// peer ends where the last authenticated datagram came from.
func TestAForgedDatagramInABatchMovesNothing(t *testing.T) {
	tun := newFakeTUN()
	tunnel := newRoamTunnel(7, roamHome)
	pump := NewPump(tun, func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
	pump.AddTunnel(tunnel)

	pump.HandleInboundBatch(
		[][]byte{roamDatagram(7, authTag), roamDatagram(7, 0x00)},
		[]*net.UDPAddr{roamAway, roamForger},
	)
	if got := tunnel.PeerAddr(); !samePeer(got, roamAway) {
		t.Fatalf("after a genuine datagram from %v and a forged one from %v, the peer is %v",
			roamAway, roamForger, got)
	}
}
