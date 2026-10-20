package l2tp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ppp"
)

// recordingHandler counts the data frames a Tunnel hands up.
type recordingHandler struct{ frames int }

func (r *recordingHandler) SessionUp()         {}
func (r *recordingHandler) DataFrame(_ []byte) { r.frames++ }
func (r *recordingHandler) Closed(_ error)     {}
func (r *recordingHandler) reset() (n int)     { n, r.frames = r.frames, 0; return n }
func nopSend([]byte) error                     { return nil }
func dataFor(t *Tunnel, frame []byte) []byte {
	return marshalData(t.localTunnelID, t.localSessionID, frame)
}
func dataWith(tid, sid uint16, f []byte) []byte { return marshalData(tid, sid, f) }

// TestTunnelCarriesNoDataBeforeTheSessionIsUp: a data message that arrives
// before ICCN belongs to no call. If this fails, data reaches PPP before the
// control channel has set a session up.
func TestTunnelCarriesNoDataBeforeTheSessionIsUp(t *testing.T) {
	h := &recordingHandler{}
	tn := NewTunnel(RoleLNS, nopSend, h)
	tn.HandleInbound(dataFor(tn, []byte{0xff, 0x03, 0x00, 0x21, 0x45}))
	if h.frames != 0 {
		t.Fatal("a data message was delivered on a tunnel with no session")
	}
}

// TestTunnelCarriesOnlyItsOwnSession: once up, only data addressed with this
// end's tunnel and session IDs is the call.
func TestTunnelCarriesOnlyItsOwnSession(t *testing.T) {
	h := &recordingHandler{}
	tn := NewTunnel(RoleLNS, nopSend, h)
	tn.established.Store(true)
	frame := []byte{0xff, 0x03, 0x00, 0x21, 0x45}

	tn.HandleInbound(dataWith(tn.localTunnelID+1, tn.localSessionID, frame))
	tn.HandleInbound(dataWith(tn.localTunnelID, tn.localSessionID+1, frame))
	if n := h.reset(); n != 0 {
		t.Fatalf("%d data message(s) for another tunnel or session were delivered", n)
	}
	tn.HandleInbound(dataFor(tn, frame))
	if n := h.reset(); n != 1 {
		t.Fatalf("the session's own data was not delivered (%d)", n)
	}
}

func gateServerPeer(t *testing.T) (*serverPeer, *fakeTUN) {
	t.Helper()
	pool, gw, err := dataplane.NewAddrPool("10.20.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ike, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	natt, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tun := newFakeTUN()
	srv := NewServer(ike, natt, tun, ServerConfig{PSK: []byte("k"), Pool: pool, Gateway: gw})
	t.Cleanup(func() { srv.Close() })
	p := &serverPeer{srv: srv, innerIP: net.IPv4(10, 20, 0, 2).To4()}
	p.inner4 = netip.MustParseAddr("10.20.0.2")
	return p, tun
}

func noTUNWrite(t *testing.T, tun *fakeTUN, why string) {
	t.Helper()
	select {
	case <-tun.out:
		t.Fatal(why)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestServerCarriesNoIPBeforePPPAuthenticates: the group PSK authenticates no
// user, so until MS-CHAPv2 and IPCP have finished an IP frame must not reach
// the TUN. If this fails, anyone holding the PSK reaches the network without
// a user account.
func TestServerCarriesNoIPBeforePPPAuthenticates(t *testing.T) {
	p, tun := gateServerPeer(t)
	gw := net.IPv4(10, 20, 0, 1)
	p.DataFrame(ppp.EncapsulateIP(makeIPv4(p.innerIP, gw)))
	noTUNWrite(t, tun, "an IP frame reached the TUN before PPP authenticated")
	if p.srv.peerByIP(p.innerIP) != nil {
		t.Fatal("the TUN routes to a peer that has not authenticated")
	}

	serverPPP{p}.NetworkUp()
	if p.srv.peerByIP(p.innerIP) != p {
		t.Fatal("the peer was not routed once PPP came up")
	}
	p.DataFrame(ppp.EncapsulateIP(makeIPv4(net.IPv4(10, 20, 0, 9), gw)))
	noTUNWrite(t, tun, "a frame with another address as its source reached the TUN")

	want := makeIPv4(p.innerIP, gw)
	p.DataFrame(ppp.EncapsulateIP(want))
	assertPacket(t, "peer->server", tun.out, want)
}
