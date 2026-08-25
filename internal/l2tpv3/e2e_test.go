package l2tpv3

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/vlog"
)

// fakeTAP is a tapIO backed by two channels, standing in for a TAP device: what
// the host writes to the interface comes out of Read, and what the pump writes
// to the interface lands in written.
type fakeTAP struct {
	toPump  chan []byte
	written chan []byte
	closed  chan struct{}
}

func newFakeTAP() *fakeTAP {
	return &fakeTAP{
		toPump:  make(chan []byte, 16),
		written: make(chan []byte, 16),
		closed:  make(chan struct{}),
	}
}

func (f *fakeTAP) Read(buf []byte) (int, error) {
	select {
	case frame := <-f.toPump:
		return copy(buf, frame), nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakeTAP) Write(pkt []byte) (int, error) {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case f.written <- cp:
	default:
	}
	return len(pkt), nil
}

func (f *fakeTAP) Close() { close(f.closed) }

// pair wires two pumps together so each one's Sender delivers straight into the
// other's HandleInbound -- the two halves of one pseudowire, with the network
// replaced by a function call.
type pair struct {
	aTAP, bTAP   *fakeTAP
	aPump, bPump *Pump
}

func newPair(t *testing.T, aCfg, bCfg *SessionConfig) *pair {
	t.Helper()
	logger := vlog.Discard()
	p := &pair{aTAP: newFakeTAP(), bTAP: newFakeTAP()}

	addrA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1701}
	addrB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1701}
	aCfg.PeerAddr, bCfg.PeerAddr = addrB, addrA

	p.aPump = NewPump(p.aTAP, func(pkt []byte, _ *net.UDPAddr) {
		// Copy: the sender's encode buffer is reused for the next packet, and a
		// real socket would have serialised these bytes before returning.
		cp := make([]byte, len(pkt))
		copy(cp, pkt)
		p.bPump.HandleInbound(cp, addrA)
	}, aCfg, logger)

	p.bPump = NewPump(p.bTAP, func(pkt []byte, _ *net.UDPAddr) {
		cp := make([]byte, len(pkt))
		copy(cp, pkt)
		p.aPump.HandleInbound(cp, addrB)
	}, bCfg, logger)

	go p.aPump.Run()
	go p.bPump.Run()

	t.Cleanup(func() {
		p.aPump.Close()
		p.bPump.Close()
		p.aTAP.Close()
		p.bTAP.Close()
	})
	return p
}

// sessions builds the two ends of one pseudowire with ASYMMETRIC cookies, which
// is the arrangement that catches a swapped-direction bug. A's local cookie is
// B's remote cookie and vice versa; get that backwards at both ends and this
// test still passes, which is exactly why the unit-level direction guard in
// frame_test.go is written from the peer's point of view instead.
func sessions(sublayer bool) (a, b *SessionConfig) {
	aCookie := []byte{0xaa, 0xaa, 0xaa, 0xaa}
	bCookie := []byte{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
	a = &SessionConfig{
		LocalSessionID: 100, RemoteSessionID: 200,
		LocalCookie: aCookie, RemoteCookie: bCookie, Sublayer: sublayer,
	}
	b = &SessionConfig{
		LocalSessionID: 200, RemoteSessionID: 100,
		LocalCookie: bCookie, RemoteCookie: aCookie, Sublayer: sublayer,
	}
	return a, b
}

func recvFrame(t *testing.T, tap *fakeTAP) []byte {
	t.Helper()
	select {
	case f := <-tap.written:
		return f
	case <-time.After(2 * time.Second):
		t.Fatal("no frame reached the far TAP")
		return nil
	}
}

// TestPseudowireCarriesFramesBothWays: the data path moves a byte-identical
// Ethernet frame in each direction, with and without a sublayer.
func TestPseudowireCarriesFramesBothWays(t *testing.T) {
	for _, sublayer := range []bool{false, true} {
		name := "no sublayer"
		if sublayer {
			name = "sublayer"
		}
		t.Run(name, func(t *testing.T) {
			aCfg, bCfg := sessions(sublayer)
			p := newPair(t, aCfg, bCfg)

			out := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("a to b"))
			p.aTAP.toPump <- out
			if got := recvFrame(t, p.bTAP); !bytes.Equal(got, out) {
				t.Errorf("a->b:\ngot  %x\nwant %x", got, out)
			}

			back := ethernetFrame("66:77:88:99:aa:bb", "00:11:22:33:44:55", 0x86DD, []byte("b to a"))
			p.bTAP.toPump <- back
			if got := recvFrame(t, p.aTAP); !bytes.Equal(got, back) {
				t.Errorf("b->a:\ngot  %x\nwant %x", got, back)
			}
		})
	}
}

// TestPseudowireCarriesARP: an ARP frame crosses unchanged. This is the frame
// type that proves the tunnel is layer 2 -- an L3 tunnel cannot carry it at
// all, and a shaper must leave it alone because it has no length field to trim
// padding by.
func TestPseudowireCarriesARP(t *testing.T) {
	aCfg, bCfg := sessions(true)
	p := newPair(t, aCfg, bCfg)

	arp := ethernetFrame("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0x0806, arpPacket())
	p.aTAP.toPump <- arp
	if got := recvFrame(t, p.bTAP); !bytes.Equal(got, arp) {
		t.Errorf("ARP frame altered in transit:\ngot  %x\nwant %x", got, arp)
	}
}

// TestShapedPseudowireDeliversTheOriginalFrame: with shaping on, an IP-bearing
// frame goes out padded, and the receiver still hands the TAP something whose
// inner IP packet is intact. The padding is trimmed by the inner header's own
// Total Length, exactly as every IP stack already does.
func TestShapedPseudowireDeliversTheOriginalFrame(t *testing.T) {
	aCfg, bCfg := sessions(true)
	p := newPair(t, aCfg, bCfg)
	p.aPump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: 1 << 16}), 1460)

	inner := ipv4Packet([]byte("shaped payload"))
	out := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, inner)
	p.aTAP.toPump <- out

	got := recvFrame(t, p.bTAP)
	if len(got) < len(out) {
		t.Fatalf("received %d octets, shorter than the %d sent", len(got), len(out))
	}
	if !bytes.Equal(got[:len(out)], out) {
		t.Errorf("the original frame did not survive shaping:\ngot  %x\nwant %x", got[:len(out)], out)
	}
	if trimmed := dataplane.TrimToIP(got[14:]); !bytes.Equal(trimmed, inner) {
		t.Errorf("inner packet after trimming:\ngot  %x\nwant %x", trimmed, inner)
	}
}

// TestShapingLeavesNonIPFramesAlone: ARP has no length field, so a padded ARP
// frame could not be trimmed back. The shaper must decline rather than corrupt.
func TestShapingLeavesNonIPFramesAlone(t *testing.T) {
	aCfg, bCfg := sessions(false)
	p := newPair(t, aCfg, bCfg)
	p.aPump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: 1 << 16}), 1460)

	arp := ethernetFrame("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0x0806, arpPacket())
	p.aTAP.toPump <- arp
	if got := recvFrame(t, p.bTAP); !bytes.Equal(got, arp) {
		t.Errorf("a non-IP frame was padded:\ngot  %x (%d octets)\nwant %x (%d)",
			got, len(got), arp, len(arp))
	}
}

// TestInboundIsRejectedOnTheWrongCookie: a packet whose cookie does not match
// never reaches the TAP.
func TestInboundIsRejectedOnTheWrongCookie(t *testing.T) {
	aCfg, bCfg := sessions(false)
	p := newPair(t, aCfg, bCfg)

	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("spoofed"))
	// Encoded for A's session ID but with a cookie A did not choose.
	bad := EncodeData(nil, aCfg.LocalSessionID, []byte{9, 9, 9, 9}, false, frame)
	p.aPump.HandleInbound(bad, nil)

	select {
	case got := <-p.aTAP.written:
		t.Fatalf("a packet with a bad cookie reached the TAP: %x", got)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestUnknownSessionIsDropped: a packet for a session we do not have is
// discarded rather than mis-parsed against some other session's cookie.
func TestUnknownSessionIsDropped(t *testing.T) {
	aCfg, bCfg := sessions(false)
	p := newPair(t, aCfg, bCfg)

	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("stray"))
	stray := EncodeData(nil, 999, nil, false, frame)
	p.aPump.HandleInbound(stray, nil)

	select {
	case got := <-p.aTAP.written:
		t.Fatalf("a packet for an unknown session reached the TAP: %x", got)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestIdleForReportsForeverBeforeTheFirstPacket: a pseudowire that never came
// up must not look idle-but-healthy to a Prober.
func TestIdleForReportsForeverBeforeTheFirstPacket(t *testing.T) {
	aCfg, bCfg := sessions(false)
	p := newPair(t, aCfg, bCfg)

	if got := p.aPump.IdleFor(); got < time.Hour {
		t.Errorf("IdleFor before any traffic = %v, want a very large duration", got)
	}

	p.bTAP.toPump <- ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("hi"))
	recvFrame(t, p.aTAP)

	if got := p.aPump.IdleFor(); got > time.Minute {
		t.Errorf("IdleFor after traffic = %v, want a small duration", got)
	}
}

// ipv4Packet builds a minimal well-formed IPv4 packet whose Total Length field
// is correct, so TrimToIP can find the end of it.
func ipv4Packet(payload []byte) []byte {
	total := 20 + len(payload)
	p := make([]byte, total)
	p[0] = 0x45 // version 4, IHL 5
	p[2] = byte(total >> 8)
	p[3] = byte(total)
	p[8] = 64 // TTL
	p[9] = 17 // UDP
	copy(p[12:16], []byte{10, 0, 0, 1})
	copy(p[16:20], []byte{10, 0, 0, 2})
	copy(p[20:], payload)
	return p
}
