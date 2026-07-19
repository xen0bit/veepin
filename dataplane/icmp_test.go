package dataplane

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

// ipv4 builds a well-formed IPv4 packet of the given total size.
func ipv4(src, dst string, df bool, size int) []byte {
	if size < ipv4HeaderMin {
		size = ipv4HeaderMin
	}
	pkt := make([]byte, size)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(size))
	if df {
		pkt[6] = ipv4FlagDF
	}
	pkt[8] = 64
	pkt[9] = 6 // TCP, which is what actually depends on this working
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())
	putIPv4Checksum(pkt[:ipv4HeaderMin])
	return pkt
}

func TestNeedsFragmentation(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt  []byte
		mtu  int
		want bool
	}{
		{"oversized with DF", ipv4("10.0.0.2", "10.0.0.1", true, 1500), 1400, true},
		{"oversized without DF", ipv4("10.0.0.2", "10.0.0.1", false, 1500), 1400, false},
		{"fits", ipv4("10.0.0.2", "10.0.0.1", true, 1000), 1400, false},
		{"exactly the MTU", ipv4("10.0.0.2", "10.0.0.1", true, 1400), 1400, false},
		{"not IPv4", []byte{0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 10, false},
		{"runt", []byte{0x45}, 10, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NeedsFragmentation(tc.pkt, tc.mtu); got != tc.want {
				t.Errorf("NeedsFragmentation = %v, want %v", got, tc.want)
			}
		})
	}
}

// A packet over the MTU without DF is a plain drop, not a black hole: the sender
// allowed fragmentation, so it is owed no notification.
func TestNoFragNeededWithoutDF(t *testing.T) {
	if NeedsFragmentation(ipv4("10.0.0.2", "10.0.0.1", false, 9000), 1400) {
		t.Error("a packet without DF was reported as needing notification")
	}
}

func TestFragNeededIsWellFormed(t *testing.T) {
	orig := ipv4("10.0.0.2", "10.0.0.1", true, 1500)
	reply := FragNeeded(orig, 1400)
	if reply == nil {
		t.Fatal("FragNeeded returned nil for a valid oversized packet")
	}

	if reply[0]>>4 != 4 {
		t.Fatalf("reply is not IPv4")
	}
	if reply[9] != protoICMP {
		t.Errorf("reply protocol = %d, want ICMP (%d)", reply[9], protoICMP)
	}

	// The error must appear to come from the destination the sender was talking
	// to, or the sending stack will ignore it.
	if got := net.IP(reply[12:16]).String(); got != "10.0.0.1" {
		t.Errorf("reply source = %s, want the original destination 10.0.0.1", got)
	}
	if got := net.IP(reply[16:20]).String(); got != "10.0.0.2" {
		t.Errorf("reply destination = %s, want the original sender 10.0.0.2", got)
	}

	icmp := reply[ipv4HeaderMin:]
	if icmp[0] != icmpTypeDestUnreachable || icmp[1] != icmpCodeFragNeeded {
		t.Errorf("icmp type/code = %d/%d, want %d/%d",
			icmp[0], icmp[1], icmpTypeDestUnreachable, icmpCodeFragNeeded)
	}
	if got := binary.BigEndian.Uint16(icmp[6:8]); got != 1400 {
		t.Errorf("advertised next-hop MTU = %d, want 1400", got)
	}

	// Checksums must be right or the host discards the message silently, which
	// would look exactly like the black hole this exists to fix.
	if sum := onesComplement(reply[:ipv4HeaderMin]); sum != 0 {
		t.Errorf("IPv4 header checksum does not verify (residual %#04x)", sum)
	}
	if sum := onesComplement(icmp); sum != 0 {
		t.Errorf("ICMP checksum does not verify (residual %#04x)", sum)
	}

	// RFC 1812: the original header plus eight octets of payload, so the sender
	// can match the error to a socket.
	if len(icmp) < 8+ipv4HeaderMin+8 {
		t.Errorf("quoted packet is %d octets, too short to identify the flow", len(icmp)-8)
	}
}

// The reply must round-trip through the parser: what veepin emits is the same
// shape it recognises coming back.
func TestFragNeededRoundTrip(t *testing.T) {
	orig := ipv4("10.0.0.2", "10.0.0.1", true, 1500)
	reply := FragNeeded(orig, 1337)

	mtu, ok := ParseFragNeeded(reply)
	if !ok {
		t.Fatal("a reply we generated was not recognised by our own parser")
	}
	if mtu != 1337 {
		t.Errorf("parsed MTU = %d, want 1337", mtu)
	}
}

func TestParseFragNeededRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"runt", []byte{0x45, 0, 0}},
		{"not ICMP", ipv4("10.0.0.1", "10.0.0.2", false, 40)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := ParseFragNeeded(tc.pkt); ok {
				t.Error("accepted something that is not a fragmentation-needed message")
			}
		})
	}

	// A pre-RFC-1191 router reports no MTU. That is not usable, and must not be
	// handed back as an MTU of zero for a caller to act on.
	t.Run("zero MTU", func(t *testing.T) {
		reply := FragNeeded(ipv4("10.0.0.2", "10.0.0.1", true, 1500), 1400)
		binary.BigEndian.PutUint16(reply[ipv4HeaderMin+6:ipv4HeaderMin+8], 0)
		if _, ok := ParseFragNeeded(reply); ok {
			t.Error("accepted a message advertising no MTU")
		}
	})
}

func TestFragNeededRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"runt", []byte{0x45, 0x00}},
		{"not IPv4", []byte{0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"IHL past the buffer", append([]byte{0x4f}, make([]byte, 19)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := FragNeeded(tc.pkt, 1400); got != nil {
				t.Errorf("built a reply for a malformed packet: %x", got)
			}
		})
	}
}

// memTUN records what the pump writes back, so the ICMP reply can be observed.
type recordingTUN struct {
	out [][]byte
	in  chan []byte
}

func (t *recordingTUN) Read(b []byte) (int, error) {
	pkt, ok := <-t.in
	if !ok {
		return 0, net.ErrClosed
	}
	return copy(b, pkt), nil
}

func (t *recordingTUN) Write(pkt []byte) (int, error) {
	t.out = append(t.out, append([]byte(nil), pkt...))
	return len(pkt), nil
}

// nopTunnel carries everything and records nothing; it exists so routeOutbound
// has a route to find.
type nopTunnel struct{ sent int }

func (n *nopTunnel) InboundKey() uint32 { return 1 }
func (n *nopTunnel) Routes() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
}
func (n *nopTunnel) PeerAddr() *net.UDPAddr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (n *nopTunnel) Encapsulate(pkt []byte) ([]byte, error) {
	n.sent++
	return pkt, nil
}
func (n *nopTunnel) Decapsulate(pkt []byte) ([]byte, error) { return pkt, nil }

// The pump must answer an oversized DF packet with ICMP rather than drop it.
// Dropping is what produces a black hole: the sender waits forever for an
// acknowledgement of a packet that can never arrive, and is never told why.
func TestPumpAnswersOversizedPackets(t *testing.T) {
	tun := &recordingTUN{in: make(chan []byte, 1)}
	tunnel := &nopTunnel{}
	p := NewPump(tun, func([]byte, *net.UDPAddr) {}, nil, nil)
	p.AddTunnel(tunnel)
	p.SetInnerMTU(1400)

	p.routeOutbound(ipv4("10.0.0.2", "10.0.0.1", true, 1500))

	if tunnel.sent != 0 {
		t.Error("an oversized packet was encapsulated instead of refused")
	}
	if len(tun.out) != 1 {
		t.Fatalf("wrote %d packets back to the TUN, want 1 ICMP reply", len(tun.out))
	}
	mtu, ok := ParseFragNeeded(tun.out[0])
	if !ok {
		t.Fatal("what was written back is not a fragmentation-needed message")
	}
	if mtu != 1400 {
		t.Errorf("advertised MTU = %d, want 1400", mtu)
	}
}

// A packet that fits must pass through untouched, and one without DF is dropped
// silently rather than answered.
func TestPumpPassesPacketsThatFit(t *testing.T) {
	tun := &recordingTUN{in: make(chan []byte, 1)}
	tunnel := &nopTunnel{}
	p := NewPump(tun, func([]byte, *net.UDPAddr) {}, nil, nil)
	p.AddTunnel(tunnel)
	p.SetInnerMTU(1400)

	p.routeOutbound(ipv4("10.0.0.2", "10.0.0.1", true, 500))
	if tunnel.sent != 1 {
		t.Errorf("a packet within the MTU was not sent (encapsulated %d)", tunnel.sent)
	}
	if len(tun.out) != 0 {
		t.Errorf("an ICMP reply was generated for a packet that fits")
	}

	// Over the MTU but fragmentable: a plain drop, no notification owed.
	p.routeOutbound(ipv4("10.0.0.2", "10.0.0.1", false, 1500))
	if len(tun.out) != 0 {
		t.Error("a non-DF packet was answered with ICMP")
	}
}

// Zero disables the check, which is the behaviour from before this existed.
func TestPumpMTUZeroDisablesTheCheck(t *testing.T) {
	tun := &recordingTUN{in: make(chan []byte, 1)}
	tunnel := &nopTunnel{}
	p := NewPump(tun, func([]byte, *net.UDPAddr) {}, nil, nil)
	p.AddTunnel(tunnel)

	p.routeOutbound(ipv4("10.0.0.2", "10.0.0.1", true, 9000))
	if tunnel.sent != 1 {
		t.Error("an oversized packet was refused even though the check is disabled")
	}
	if len(tun.out) != 0 {
		t.Error("an ICMP reply was generated with the check disabled")
	}
}
