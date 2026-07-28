package softether

import (
	"net/netip"
	"testing"
	"time"
)

func TestBridgeLearnLookup(t *testing.T) {
	b := NewBridge(DefaultAgeTime)
	p1 := b.NewPort()
	p2 := b.NewPort()

	macA := MACAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	macB := MACAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	if err := b.Learn(macA, p1); err != nil {
		t.Fatalf("Learn: %v", err)
	}
	if got := b.Lookup(macA); got != p1 {
		t.Errorf("Lookup(macA) = %d, want %d", got, p1)
	}

	if err := b.Learn(macB, p2); err != nil {
		t.Fatalf("Learn: %v", err)
	}
	if got := b.Lookup(macB); got != p2 {
		t.Errorf("Lookup(macB) = %d, want %d", got, p2)
	}
}

func TestBridgeLearnRemovesStale(t *testing.T) {
	b := NewBridge(50 * time.Millisecond)
	p := b.NewPort()
	mac := MACAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	_ = b.Learn(mac, p)
	if got := b.Lookup(mac); got != p {
		t.Fatalf("expected immediate lookup to succeed")
	}

	time.Sleep(100 * time.Millisecond)
	if got := b.Lookup(mac); got != 0 {
		t.Errorf("expected stale entry to return 0, got %d", got)
	}
}

func TestBridgeRemovePort(t *testing.T) {
	b := NewBridge(DefaultAgeTime)
	p := b.NewPort()
	mac := MACAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	_ = b.Learn(mac, p)
	b.RemovePort(p)

	if got := b.Lookup(mac); got != 0 {
		t.Errorf("expected removed port's MAC to vanish, got %d", got)
	}
}

func TestBridgeForwardKnownUnicast(t *testing.T) {
	b := NewBridge(DefaultAgeTime)
	p1 := b.NewPort()
	_ = b.NewPort() // p2

	macA := MACAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	macB := MACAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	_ = b.Learn(macA, p1)
	_ = b.Learn(macB, p1) // learn both on the same port for this test

	frame := ethFrame{Src: macA, Dst: macB, Type: EtherTypeIPv4, Body: []byte{0x45, 0, 0, 0x20}}
	result := b.Forward(frame, p1)

	if len(result.Destinations) != 1 || result.Destinations[0] != p1 {
		t.Errorf("expected forward to port %d, got %v", p1, result.Destinations)
	}
	if !result.ExcludeSource {
		t.Error("expected ExcludeSource = true")
	}
}

func TestBridgeForwardBroadcast(t *testing.T) {
	b := NewBridge(DefaultAgeTime)
	p1 := b.NewPort()
	broadcast := MACAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	frame := ethFrame{Src: MACAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, Dst: broadcast}
	result := b.Forward(frame, p1)

	if result.Destinations != nil {
		t.Errorf("expected nil Destinations for broadcast (flood), got %v", result.Destinations)
	}
	if !result.ExcludeSource {
		t.Error("expected ExcludeSource = true for broadcast")
	}
}

func TestBridgeForwardUnknownUnicast(t *testing.T) {
	b := NewBridge(DefaultAgeTime)
	p1 := b.NewPort()
	_ = b.NewPort()

	unknownMAC := MACAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00}
	frame := ethFrame{Src: MACAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, Dst: unknownMAC}
	result := b.Forward(frame, p1)

	if result.Destinations != nil {
		t.Errorf("expected nil Destinations (flood unknown unicast), got %v", result.Destinations)
	}
}

func TestIsMulticast(t *testing.T) {
	if !IsMulticast(MACAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}) {
		t.Error("expected multicast MAC to be detected")
	}
	if IsMulticast(MACAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Error("expected unicast MAC not to be multicast")
	}
}

func TestIsBroadcast(t *testing.T) {
	if !IsBroadcast(MACAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Error("expected broadcast MAC to be detected")
	}
	if IsBroadcast(MACAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}) {
		t.Error("expected multicast MAC not to be broadcast")
	}
}

func TestParseFrame(t *testing.T) {
	frame := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
		0x08, 0x00, // EtherType IPv4
		0x45, 0x00, 0x00, 0x20, // IPv4 header start
	}
	f, ok := ParseFrame(frame)
	if !ok {
		t.Fatal("ParseFrame failed")
	}
	if f.Dst != (MACAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Errorf("dst = %s, want 00:11:22:33:44:55", f.Dst)
	}
	if f.Src != (MACAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("src = %s, want aa:bb:cc:dd:ee:ff", f.Src)
	}
	if f.Type != EtherTypeIPv4 {
		t.Errorf("type = %x, want %x", f.Type, EtherTypeIPv4)
	}
}

func TestParseFrameShort(t *testing.T) {
	_, ok := ParseFrame([]byte{0, 1, 2})
	if ok {
		t.Error("expected ParseFrame to fail on short input")
	}
}

func TestNewPort(t *testing.T) {
	b := NewBridge(DefaultAgeTime)
	p1 := b.NewPort()
	p2 := b.NewPort()
	if p1 == p2 {
		t.Error("expected unique port IDs")
	}
}

func TestBridgeMACTableFull(t *testing.T) {
	b := NewBridge(DefaultAgeTime)
	p := b.NewPort()

	// Fill the table.
	for i := 0; i < MaxMACEntries+1; i++ {
		mac := MACAddr{byte(i >> 16), byte(i >> 8), byte(i), 0, 0, 0}
		err := b.Learn(mac, p)
		if err == ErrMACTableFull {
			return // expected once full
		}
	}
	t.Error("expected ErrMACTableFull after MaxMACEntries")
}

func TestARPReply(t *testing.T) {
	ourMAC := MACAddr{0x00, 0x0c, 0x29, 0x01, 0x02, 0x03}
	ourIP := netip.MustParseAddr("10.0.0.1")

	// Build an ARP request (Ethernet + ARP).
	requestMAC := MACAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00}
	requestIP := netip.MustParseAddr("10.0.0.2")

	arpReq := make([]byte, 42)
	copy(arpReq[0:6], ourMAC[:])      // dst = our MAC
	copy(arpReq[6:12], requestMAC[:]) // src
	arpReq[12] = 0x08                 // EtherType
	arpReq[13] = 0x06                 // ARP
	arpReq[14] = 0x00                 // htype
	arpReq[15] = 0x01                 // Ethernet
	arpReq[16] = 0x08                 // ptype IPv4
	arpReq[17] = 0x00
	arpReq[18] = 6 // hlen
	arpReq[19] = 4 // plen
	arpReq[20] = 0 // op = request
	arpReq[21] = 1
	copy(arpReq[22:28], requestMAC[:]) // sender MAC
	copy(arpReq[28:32], requestIP.AsSlice())
	copy(arpReq[32:38], ourMAC[:]) // target MAC
	copy(arpReq[38:42], ourIP.AsSlice())

	reply, ok := arpReply(arpReq, ourMAC, ourIP)
	if !ok {
		t.Fatal("arpReply returned false")
	}
	// Verify it's an ARP reply (op=2).
	if len(reply) < 42 {
		t.Fatal("reply too short")
	}
	op := int(reply[20])<<8 | int(reply[21])
	if op != 2 {
		t.Errorf("ARP op = %d, want 2 (reply)", op)
	}
	// Reply dst should be the request source.
	if reply[0] != requestMAC[0] || reply[1] != requestMAC[1] {
		t.Error("reply dst should be requestor's MAC")
	}
}

func TestARPReplyWrongIP(t *testing.T) {
	ourMAC := MACAddr{0x00, 0x0c, 0x29, 0x01, 0x02, 0x03}
	ourIP := netip.MustParseAddr("10.0.0.1")
	wrongIP := netip.MustParseAddr("10.0.0.99")

	req := make([]byte, 42)
	copy(req[38:42], wrongIP.AsSlice()) // TPA (target IP) is not ours
	_, ok := arpReply(req, ourMAC, ourIP)
	if ok {
		t.Error("arpReply should return false when target IP doesn't match")
	}
}

func TestFloodPorts(t *testing.T) {
	b := NewBridge(DefaultAgeTime)
	p1 := b.NewPort()
	_ = b.NewPort()
	_ = b.NewPort()

	ports := b.FloodPorts(p1)
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}
	for _, p := range ports {
		if p == p1 {
			t.Error("flood should exclude source port")
		}
	}
}
