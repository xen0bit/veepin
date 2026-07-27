package dataplane

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

const testMTU = 1400

// v4TCP builds an IPv4/TCP packet of total length n with the given ports, so a
// test can vary flow identity and size independently.
func v4TCP(t *testing.T, n int, sport, dport uint16) []byte {
	t.Helper()
	if n < 24 {
		t.Fatalf("v4TCP: n = %d, need at least 24", n)
	}
	p := make([]byte, n)
	p[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(p[2:4], uint16(n))
	p[8] = 64 // TTL
	p[9] = 6  // TCP
	copy(p[12:16], []byte{10, 0, 0, 1})
	copy(p[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	return p
}

// v6TCP builds an IPv6/TCP packet whose total on-wire length is n.
func v6TCP(t *testing.T, n int, sport, dport uint16) []byte {
	t.Helper()
	if n < 44 {
		t.Fatalf("v6TCP: n = %d, need at least 44", n)
	}
	p := make([]byte, n)
	p[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(p[4:6], uint16(n-40))
	p[6] = 6  // TCP
	p[7] = 64 // hop limit
	p[8] = 0xfd
	p[24] = 0xfd
	p[39] = 1
	binary.BigEndian.PutUint16(p[40:42], sport)
	binary.BigEndian.PutUint16(p[42:44], dport)
	return p
}

// fakeClock is a manually advanced clock, so idle behaviour is tested without
// sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestShaperPadsYoungFlowThenStops(t *testing.T) {
	// The budget is charged what each packet *emits*, not what it carries, so a
	// budget of three MTUs buys exactly three shaped packets whatever size they
	// are — then the flow is free forever.
	s := NewShaper(ShapeConfig{Bytes: 3 * testMTU})
	pkt := v4TCP(t, 100, 1234, 443)

	for i := range 3 {
		if got := s.Target(pkt, testMTU); got != testMTU {
			t.Fatalf("packet %d: Target = %d, want %d (flow still has budget)", i, got, testMTU)
		}
	}
	for i := range 5 {
		if got := s.Target(pkt, testMTU); got != 0 {
			t.Fatalf("packet %d past budget: Target = %d, want 0", i+3, got)
		}
	}
}

// TestShaperBudgetBoundsEmittedBytes is the property the budget is supposed to
// have and did not: it must bound what shaping puts on the wire, not what the
// flow carries. Charging the inner length let a flow of small packets run far
// past the budget's apparent cost — at 60-octet packets a 16 KiB budget shaped
// 273 of them and emitted 382 KiB — which made the design's affordability
// argument untrue for exactly the traffic that needs the most shaping.
//
// The bound is the budget plus at most one MTU: a flow with any budget left
// shapes the next packet in full rather than refusing it, so that a budget
// below one MTU still buys one shaped packet instead of none.
func TestShaperBudgetBoundsEmittedBytes(t *testing.T) {
	const budget = 16384
	for _, size := range []int{60, 100, 576, testMTU - 1} {
		s := NewShaper(ShapeConfig{Bytes: budget})
		pkt := v4TCP(t, size, 1234, 443)

		emitted, shaped := 0, 0
		for range 1000 {
			target := s.Target(pkt, testMTU)
			if target == 0 {
				break
			}
			emitted += target
			shaped++
		}
		if emitted > budget+testMTU {
			t.Errorf("%d-octet packets: emitted %d bytes for a %d budget", size, emitted, budget)
		}
		// The count is the same whatever the packet size, which is what lets it
		// be normalised rather than merely bounded.
		if want := (budget + testMTU - 1) / testMTU; shaped != want {
			t.Errorf("%d-octet packets: %d shaped packets, want %d", size, shaped, want)
		}
	}
}

// A packet already at the MTU is never padded, so it costs the budget nothing
// it would not have spent anyway — bulk transfer stays free.
func TestShaperAtMTUPacketIsNeverPadded(t *testing.T) {
	s := NewShaper(ShapeConfig{Bytes: 1 << 20})
	for range 10 {
		if got := s.Target(v4TCP(t, testMTU, 1234, 443), testMTU); got != 0 {
			t.Fatalf("at-MTU packet: Target = %d, want 0", got)
		}
	}
}

func TestShaperTracksFlowsIndependently(t *testing.T) {
	s := NewShaper(ShapeConfig{Bytes: 100})
	a := v4TCP(t, 100, 1111, 443)
	b := v4TCP(t, 100, 2222, 443) // same hosts, different source port

	if got := s.Target(a, testMTU); got != testMTU {
		t.Fatalf("flow a first packet: Target = %d, want %d", got, testMTU)
	}
	if got := s.Target(a, testMTU); got != 0 {
		t.Fatalf("flow a second packet: Target = %d, want 0", got)
	}
	// b is a different flow and must still have its own full budget.
	if got := s.Target(b, testMTU); got != testMTU {
		t.Fatalf("flow b first packet: Target = %d, want %d", got, testMTU)
	}
}

func TestShaperReArmsAfterIdle(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	s := NewShaper(ShapeConfig{Bytes: 100, Idle: 30 * time.Second, Now: clk.now})
	pkt := v4TCP(t, 100, 1234, 443)

	if got := s.Target(pkt, testMTU); got != testMTU {
		t.Fatalf("first packet: Target = %d, want %d", got, testMTU)
	}
	if got := s.Target(pkt, testMTU); got != 0 {
		t.Fatalf("budget should be spent: Target = %d, want 0", got)
	}

	clk.advance(29 * time.Second)
	if got := s.Target(pkt, testMTU); got != 0 {
		t.Fatalf("below the idle threshold: Target = %d, want 0", got)
	}
	clk.advance(31 * time.Second)
	if got := s.Target(pkt, testMTU); got != testMTU {
		t.Fatalf("past the idle threshold the budget should re-arm: Target = %d, want %d", got, testMTU)
	}
}

func TestShaperBoundsFlowTable(t *testing.T) {
	const maxFlows = 16
	s := NewShaper(ShapeConfig{Bytes: 4096, MaxFlows: maxFlows})
	for i := range maxFlows * 4 {
		s.Target(v4TCP(t, 100, uint16(1024+i), 443), testMTU)
		if len(s.flows) > maxFlows {
			t.Fatalf("flow table grew to %d, want <= %d", len(s.flows), maxFlows)
		}
	}
}

func TestShaperNeverExceedsMTU(t *testing.T) {
	s := NewShaper(ShapeConfig{Bytes: 1 << 20})
	// A packet already at the MTU has nothing to pad to.
	if got := s.Target(v4TCP(t, testMTU, 1, 2), testMTU); got != 0 {
		t.Errorf("at-MTU packet: Target = %d, want 0", got)
	}
	// One over should not produce a target either; the pump's fragmentation
	// check owns that case.
	if got := s.Target(v4TCP(t, testMTU+40, 3, 4), testMTU); got != 0 {
		t.Errorf("over-MTU packet: Target = %d, want 0", got)
	}
	// And a shaped packet is never padded past the MTU it was given.
	if got := s.Target(v4TCP(t, 100, 5, 6), testMTU); got > testMTU {
		t.Errorf("Target = %d, want <= %d", got, testMTU)
	}
}

func TestShaperDisabled(t *testing.T) {
	pkt := v4TCP(t, 100, 1234, 443)
	if got := (*Shaper)(nil).Target(pkt, testMTU); got != 0 {
		t.Errorf("nil shaper: Target = %d, want 0", got)
	}
	if got := NewShaper(ShapeConfig{}).Target(pkt, testMTU); got != 0 {
		t.Errorf("zero Bytes: Target = %d, want 0", got)
	}
	if got := NewShaper(ShapeConfig{Bytes: 4096}).Target(pkt, 0); got != 0 {
		t.Errorf("zero mtu: Target = %d, want 0", got)
	}
	// A non-IP packet cannot be attributed to a flow and is left alone.
	if got := NewShaper(ShapeConfig{Bytes: 4096}).Target([]byte{0xff, 0x00}, testMTU); got != 0 {
		t.Errorf("non-IP packet: Target = %d, want 0", got)
	}
}

func TestShaperDualStack(t *testing.T) {
	s := NewShaper(ShapeConfig{Bytes: 100})
	if got := s.Target(v6TCP(t, 100, 1234, 443), testMTU); got != testMTU {
		t.Fatalf("IPv6 first packet: Target = %d, want %d", got, testMTU)
	}
	if got := s.Target(v6TCP(t, 100, 1234, 443), testMTU); got != 0 {
		t.Fatalf("IPv6 budget should be spent: Target = %d, want 0", got)
	}
}

// TestShaperAllocations guards the property that makes shaping affordable: the
// per-packet decision must allocate nothing, in both the shaped and the spent
// state. A map key that escapes here would put garbage on every outbound packet.
func TestShaperAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are perturbed by the race detector")
	}
	pkt := v4TCP(t, 100, 1234, 443)

	// Steady state with budget remaining: the table entry already exists, so
	// nothing should allocate.
	shaping := NewShaper(ShapeConfig{Bytes: 1 << 30})
	shaping.Target(pkt, testMTU) // create the entry before measuring
	if n := testing.AllocsPerRun(200, func() {
		shaping.Target(pkt, testMTU)
	}); n != 0 {
		t.Errorf("shaped-path allocs/op = %v, want 0", n)
	}

	// Steady state past the budget: the common case for bulk transfer.
	spent := NewShaper(ShapeConfig{Bytes: 1})
	spent.Target(pkt, testMTU)
	if n := testing.AllocsPerRun(200, func() {
		spent.Target(pkt, testMTU)
	}); n != 0 {
		t.Errorf("spent-path allocs/op = %v, want 0", n)
	}
}

func TestTrimToIP(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int // expected length, or -1 for nil
	}{
		{"ipv4 exact", v4TCP(t, 100, 1, 2), 100},
		{"ipv6 exact", v6TCP(t, 100, 1, 2), 100},
		{"ipv4 padded", append(v4TCP(t, 100, 1, 2), make([]byte, 1300)...), 100},
		{"ipv6 padded", append(v6TCP(t, 100, 1, 2), make([]byte, 1300)...), 100},
		{"empty is a keepalive", nil, -1},
		{"not an IP packet", []byte{0xff, 0x00, 0x00, 0x00}, -1},
		{"ipv4 runt", make([]byte, 8), -1},
		{"ipv4 header lies long", v4TCP(t, 100, 1, 2)[:60], -1},
		{"ipv6 header lies long", v6TCP(t, 100, 1, 2)[:60], -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TrimToIP(tc.in)
			if tc.want < 0 {
				if got != nil {
					t.Fatalf("TrimToIP = %d bytes, want nil", len(got))
				}
				return
			}
			if len(got) != tc.want {
				t.Fatalf("TrimToIP = %d bytes, want %d", len(got), tc.want)
			}
		})
	}
}

// TestTrimToIPIgnoresPaddingBytes checks that the trim returns exactly the
// original packet, not merely the right length — the property the padding
// round-trips depend on.
func TestTrimToIPIgnoresPaddingBytes(t *testing.T) {
	orig := v4TCP(t, 137, 1234, 443)
	for i := 24; i < len(orig); i++ {
		orig[i] = byte(i) // distinguishable payload
	}
	padded := make([]byte, 1400)
	copy(padded, orig)
	got := TrimToIP(padded)
	if string(got) != string(orig) {
		t.Fatalf("TrimToIP did not recover the original packet")
	}
}

// TestFlowKeyIgnoresLaterFragments checks that a non-first fragment does not
// read its "ports" out of the payload, which would scatter one flow's fragments
// across many table entries.
func TestFlowKeyIgnoresLaterFragments(t *testing.T) {
	first := v4TCP(t, 100, 1234, 443)
	later := v4TCP(t, 100, 1234, 443)
	binary.BigEndian.PutUint16(later[6:8], 0x00b9) // fragment offset != 0

	kf, ok := flowKeyOf(first)
	if !ok {
		t.Fatal("first fragment: flowKeyOf failed")
	}
	kl, ok := flowKeyOf(later)
	if !ok {
		t.Fatal("later fragment: flowKeyOf failed")
	}
	if kl.sport != 0 || kl.dport != 0 {
		t.Errorf("later fragment ports = %d/%d, want 0/0", kl.sport, kl.dport)
	}
	if kf.src != kl.src || kf.dst != kl.dst || kf.proto != kl.proto {
		t.Error("fragments of one packet should agree on addresses and protocol")
	}
}

// padTunnel records what the pump asked it for, so the wiring between Shaper
// and PaddingTunnel can be observed. Its "encapsulation" is a 4-byte SPI prefix
// plus zero filler out to the requested size.
type padTunnel struct {
	peer      *net.UDPAddr
	lastPad   int  // minInner from the most recent EncapsulatePadded, -1 if plain
	supported bool // false makes it a plain Tunnel with no padding capability
}

func (t *padTunnel) InboundKey() uint32 { return 1 }
func (t *padTunnel) Routes() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
}
func (t *padTunnel) PeerAddr() *net.UDPAddr { return t.peer }
func (t *padTunnel) Encapsulate(p []byte) ([]byte, error) {
	t.lastPad = -1
	return append([]byte{0, 0, 0, 1}, p...), nil
}
func (t *padTunnel) Decapsulate(p []byte) ([]byte, error) { return p[4:], nil }
func (t *padTunnel) EncapsulatePadded(p []byte, minInner int) ([]byte, error) {
	t.lastPad = minInner
	out := append([]byte{0, 0, 0, 1}, p...)
	if grow := minInner - len(p); grow > 0 {
		out = append(out, make([]byte, grow)...)
	}
	return out, nil
}

// plainTunnel implements Tunnel and nothing more, so the shaper must fall back
// rather than fail — the property that lets shaping be switched on tree-wide
// while only some protocols can act on it. It deliberately does not embed
// padTunnel: doing so would give it an EncapsulatePadded method and satisfy
// PaddingTunnel, which is the opposite of what this stands for.
type plainTunnel struct{ peer *net.UDPAddr }

func (t *plainTunnel) InboundKey() uint32 { return 1 }
func (t *plainTunnel) Routes() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
}
func (t *plainTunnel) PeerAddr() *net.UDPAddr { return t.peer }
func (t *plainTunnel) Encapsulate(p []byte) ([]byte, error) {
	return append([]byte{0, 0, 0, 1}, p...), nil
}
func (t *plainTunnel) Decapsulate(p []byte) ([]byte, error) { return p[4:], nil }

// Compile-time statement of what each double is for.
var (
	_ PaddingTunnel = (*padTunnel)(nil)
	_ Tunnel        = (*plainTunnel)(nil)
)

func TestPumpShapesThroughPaddingTunnel(t *testing.T) {
	tun := &padTunnel{peer: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}, supported: true}
	var sent [][]byte
	p := NewPump(newFakeTUN(), func(pkt []byte, _ *net.UDPAddr) {
		sent = append(sent, append([]byte(nil), pkt...))
	}, SPIDemux, nil)
	p.AddTunnel(tun)
	p.SetInnerMTU(testMTU)
	p.SetShaper(NewShaper(ShapeConfig{Bytes: 300}))

	small := v4TCP(t, 100, 1234, 443)
	p.routeOutbound(small)
	if tun.lastPad != testMTU {
		t.Fatalf("first packet: minInner = %d, want %d", tun.lastPad, testMTU)
	}
	if len(sent) != 1 || len(sent[0]) != 4+testMTU {
		t.Fatalf("sent datagram = %d bytes, want %d", len(sent[0]), 4+testMTU)
	}

	// Spend the budget; after that the pump must take the plain path.
	for range 5 {
		p.routeOutbound(small)
	}
	if tun.lastPad != -1 {
		t.Errorf("past the budget the pump should call Encapsulate, got minInner = %d", tun.lastPad)
	}
	if got := len(sent[len(sent)-1]); got != 4+len(small) {
		t.Errorf("unshaped datagram = %d bytes, want %d", got, 4+len(small))
	}
}

// A Tunnel that implements no padding must simply be sent unpadded.
func TestPumpFallsBackWithoutPaddingSupport(t *testing.T) {
	tun := &plainTunnel{peer: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}}
	var sent int
	p := NewPump(newFakeTUN(), func([]byte, *net.UDPAddr) { sent++ }, SPIDemux, nil)
	// Register through the Tunnel interface only, so the pump's type assertion
	// is what decides — exactly as it would for a real protocol.
	p.AddTunnel(Tunnel(tun))
	p.SetInnerMTU(testMTU)
	p.SetShaper(NewShaper(ShapeConfig{Bytes: 4096}))

	p.routeOutbound(v4TCP(t, 100, 1234, 443)) // must not panic
	if sent != 1 {
		t.Fatalf("sent %d datagrams, want 1", sent)
	}
}

// A pump with no shaper behaves exactly as before.
func TestPumpWithoutShaperNeverPads(t *testing.T) {
	tun := &padTunnel{peer: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}}
	p := NewPump(newFakeTUN(), func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
	p.AddTunnel(tun)
	p.SetInnerMTU(testMTU)

	p.routeOutbound(v4TCP(t, 100, 1234, 443))
	if tun.lastPad != -1 {
		t.Errorf("unshaped pump asked for padding: minInner = %d", tun.lastPad)
	}
}
