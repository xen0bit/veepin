package ike

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// capture records what a pacer transmitted: the bytes, so a mirror tunnel can
// open them, and the sizes, which are the observable a passive attacker has.
type capture struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (c *capture) send(pkt []byte, _ *net.UDPAddr) {
	c.mu.Lock()
	c.pkts = append(c.pkts, append([]byte(nil), pkt...))
	c.mu.Unlock()
}

func (c *capture) packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.pkts...)
}

func (c *capture) sizes() []int {
	out := []int{}
	for _, p := range c.packets() {
		out = append(out, len(p))
	}
	return out
}

// pacedPair builds a paced tunnel and the mirror aggfragTunnel that can open
// what it sends, at the given rate.
func pacedPair(t *testing.T, rate int) (*pacedTunnel, *aggfragTunnel, *capture) {
	t.Helper()
	out, in := aggfragPair(t)
	p := newPacedTunnel(out, rate, iptfsPayloadSize)
	c := &capture{}
	p.StartPacing(c.send)
	t.Cleanup(p.StopPacing)
	return p, in, c
}

// TestTheStreamIsIdenticalIdleOrSaturated is the whole security claim of
// constant-rate IP-TFS, stated as a test rather than as a comment.
//
// If the datagram stream a passive observer sees depends on the traffic inside
// it, the feature has not been delivered -- and a ping, a throughput run and an
// interop cell would all still pass. So this measures both: a tunnel carrying
// nothing and a tunnel carrying as much as it will take, and requires the
// counts and sizes to agree.
func TestTheStreamIsIdenticalIdleOrSaturated(t *testing.T) {
	const rate = 140_000 // 100 payloads/sec: a 10 ms interval, comfortably timeable
	const window = 400 * time.Millisecond

	_, _, idleCap := pacedPair(t, rate)
	time.Sleep(window)
	idleSizes := idleCap.sizes()

	busy, _, busyCap := pacedPair(t, rate)
	stop := make(chan struct{})
	go func() {
		pkt := ipv4Packet(200)
		for {
			select {
			case <-stop:
				return
			default:
				busy.Enqueue(pkt)
				time.Sleep(time.Millisecond)
			}
		}
	}()
	time.Sleep(window)
	close(stop)
	busySizes := busyCap.sizes()

	if len(idleSizes) == 0 {
		t.Fatal("the idle tunnel sent nothing: a constant-rate sender that stops when " +
			"there is no traffic has exactly the schedule it was meant to remove")
	}
	// Timer jitter means the counts are close rather than equal; a difference
	// that tracked the load would be far larger than one tick.
	if diff := abs(len(idleSizes) - len(busySizes)); diff > 3 {
		t.Errorf("idle sent %d datagrams, saturated sent %d — the count follows the load",
			len(idleSizes), len(busySizes))
	}
	for _, sizes := range [][]int{idleSizes, busySizes} {
		for i, n := range sizes {
			if n != sizes[0] {
				t.Fatalf("datagram %d is %d octets, the first was %d — the SIZE follows "+
					"the load, so the padding is not doing its job", i, n, sizes[0])
			}
		}
	}
	if idleSizes[0] != busySizes[0] {
		t.Errorf("idle datagrams are %d octets and saturated ones %d",
			idleSizes[0], busySizes[0])
	}
}

// TestAPacedTunnelStillCarriesTheTraffic. The property above is worthless if the
// packets never arrive: a sender that only ever emitted padding would pass it
// perfectly.
func TestAPacedTunnelStillCarriesTheTraffic(t *testing.T) {
	const rate = 140_000
	out, in, sentPkts := pacedPair(t, rate)

	want := ipv4Packet(120)
	if !out.Enqueue(want) {
		t.Fatal("Enqueue refused the first packet on an empty queue")
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("the enqueued packet never came out of the tunnel: a sender that " +
				"only ever emits padding passes the constant-rate test perfectly")
		default:
		}
		time.Sleep(20 * time.Millisecond)
		for _, esp := range sentPkts.packets() {
			pkts, err := in.DecapsulateMulti(esp, nil)
			if err != nil {
				continue
			}
			for _, p := range pkts {
				if bytes.Equal(p, want) {
					return
				}
			}
		}
	}
}

// TestAFullQueueDropsRatherThanBlocks. Blocking would stall the pump's single
// TUN reader, so one tunnel configured below its offered load would degrade
// every other tunnel the pump serves.
func TestAFullQueueDropsRatherThanBlocks(t *testing.T) {
	// A rate so low that nothing drains during the test.
	out := newPacedTunnel(mustAggfragOut(t), 1, iptfsPayloadSize)

	pkt := ipv4Packet(100)
	accepted := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range pacerQueueDepth * 4 {
			if out.Enqueue(pkt) {
				accepted++
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue blocked on a full queue; the pump's TUN reader would be stalled")
	}
	if accepted > pacerQueueDepth+1 {
		t.Errorf("accepted %d packets into a queue of %d", accepted, pacerQueueDepth)
	}
	if accepted == 0 {
		t.Error("accepted nothing at all")
	}
}

// TestPacingResolvesARateIntoAScheduleThatMeansIt.
func TestPacingResolvesARateIntoAScheduleThatMeansIt(t *testing.T) {
	// 1400 octets every 10 ms is 140 kB/s.
	iv, per := pacing(140_000, 1400)
	if per != 1 {
		t.Errorf("perTick = %d, want 1 at a rate the timer can serve", per)
	}
	if iv != 10*time.Millisecond {
		t.Errorf("interval = %v, want 10ms", iv)
	}
	// Zero and nonsense produce no schedule rather than a division by zero.
	if iv, per := pacing(0, 1400); iv != 0 || per != 0 {
		t.Errorf("pacing(0) = (%v, %d), want (0, 0)", iv, per)
	}
	if iv, per := pacing(140_000, 0); iv != 0 || per != 0 {
		t.Errorf("pacing(rate, 0) = (%v, %d), want (0, 0)", iv, per)
	}
}

// TestTheRateAboveWhichTimingIsQuantised pins the claim the package comment and
// doc/security.md both make in prose: below roughly 100 Mbit/s the sender emits
// one payload per tick, above it the timer cannot keep up and it emits bursts.
//
// A number in a comment drifts from the number in the code silently. This is
// where the two are held together.
func TestTheRateAboveWhichTimingIsQuantised(t *testing.T) {
	const mbit = 1_000_000 / 8 // bytes per second in one Mbit/s

	if bursty, _ := burstsFor(10*mbit, iptfsPayloadSize); bursty {
		t.Error("10 Mbit/s reported as bursty; the docs say it is smooth")
	}
	if bursty, _ := burstsFor(100*mbit, iptfsPayloadSize); bursty {
		t.Error("100 Mbit/s reported as bursty; the docs say roughly there is the boundary")
	}
	bursty, per := burstsFor(1000*mbit, iptfsPayloadSize)
	if !bursty {
		t.Error("1 Gbit/s reported as smooth; a Go timer cannot deliver an 11µs tick")
	}
	if per < 2 {
		t.Errorf("perTick = %d at 1 Gbit/s, want several payloads per tick", per)
	}
}

// --- helpers ---

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// ipv4Packet builds a well-formed IPv4 packet of the given total length, since
// the AGGFRAG block length is read from the inner IP header and a malformed one
// would be unreadable rather than merely wrong.
func ipv4Packet(total int) []byte {
	p := make([]byte, total)
	p[0] = 0x45
	p[2], p[3] = byte(total>>8), byte(total)
	p[8], p[9] = 64, 17
	copy(p[12:16], []byte{10, 0, 0, 1})
	copy(p[16:20], []byte{10, 0, 0, 2})
	for i := 20; i < total; i++ {
		p[i] = byte(i)
	}
	return p
}

func mustAggfragOut(t *testing.T) *aggfragTunnel {
	t.Helper()
	out, _ := aggfragPair(t)
	return out
}
