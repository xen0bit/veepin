package dataplane

import (
	"net"
	"testing"
	"time"
)

func udp(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

// clock is a controllable time source, so rate-limit behaviour is tested by
// advancing time rather than by sleeping.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestGate(cfg AdmissionConfig) (*Gate, *clock) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	cfg.Now = c.now
	return NewGate(cfg), c
}

func TestGateCapsHalfOpen(t *testing.T) {
	g, _ := newTestGate(AdmissionConfig{
		MaxHalfOpen: 3,
		// Generous enough that the rate limit is not what is being measured.
		PerSourceRate: 1000, PerSourceBurst: 1000,
	})

	for i := range 3 {
		if r := g.Admit(udp("192.0.2.1", 1000+i)); r != Admitted {
			t.Fatalf("handshake %d rejected: %v", i, r)
		}
	}
	if r := g.Admit(udp("192.0.2.1", 2000)); r != RejectedAtCapacity {
		t.Errorf("fourth handshake = %v, want RejectedAtCapacity", r)
	}

	// Completing one frees a slot.
	g.Done()
	if r := g.Admit(udp("192.0.2.1", 2001)); r != Admitted {
		t.Errorf("after Done, admit = %v, want Admitted", r)
	}
}

// The reservation must be released on every path, or the cap becomes a slow
// leak that looks exactly like a sustained attack.
func TestGateDoneIsBalanced(t *testing.T) {
	g, _ := newTestGate(AdmissionConfig{MaxHalfOpen: 2, PerSourceRate: 1000, PerSourceBurst: 1000})

	g.Admit(udp("192.0.2.1", 1000))
	g.Admit(udp("192.0.2.1", 1001))
	if got := g.HalfOpen(); got != 2 {
		t.Fatalf("HalfOpen = %d, want 2", got)
	}
	g.Done()
	g.Done()
	if got := g.HalfOpen(); got != 0 {
		t.Errorf("HalfOpen = %d, want 0", got)
	}

	// Over-releasing must not underflow into free capacity.
	g.Done()
	if got := g.HalfOpen(); got != 0 {
		t.Errorf("HalfOpen after extra Done = %d, want 0", got)
	}
}

// One hostile source must not be able to consume the whole cap, or a single host
// denies service to everyone else.
func TestGateRateLimitsOneSource(t *testing.T) {
	g, _ := newTestGate(AdmissionConfig{
		MaxHalfOpen: 1000, PerSourceRate: 10, PerSourceBurst: 5,
	})

	var admitted int
	for range 50 {
		if g.Admit(udp("192.0.2.66", 9999)) == Admitted {
			admitted++
			g.Done()
		}
	}
	if admitted != 5 {
		t.Errorf("burst admitted %d handshakes, want 5", admitted)
	}

	// A different source is unaffected: the limit is per-source, not global.
	if r := g.Admit(udp("198.51.100.9", 1234)); r != Admitted {
		t.Errorf("an unrelated source was rejected: %v", r)
	}
}

// Tokens refill over time, so a client that retransmits an unanswered handshake
// -- which is normal on a lossy link -- is not mistaken for an attack.
func TestGateRefillsOverTime(t *testing.T) {
	g, clk := newTestGate(AdmissionConfig{
		MaxHalfOpen: 1000, PerSourceRate: 10, PerSourceBurst: 2,
	})
	peer := udp("192.0.2.5", 4242)

	for range 2 {
		if g.Admit(peer) != Admitted {
			t.Fatal("burst should have been admitted")
		}
		g.Done()
	}
	if g.Admit(peer) != RejectedRateLimited {
		t.Fatal("expected the third attempt to be rate limited")
	}

	clk.add(time.Second) // 10 tokens/s, capped at a burst of 2
	for range 2 {
		if r := g.Admit(peer); r != Admitted {
			t.Errorf("after refill, admit = %v, want Admitted", r)
		}
		g.Done()
	}
}

// The limiter's own bookkeeping must be bounded, or it becomes the unbounded
// allocation it exists to prevent -- a scan from many source addresses would
// otherwise grow the map without limit.
func TestGateEvictsIdleSources(t *testing.T) {
	g, clk := newTestGate(AdmissionConfig{MaxHalfOpen: 100_000, PerSourceRate: 1000, PerSourceBurst: 1000})

	for i := range 500 {
		g.Admit(udp("192.0.2."+itoa(i%256), 1000+i))
		g.Done()
	}

	g.mu.Lock()
	before := len(g.sources)
	g.mu.Unlock()
	if before == 0 {
		t.Fatal("no sources were tracked")
	}

	// Go quiet past the idle timeout, then touch the gate once so eviction runs.
	clk.add(2 * sourceIdleTimeout)
	g.Admit(udp("203.0.113.1", 1))
	g.Done()

	g.mu.Lock()
	after := len(g.sources)
	g.mu.Unlock()
	if after >= before {
		t.Errorf("idle sources were not evicted: %d before, %d after", before, after)
	}
}

func TestGateZeroConfigUsesDefaults(t *testing.T) {
	g := NewGate(AdmissionConfig{})
	if g.cfg.MaxHalfOpen != DefaultMaxHalfOpen ||
		g.cfg.PerSourceRate != DefaultPerSourceRate ||
		g.cfg.PerSourceBurst != DefaultPerSourceBurst {
		t.Errorf("zero config did not pick up defaults: %+v", g.cfg)
	}
	if g.Admit(udp("192.0.2.1", 1)) != Admitted {
		t.Error("a default gate rejected the first handshake")
	}
}

// itoa avoids pulling strconv into a test file for one call.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
