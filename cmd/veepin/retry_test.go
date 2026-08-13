package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/xen0bit/veepin/client"
)

func testRand() *rand.Rand { return rand.New(rand.NewPCG(1, 2)) }

// The delay doubles and then stops doubling. Without the cap a client that has
// been retrying for an hour waits hours; without the growth it hammers a server
// that is refusing connections.
func TestBackoffDoublesThenCaps(t *testing.T) {
	rnd := testRand()
	// Nominal values are 1s, 2s, 4s ... capped at 60s; the jitter keeps each
	// draw in [nominal/2, nominal].
	for _, tc := range []struct {
		n      int
		lo, hi time.Duration
	}{
		{1, 500 * time.Millisecond, time.Second},
		{2, time.Second, 2 * time.Second},
		{3, 2 * time.Second, 4 * time.Second},
		{6, 16 * time.Second, 32 * time.Second},
		// Nominal 64s here, which the cap pulls down to 60s -- so the band is
		// the capped one from this attempt on, not 2^6.
		{7, 30 * time.Second, 60 * time.Second},
		{20, 30 * time.Second, 60 * time.Second},
		{100, 30 * time.Second, 60 * time.Second},
	} {
		t.Run(fmt.Sprint(tc.n), func(t *testing.T) {
			for range 200 {
				d := backoff(tc.n, rnd)
				if d < tc.lo || d > tc.hi {
					t.Fatalf("backoff(%d) = %v, want within [%v, %v]", tc.n, d, tc.lo, tc.hi)
				}
			}
		})
	}
}

// The jitter is half-and-half, not full: a draw that comes up small must not
// turn backoff into a tight loop. The floor is what guarantees that, and it is
// the property a "0 to nominal" jitter would lose.
func TestBackoffNeverFallsBelowHalfTheNominalDelay(t *testing.T) {
	rnd := testRand()
	for range 1000 {
		if d := backoff(1, rnd); d < retryMinDelay/2 {
			t.Fatalf("backoff(1) = %v, below the %v floor", d, retryMinDelay/2)
		}
	}
}

// A fleet re-dialling a restarted server in lockstep is the failure the whole
// mechanism exists not to make worse, so the delay has to actually vary.
func TestBackoffIsJittered(t *testing.T) {
	rnd := testRand()
	seen := map[time.Duration]bool{}
	for range 100 {
		seen[backoff(5, rnd)] = true
	}
	if len(seen) < 10 {
		t.Errorf("backoff(5) produced %d distinct delays in 100 draws; it is not jittered", len(seen))
	}
}

// The one that matters most. A wrong password retried with backoff is a lockout
// on any server that counts failures, and client.ErrAuth exists precisely so a
// caller can tell that case apart.
func TestPermanentStopsOnARejectedCredential(t *testing.T) {
	wrapped := fmt.Errorf("ikev2: handshake: %w", client.ErrAuth)
	if !permanent(wrapped) {
		t.Error("a wrapped ErrAuth is not treated as permanent; retrying it locks the account out")
	}
	if !permanent(client.ErrUnknownProtocol) {
		t.Error("an unknown protocol is not permanent; no amount of waiting adds a blank import")
	}
}

// Everything else is worth another try: a dropped carrier, a refused
// connection, a peer that went away. Treating these as permanent is the bug
// being fixed, so the test states it from that side.
func TestPermanentDoesNotStopOnATransportFailure(t *testing.T) {
	for _, err := range []error{
		errors.New("dial udp 192.0.2.1:500: connect: network is unreachable"),
		errors.New("read: connection reset by peer"),
		context.DeadlineExceeded,
		errors.New("ikev2: no response to IKE_SA_INIT"),
	} {
		if permanent(err) {
			t.Errorf("%v treated as permanent; a recoverable outage becomes a permanent one", err)
		}
	}
}

// A Ctrl-C during a sixty-second backoff has to exit now, not in sixty seconds.
func TestSleepCtxReturnsImmediatelyOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if sleepCtx(ctx, time.Minute) {
		t.Error("sleepCtx reported it slept the full minute on a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("sleepCtx took %v to notice a cancelled context", elapsed)
	}
}

func TestSleepCtxSleepsWhenNotCancelled(t *testing.T) {
	if !sleepCtx(context.Background(), 10*time.Millisecond) {
		t.Error("sleepCtx reported a cancellation that did not happen")
	}
}

// The attempt counter is only shown when it is bounded. "attempt 3 of 0" is
// worse than saying nothing.
func TestAttemptsLeftIsSilentWhenUnbounded(t *testing.T) {
	if got := attemptsLeft(3, 0); got != "" {
		t.Errorf("attemptsLeft(3, 0) = %q, want empty", got)
	}
	if got := attemptsLeft(3, 5); got != " (attempt 3 of 5)" {
		t.Errorf("attemptsLeft(3, 5) = %q", got)
	}
}

// Retry is on by default, because a VPN client that gives up on the first blip
// is not a VPN client. This pins the default rather than the mechanism: it is
// the decision most likely to be quietly reversed by someone finding the
// retries inconvenient in a test.
func TestRetryIsOnByDefault(t *testing.T) {
	fs := newTestFlagSet()
	n := bindNetFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if !n.retry {
		t.Error("-retry defaults to false; a dropped tether ends the tunnel for good")
	}
	if n.retryMax != 0 {
		t.Errorf("-retry-max defaults to %d, want 0 (unbounded)", n.retryMax)
	}
}
