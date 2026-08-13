package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/xen0bit/veepin/client"
)

// Reconnection.
//
// client.Dial attaches a liveness monitor to every protocol that implements
// client.Prober; the monitor detects a dead peer and ends the session. Nothing
// then re-dialled, so the cross-protocol liveness work converted a recoverable
// event into a permanent one: a laptop changing Wi-Fi networks, a tether that
// drops for four seconds, a server that restarts -- each ended the tunnel for
// good, and the user found out later.
//
// A VPN client that gives up on the first blip is not a VPN client, so this is
// on by default. -retry=false is for the person scripting it.

const (
	// retryMinDelay is the first wait. Short enough that a four-second tether
	// drop costs a four-second outage rather than a minute of one.
	retryMinDelay = time.Second
	// retryMaxDelay caps the growth. A server that has been down for an hour is
	// not helped by hourly attempts, and a client that keeps trying every
	// minute reconnects promptly when it comes back.
	retryMaxDelay = 60 * time.Second
	// retrySettled is how long a session must stay up to count as working. Past
	// it the backoff resets, so an hour-old tunnel that drops retries in one
	// second rather than in whatever the last outage escalated to.
	retrySettled = 60 * time.Second
)

// backoff returns the wait before attempt n (1 = the first retry), jittered.
//
// The jitter is half-and-half rather than full: the delay is never less than
// half the nominal, so a client whose random draw comes up small does not turn
// backoff into a tight loop against a server that is refusing connections. The
// randomised half is what keeps a fleet of clients from re-dialling a restarted
// server in lockstep, which is the failure the whole mechanism exists to avoid
// making worse.
func backoff(n int, rnd *rand.Rand) time.Duration {
	if n < 1 {
		n = 1
	}
	d := retryMinDelay
	for range n - 1 {
		d *= 2
		if d >= retryMaxDelay {
			d = retryMaxDelay
			break
		}
	}
	half := d / 2
	return half + time.Duration(rnd.Int64N(int64(half)+1))
}

// permanent reports whether an error means "stop", so that retrying it would be
// harmful rather than merely useless.
//
// client.ErrAuth is the one that matters. A wrong password retried with backoff
// is a lockout on any server that counts failures, and the error type that
// distinguishes it exists precisely so callers can tell. ErrUnknownProtocol is
// a missing blank import: no amount of waiting adds one.
func permanent(err error) bool {
	return errors.Is(err, client.ErrAuth) || errors.Is(err, client.ErrUnknownProtocol)
}

// sleepCtx waits for d or until ctx ends, reporting false if ctx ended first.
// A Ctrl-C during a 60-second backoff must exit now, not in 60 seconds.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// attemptsLeft renders the remaining-attempt count for a log line, or the empty
// string when the count is unbounded. Split out because the sentence reads
// badly either way if the two cases are one format string.
func attemptsLeft(attempt, max int) string {
	if max <= 0 {
		return ""
	}
	return fmt.Sprintf(" (attempt %d of %d)", attempt, max)
}
