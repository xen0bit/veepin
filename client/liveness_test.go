package client

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSession is a Session whose Wait blocks until Close (or the context ends).
// It optionally implements Prober and LivenessTuner.
type fakeSession struct {
	done      chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool

	probe func(context.Context) error // nil ⇒ does not implement Prober
	cfg   *LivenessConfig             // non-nil ⇒ implements LivenessTuner
}

func newFakeSession() *fakeSession { return &fakeSession{done: make(chan struct{})} }

func (f *fakeSession) Wait(ctx context.Context) error {
	select {
	case <-f.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakeSession) Close() error {
	f.closeOnce.Do(func() { f.closed.Store(true); close(f.done) })
	return nil
}

// proberSession embeds fakeSession and implements Prober.
type proberSession struct {
	*fakeSession
	probes atomic.Int64
}

func (p *proberSession) Probe(ctx context.Context) error {
	p.probes.Add(1)
	return p.probe(ctx)
}

// tunedProber additionally implements LivenessTuner.
type tunedProber struct{ *proberSession }

func (t *tunedProber) LivenessConfig() LivenessConfig { return *t.cfg }

func TestMonitorLeavesNonProberUnwrapped(t *testing.T) {
	s := newFakeSession()
	if got := monitor(s); got != s {
		t.Fatalf("a non-Prober session was wrapped: %T", got)
	}
}

func TestMonitorTearsDownAfterConsecutiveFailures(t *testing.T) {
	base := newFakeSession()
	base.probe = func(context.Context) error { return errors.New("dead") }
	base.cfg = &LivenessConfig{Interval: 5 * time.Millisecond, Timeout: 5 * time.Millisecond, MaxFailures: 3}
	ps := &proberSession{fakeSession: base}
	sess := monitor(&tunedProber{ps})

	// Wait should return once the monitor gives up and closes the session.
	waitErr := make(chan error, 1)
	go func() { waitErr <- sess.Wait(context.Background()) }()

	select {
	case err := <-waitErr:
		if err != nil {
			t.Fatalf("Wait returned %v, want nil after monitored teardown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("monitor never tore down a persistently failing session")
	}
	if !base.closed.Load() {
		t.Fatal("underlying session was not closed")
	}
	if got := ps.probes.Load(); got < 3 {
		t.Fatalf("only %d probes before teardown, want at least MaxFailures=3", got)
	}
}

func TestMonitorKeepsHealthySessionUp(t *testing.T) {
	base := newFakeSession()
	base.probe = func(context.Context) error { return nil } // always healthy
	base.cfg = &LivenessConfig{Interval: 2 * time.Millisecond, Timeout: 5 * time.Millisecond, MaxFailures: 3}
	ps := &proberSession{fakeSession: base}
	sess := monitor(&tunedProber{ps})

	// The session must still be up after many probe intervals.
	time.Sleep(80 * time.Millisecond)
	if base.closed.Load() {
		t.Fatal("monitor tore down a healthy session")
	}
	if got := ps.probes.Load(); got < 5 {
		t.Fatalf("healthy session probed only %d times; monitor may not be running", got)
	}

	// Closing the wrapper stops the monitor and closes the session.
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !base.closed.Load() {
		t.Fatal("Close did not close the underlying session")
	}
}

func TestMonitorRecoversFromTransientFailures(t *testing.T) {
	base := newFakeSession()
	var n atomic.Int64
	// Fail twice, then succeed forever — must never reach MaxFailures=3 in a row.
	base.probe = func(context.Context) error {
		if n.Add(1) <= 2 {
			return errors.New("transient")
		}
		return nil
	}
	base.cfg = &LivenessConfig{Interval: 2 * time.Millisecond, Timeout: 5 * time.Millisecond, MaxFailures: 3}
	ps := &proberSession{fakeSession: base}
	monitor(&tunedProber{ps})

	time.Sleep(80 * time.Millisecond)
	if base.closed.Load() {
		t.Fatal("transient failures followed by recovery tore the session down")
	}
}

func TestLivenessConfigDefaults(t *testing.T) {
	got := LivenessConfig{}.withDefaults()
	if got != DefaultLivenessConfig {
		t.Fatalf("zero config = %+v, want defaults %+v", got, DefaultLivenessConfig)
	}
	// A partially-set config keeps its non-zero fields.
	partial := LivenessConfig{Interval: 42 * time.Second}.withDefaults()
	if partial.Interval != 42*time.Second {
		t.Fatalf("override lost: Interval = %v", partial.Interval)
	}
	if partial.Timeout != DefaultLivenessConfig.Timeout || partial.MaxFailures != DefaultLivenessConfig.MaxFailures {
		t.Fatalf("partial config did not fill defaults: %+v", partial)
	}
}
