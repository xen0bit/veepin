package harden

import "testing"

// TestZeroOptionsApplyNothing: the zero value is the behaviour from before this
// package existed, on every platform. A caller that never asked must not be
// given an error to handle.
func TestZeroOptionsApplyNothing(t *testing.T) {
	var none Options
	if none.Any() {
		t.Error("the zero Options reports Any() = true")
	}
	applied, err := Apply(Options{})
	if err != nil {
		t.Errorf("Apply(zero) = %v, want nil", err)
	}
	if len(applied) != 0 {
		t.Errorf("Apply(zero) applied %v, want nothing", applied)
	}
}

// TestAnyReportsEachSwitchIndependently. The two protections are separable on
// purpose -- PR_SET_DUMPABLE changes who owns /proc/self, which a deployment
// that reads its own /proc entries needs to be able to decline without also
// giving up memory locking.
func TestAnyReportsEachSwitchIndependently(t *testing.T) {
	lock := Options{LockMemory: true}
	if !lock.Any() {
		t.Error("LockMemory alone reports Any() = false")
	}
	dumps := Options{NoCoreDumps: true}
	if !dumps.Any() {
		t.Error("NoCoreDumps alone reports Any() = false")
	}
}
