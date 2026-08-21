//go:build linux

package harden

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestNoCoreDumpsActuallyTakesEffect reads the result back out of the kernel
// rather than trusting the syscall's return.
//
// It runs in a subprocess because PR_SET_DUMPABLE is irreversible in the
// direction that matters for a test suite: clearing it makes /proc/self
// root-owned, and a later test in the same process that reads its own /proc
// entries -- the abandoned-fd guard in internal/supervisor, for one -- would
// then fail for reasons having nothing to do with what it is testing.
func TestNoCoreDumpsActuallyTakesEffect(t *testing.T) {
	if os.Getenv("VEEPIN_HARDEN_CHILD") == "1" {
		if _, err := Apply(Options{NoCoreDumps: true}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		got, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_GET_DUMPABLE, 0, 0)
		if errno != 0 {
			t.Fatalf("PR_GET_DUMPABLE: %v", errno)
		}
		if got != 0 {
			t.Fatalf("PR_GET_DUMPABLE = %d after Apply, want 0; the process is still dumpable "+
				"and a crash would write session keys into a core file", got)
		}
		return
	}
	runInChild(t, "TestNoCoreDumpsActuallyTakesEffect")
}

// TestLockMemoryReportsItsFailureRatherThanPretending is the claim this package
// is built around: a hardening switch that silently does nothing is worse than
// no switch, because the appearance invites confidence the process has not
// earned.
//
// mlockall needs CAP_IPC_LOCK or RLIMIT_MEMLOCK headroom, and CI has neither
// reliably -- so rather than skipping on the interesting case, the child drops
// RLIMIT_MEMLOCK to zero and requires the failure to be reported. Whichever way
// the environment falls, one of the two branches is exercised.
func TestLockMemoryReportsItsFailureRatherThanPretending(t *testing.T) {
	if os.Getenv("VEEPIN_HARDEN_CHILD") == "1" {
		zero := unix.Rlimit{Cur: 0, Max: 0}
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &zero); err != nil {
			t.Skipf("cannot lower RLIMIT_MEMLOCK: %v", err)
		}
		applied, err := Apply(Options{LockMemory: true, NoCoreDumps: true})
		if err == nil {
			t.Fatal("mlockall succeeded with RLIMIT_MEMLOCK at zero, which it cannot have")
		}
		if !strings.Contains(err.Error(), "mlockall") {
			t.Errorf("error = %q, want it to name mlockall so an operator knows which switch failed", err)
		}
		if !strings.Contains(err.Error(), "CAP_IPC_LOCK") {
			t.Errorf("error = %q, want it to name the capability or limit that would fix it", err)
		}
		// And nothing after the failure was applied: a caller that asked for
		// both wanted both, and reporting "core dumps disabled" past a refused
		// mlockall is the partial success this package refuses to report.
		for _, a := range applied {
			if strings.Contains(a, "core dumps") {
				t.Error("core-dump hardening was reported as applied after mlockall failed")
			}
		}
		return
	}
	runInChild(t, "TestLockMemoryReportsItsFailureRatherThanPretending")
}

// runInChild re-executes the test binary for one test with the child marker set.
func runInChild(t *testing.T, name string) {
	t.Helper()
	out, err := runSelf(t, name)
	if err != nil {
		t.Fatalf("child %s failed: %v\n%s", name, err, out)
	}
	if strings.Contains(out, "--- FAIL") {
		t.Fatalf("child %s reported failures:\n%s", name, out)
	}
}
