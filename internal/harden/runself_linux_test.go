//go:build linux

package harden

import (
	"os"
	"os/exec"
	"testing"
)

// runSelf re-runs this test binary for a single test with VEEPIN_HARDEN_CHILD
// set, so an irreversible process change lands in a process nothing else uses.
func runSelf(t *testing.T, name string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), "VEEPIN_HARDEN_CHILD=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}
