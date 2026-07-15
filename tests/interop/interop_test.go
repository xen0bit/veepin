//go:build interop

// Docker-based interoperability tests: they stand up ikennkt and strongSwan in
// containers and prove a real ESP-in-UDP tunnel by pinging across it, in both
// directions. Run with `make interop` or `go test -tags interop ./tests/interop/`.
//
// These shell out to `docker compose`; they are stdlib-only (no new module
// dependency) and skip cleanly where Docker is unavailable.
package interop

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// pingDeadline bounds how long we retry the cross-tunnel ping. It must cover
// image build, container start, the client's connect-retry loop, and (for
// strongSwan) charon startup.
const pingDeadline = 100 * time.Second

// TestInteropSelf is the infra sanity check: ikennkt client <-> ikennkt server.
// It isolates the container/TUN/NAT-T/ping harness from strongSwan.
func TestInteropSelf(t *testing.T) {
	runInterop(t, "compose.selftest.yml", "client", "10.10.10.1")
}

// TestInteropIkennktClientStrongswanServer is Direction A: the ikennkt client
// (ikev2) tunnels to a strongSwan responder and pings a strongSwan-side address.
func TestInteropIkennktClientStrongswanServer(t *testing.T) {
	runInterop(t, "compose.client-ss.yml", "ikennkt-client", "10.20.30.254")
}

// TestInteropStrongswanClientIkennktServer is Direction B: a strongSwan
// initiator tunnels to the ikennkt server (ikev2d) and pings its TUN gateway.
func TestInteropStrongswanClientIkennktServer(t *testing.T) {
	runInterop(t, "compose.server-ss.yml", "strongswan-client", "10.10.10.1")
}

// runInterop brings up the given compose file, then retries a ping from pingSvc
// to target across the tunnel until it succeeds or pingDeadline elapses. A
// successful ping proves the full path: handshake, config-mode addressing, and
// bidirectional ESP. The stack is always torn down; logs are dumped on failure.
func runInterop(t *testing.T, composeFile, pingSvc, target string) {
	t.Helper()
	requireDocker(t)

	if out, err := compose(t, composeFile, "up", "--build", "-d"); err != nil {
		t.Fatalf("compose up: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			if logs, err := compose(t, composeFile, "logs", "--no-color"); err == nil {
				t.Logf("--- compose logs (%s) ---\n%s", composeFile, logs)
			}
		}
		_, _ = compose(t, composeFile, "down", "-v", "--timeout", "5")
	})

	deadline := time.Now().Add(pingDeadline)
	var last string
	for time.Now().Before(deadline) {
		out, err := compose(t, composeFile, "exec", "-T", pingSvc,
			"ping", "-c2", "-W2", target)
		if err == nil && strings.Contains(out, "0% packet loss") {
			t.Logf("tunnel up: %s pinged %s across the tunnel", pingSvc, target)
			return
		}
		last = out
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("cross-tunnel ping %s -> %s never succeeded within %s:\n%s",
		pingSvc, target, pingDeadline, last)
}

// compose runs `docker compose -f <file> <args...>` in the test's directory
// (which holds the compose files and their relative build contexts).
func compose(t *testing.T, file string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	full := append([]string{"compose", "-f", file}, args...)
	out, err := exec.CommandContext(ctx, "docker", full...).CombinedOutput()
	return string(out), err
}

// requireDocker skips the test unless a working Docker daemon is reachable.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not available")
	}
}
