package supervisor

// The tests elsewhere in this package inject a fake constructor, so they cover
// the manager's lifecycle without ever touching client.NewServer, the registry,
// or a protocol's parse function. These two cover that seam, from either side of
// the privilege line.
//
// Opening a TUN needs CAP_NET_ADMIN, which an ordinary `go test` does not have.
// That is not a reason to leave the seam untested: the interesting half of it --
// registry lookup, option parsing, and what the manager does when construction
// fails -- happens before any TUN is opened, and runs anywhere. The other half
// runs when the suite is run with the capability and says so when it is skipped,
// rather than passing quietly on a code path it never entered.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/dataplane"

	// The real registry, via the same facade import the binary uses. Without it
	// NewServer would reject "toy" as unknown and the tests below would pass
	// against a registry that has never heard of any protocol.
	_ "github.com/xen0bit/veepin/toy"
)

// toyListener is a listener config for the worked-example protocol: the smallest
// real server in the tree, and the one whose options are stable enough to hard
// code. It is never given traffic here -- internal/toy is deliberately insecure
// and must not carry any -- only started and stopped.
func toyListener(name string, port int) ListenerConfig {
	return ListenerConfig{
		Name:     name,
		Protocol: "toy",
		Options: map[string]string{
			"listen": "127.0.0.1",
			"port":   itoa(port),
			"pool":   "10.99.0.0/24",
			"user":   "u",
			"secret": "s",
		},
		Enabled: true,
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func writeListener(t *testing.T, dir string, cfg ListenerConfig) {
	t.Helper()
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cfg.Name+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// tunAvailable reports whether this process can open a TUN. Used to choose which
// of the two assertions below applies, so the same test file is meaningful with
// and without the capability.
func tunAvailable(t *testing.T) bool {
	t.Helper()
	tun, err := dataplane.OpenTUN("")
	if err != nil {
		return false
	}
	_ = tun.Close()
	return true
}

// TestRealConstructorReachesTheRegistry drives the manager with its production
// constructor -- no fake -- and a real listener file. It asserts the seam the
// fake-ctor tests cannot: that a config file's protocol name and option map
// reach client.NewServer and the facade's parse function intact.
//
// Whether the build then succeeds depends on CAP_NET_ADMIN, and both outcomes
// are pinned. Unprivileged, the TUN open fails and the listener must land in
// "error" state naming that -- tracked and explained rather than crashed or
// vanished. Privileged, it must be running.
func TestRealConstructorReachesTheRegistry(t *testing.T) {
	dir := t.TempDir()
	writeListener(t, dir, toyListener("site-a", 55550))

	// nil ctor is the production path: client.NewServer.
	mgr := NewManager(dir, testLogger(t), nil)
	t.Cleanup(func() { _ = mgr.Close() })
	err := mgr.Apply()

	s := mgr.Status("site-a")
	if tunAvailable(t) {
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if s.State != "running" {
			t.Errorf("state = %q, want running: %+v", s.State, s)
		}
		if s.TUNName == "" {
			t.Errorf("a running listener reported no TUN: %+v", s)
		}
		return
	}

	if err == nil {
		t.Fatal("Apply succeeded without CAP_NET_ADMIN; the TUN open should have failed")
	}
	if s.State != "error" {
		t.Errorf("state = %q, want error -- a listener that cannot build must stay "+
			"tracked and say why: %+v", s.State, s)
	}
	// The reason must survive from the syscall all the way out to the API's view.
	// An "error" state with an empty or generic message is what sends an operator
	// to the logs of a process that may not be writing any.
	if !strings.Contains(s.Error, "CAP_NET_ADMIN") {
		t.Errorf("status error does not name the cause: %q", s.Error)
	}
}

// TestRealListenerServesAndStops runs an actual server through the whole
// supervisor path -- construct, ListenAndServe on a real socket, Stop -- which
// is the part no fake can stand in for. It needs CAP_NET_ADMIN and skips
// loudly without it.
func TestRealListenerServesAndStops(t *testing.T) {
	if !tunAvailable(t) {
		t.Skip("needs CAP_NET_ADMIN to open a TUN; run the suite as root or with " +
			"setcap to cover the real-listener path")
	}
	dir := t.TempDir()
	writeListener(t, dir, toyListener("site-a", 55551))
	writeListener(t, dir, toyListener("site-b", 55552))

	mgr := NewManager(dir, testLogger(t), nil)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, name := range []string{"site-a", "site-b"} {
		s := mgr.Status(name)
		if s.State != "running" {
			t.Fatalf("%s: state = %q, want running: %+v", name, s.State, s)
		}
	}

	// A rebuild closes the old socket and binds a new one on the same port. If
	// the teardown did not actually release it, the rebuild fails with "address
	// already in use" -- which is the whole reason stopLocked waits for the serve
	// goroutine rather than just closing and moving on.
	if err := mgr.Rebuild("site-a"); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if s := mgr.Status("site-a"); s.State != "running" {
		t.Errorf("after rebuild: state = %q, want running: %+v", s.State, s)
	}
	if s := mgr.Status("site-b"); s.State != "running" {
		t.Errorf("site-b disturbed by site-a's rebuild: %+v", s)
	}

	if err := mgr.Stop("site-a"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if s := mgr.Status("site-a"); s.State != "unknown" {
		t.Errorf("after Stop: state = %q, want unknown", s.State)
	}
}
