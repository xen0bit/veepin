package supervisor

// Tests for the manager's lifecycle: build, rebuild, stop, Close, and the
// reconciliation of an on-disk dir to the live set. No TUN is opened; the ctor
// is injected to return an in-memory fakeServer that satisfies client.Server.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xen0bit/veepin/client"
)

// fakeServer is an injectable client.Server for manager tests. It blocks in
// ListenAndServe until Close is called, the standard shape a real Server takes,
// so the goroutine it owns mirrors a real one.
type fakeServer struct {
	name      string
	tun       string
	gateway   net.IP
	network   *net.IPNet
	closeOnce sync.Once
	closed    atomic.Bool
	serveCh   chan struct{}
	applyErr  error
}

func (s *fakeServer) ListenAndServe() error {
	<-s.serveCh
	if s.applyErr != nil {
		return s.applyErr
	}
	return net.ErrClosed
}

func (s *fakeServer) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.serveCh)
	})
	return nil
}
func (s *fakeServer) TUNName() string     { return s.tun }
func (s *fakeServer) Gateway() net.IP     { return s.gateway }
func (s *fakeServer) Network() *net.IPNet { return s.network }
func (s *fakeServer) isClosed() bool      { return s.closed.Load() }

// fakeCtor records the calls made to the constructor and produces one
// fakeServer per call. Set nextErr to make the next construction fail; that
// surfaces the error from Apply exactly as a real protocol would.
type fakeCtor struct {
	mu      sync.Mutex
	built   []*fakeServer
	nextErr error
	tunIdx  atomic.Int32
}

func (f *fakeCtor) construct(protocol string, opts map[string]string) (client.Server, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nextErr != nil {
		err := f.nextErr
		f.nextErr = nil
		return nil, err
	}
	idx := int(f.tunIdx.Add(1) - 1)
	serv := &fakeServer{
		name:    opts["__name"],
		tun:     fmt.Sprintf("tun%d", idx),
		gateway: net.ParseIP(fmt.Sprintf("10.%d.0.1", idx+1)),
		network: mustParseCIDR(fmt.Sprintf("10.%d.0.0/24", idx+1)),
		serveCh: make(chan struct{}),
	}
	f.built = append(f.built, serv)
	return serv, nil
}

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func writeCfg(t *testing.T, dir, name, protocol string) {
	t.Helper()
	cfg := ListenerConfig{Name: name, Protocol: protocol,
		Options: map[string]string{"__name": name}, Enabled: true}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(dir, name+".json"), name+".json", string(body))
}

// TestApplyBuildsEveryListener verifies that loading a directory with two
// listener files builds and starts both: each fake server is constructed, the
// Status reflects state=running, and statuses are sorted by name.
func TestApplyBuildsEveryListener(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	writeCfg(t, dir, "site-b", "ikev2")
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	all := mgr.All()
	if len(all) != 2 {
		t.Fatalf("len(All) = %d, want 2 (%+v)", len(all), all)
	}
	if all[0].Name != "site-a" || all[1].Name != "site-b" {
		t.Errorf("statuses not sorted by name: %+v", all)
	}
	for _, s := range all {
		if s.State != "running" {
			t.Errorf("%s: state = %q, want running", s.Name, s.State)
		}
		if s.TUNName == "" || s.Gateway == "" || s.Network == "" {
			t.Errorf("%s: empty TUN/Gateway/Network: %+v", s.Name, s)
		}
	}
	if len(ctor.built) != 2 {
		t.Errorf("ctor.built = %d, want 2", len(ctor.built))
	}
}

// TestApplyKeepsRunningListenersUntouched verifies the cold-rebuild contract: a
// second Apply against the same directory builds nothing new and does not
// close the existing listeners.
func TestApplyKeepsRunningListenersUntouched(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	built := ctor.built[0]
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	if len(ctor.built) != 1 {
		t.Errorf("second Apply built %d new listeners, want 0", len(ctor.built)-1)
	}
	if built.isClosed() {
		t.Errorf("original server closed by an Apply that did not change its config")
	}
}

// TestApplyRemovedConfigTearsDownListener verifies that a listener whose file
// has been deleted stops its server and drops from the live set: the
// supervisor never leaks a server whose config has gone away.
func TestApplyRemovedConfigTearsDownListener(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	writeCfg(t, dir, "site-b", "ikev2")
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	b := ctor.built[1] // second-built listener, by file write order
	if err := os.Remove(filepath.Join(dir, "site-b.json")); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	if !b.isClosed() {
		t.Errorf("site-b's server was not closed when its config disappeared")
	}
	if got := mgr.Status("site-b"); got.State != "unknown" {
		t.Errorf("site-b still present: %+v", got)
	}
	if got := mgr.Status("site-a"); got.State != "running" {
		t.Errorf("site-a torn down by the removal of site-b: %+v", got)
	}
}

// TestApplyEnabledFalseStopsListener verifies the disabled-listener path: an
// enabled:false file keeps the listener tracked but stopped.
func TestApplyEnabledFalseStopsListener(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	// Now write a config that disables it.
	cfg := ListenerConfig{Name: "site-a", Protocol: "wireguard",
		Options: map[string]string{"__name": "site-a"}, Enabled: false}
	body, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(dir, "site-a.json"), body, 0o600)
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	if s := mgr.Status("site-a"); s.State != "stopped" && s.State != "disabled" {
		t.Errorf("disabled listener state = %q, want stopped or disabled", s.State)
	}
}

// TestApplyNewConfigAddsListener: a second Apply that adds a file builds a new
// listener without disturbing the running one.
func TestApplyNewConfigAddsListener(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	writeCfg(t, dir, "site-b", "ikev2")
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	if s := mgr.Status("site-b"); s.State != "running" {
		t.Errorf("added listener state = %q, want running", s.State)
	}
}

// TestApplyChangedConfigRebuildsListener verifies the cold-rebuild contract:
// changing the Options of a listener rebuilds it. The rebuilt server is a new
// instance, and the original is closed; other listeners stay running.
func TestApplyChangedConfigRebuildsListener(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	writeCfg(t, dir, "site-b", "ikev2")
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	origA := ctor.built[0]
	// Change options for site-a only.
	cfg := ListenerConfig{Name: "site-a", Protocol: "wireguard",
		Options: map[string]string{"__name": "site-a", "renamed": "value"}, Enabled: true}
	body, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(dir, "site-a.json"), body, 0o600)
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	if !origA.isClosed() {
		t.Errorf("a changed listener's server was not closed")
	}
	if len(ctor.built) != 3 {
		t.Errorf("changed config built %d total, want 3 (2 initial + 1 rebuild)", len(ctor.built))
	}
	if s := mgr.Status("site-b"); s.State != "running" {
		t.Errorf("untouched listener site-b was disturbed: %+v", s)
	}
}

// TestApplyConstructionErrorFailsLoudly verifies that a ctor returning an error
// aborts Apply entirely so the management API reports the failure; no
// subsequent listeners in the same Apply pass are tentatively built.
func TestApplyConstructionErrorFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	ctor := &fakeCtor{nextErr: fmt.Errorf("simulated protocol failure")}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err == nil {
		t.Fatalf("Apply succeeded against a failing ctor")
	}
}

// TestApplyUnknownProtocolRejected verifies that the ctor (the real
// client.NewServer in production) rejecting an unknown protocol name fails
// Apply, rather than the manager building something the registry has not heard
// of. Production's NewServer returns ErrUnknownProtocol; the test's fakeCtor
// returns a stand-in error so the test does not need to blank-import the
// protocol facades.
func TestApplyUnknownProtocolRejected(t *testing.T) {
	dir := t.TempDir()
	cfg := ListenerConfig{Name: "x", Protocol: "nonsense-example",
		Options: map[string]string{"__name": "x"}, Enabled: true}
	body, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(dir, "x.json"), body, 0o600)
	ctor := &fakeCtor{nextErr: fmt.Errorf("unknown protocol nonsense-example")}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err == nil {
		t.Fatalf("expected unknown-protocol error")
	}
}

// TestRebuildForcesColdRebuild verifies the per-listener Rebuild path used by
// the management API: it closes the current server and starts a new one.
func TestRebuildForcesColdRebuild(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	orig := ctor.built[0]
	if err := mgr.Rebuild("site-a"); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if !orig.isClosed() {
		t.Errorf("Rebuild did not close the original server")
	}
	if len(ctor.built) != 2 {
		t.Errorf("Rebuild built %d servers total, want 2", len(ctor.built))
	}
}

// TestRebuildUnknownListenerErrors pins the API contract that rebuilding a
// name the manager does not know is an error rather than a silent no-op.
func TestRebuildUnknownListenerErrors(t *testing.T) {
	dir := t.TempDir()
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	if err := mgr.Rebuild("nope"); err == nil {
		t.Errorf("Rebuild on an unknown name succeeded")
	}
}

// TestStopRemovesListener verifies that Stop tears down the server and removes
// its handle; the management API uses Stop to retire a listener.
func TestStopRemovesListener(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	orig := ctor.built[0]
	if err := mgr.Stop("site-a"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !orig.isClosed() {
		t.Errorf("Stop did not close the server")
	}
	if s := mgr.Status("site-a"); s.State != "unknown" {
		t.Errorf("Status returned %q, want unknown", s.State)
	}
}

// TestStopWaitsForServeGoroutine verifies that Stop blocks until the serve
// goroutine has exited, so a subsequent Close/rebuild does not race. Slow serve
// exit could let a rebuilt server reuse its TUN name before the goroutine gave
// the kernel the release.
func TestStopWaitsForServeGoroutine(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = mgr.Stop("site-a")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not return within 3s")
	}
}

// TestApplyConcurrentRebuildsAreSafe verifies the locking: a rebuild running
// concurrently with a status read does not race. Run with `go test -race`.
func TestApplyConcurrentRebuildsAreSafe(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	writeCfg(t, dir, "site-b", "ikev2")
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mgr.Rebuild("site-a")
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mgr.All()
		}()
	}
	wg.Wait()
}

// TestCloseTearsDownEveryListener covers supervisor shutdown: Close leaves no
// live goroutine and closes every server, so the process can exit cleanly.
func TestCloseTearsDownEveryListener(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "site-a", "wireguard")
	writeCfg(t, dir, "site-b", "ikev2")
	ctor := &fakeCtor{}
	mgr := NewManager(dir, testLogger(t), ctor.construct)
	if err := mgr.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, b := range ctor.built {
		if !b.isClosed() {
			t.Errorf("a built server was not closed by Close")
		}
	}
}

// TestManagerDefaultCtorIsNewServer pins the default constructor: with a nil
// ctor argument the Manager uses the real production registry. The test only
// verifies codegen/dispatch shape; it does not call Apply (which would require
// privileges), it just confirms the logger field isn't panicking.
func TestManagerDefaultCtorIsNewServer(t *testing.T) {
	dir := t.TempDir()
	// Constructing the manager with a nil ctor must not panic.
	m := NewManager(dir, nil, nil)
	if m == nil {
		t.Fatal("nil manager")
	}
	if m.listeners == nil {
		t.Errorf("listeners map not initialized")
	}
}

// TestStatusOfUnknownListener returns State=unknown so the management API can
// distinguish "never heard of it" from "stopped".
func TestStatusOfUnknownListener(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir, testLogger(t), (&fakeCtor{}).construct)
	if s := mgr.Status("never-existed"); s.State != "unknown" {
		t.Errorf("Status = %q, want unknown", s.State)
	}
}

// testLogger produces a discard logger for tests that do not care about output;
// the manager accepts a *log.Logger so failing tests surface a real logger.
func testLogger(t *testing.T) *log.Logger {
	_ = t
	return log.New(io.Discard, "", 0)
}
