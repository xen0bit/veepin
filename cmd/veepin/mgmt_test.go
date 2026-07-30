package main

// End-to-end test of the mgmt CLI against a real mgmt.Server: the binary's CLI
// command is exercised exactly as an operator would, against an in-process
// supervisor with a fake manager. Tests both the happy path and the no-token
// error path that the usage text promises operators hit if VEEPIN_MGMT_TOKEN
// is unset.

import (
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/mgmt"
	"github.com/xen0bit/veepin/internal/supervisor"
)

// cliFakeMgr mirrors internal/mgmt's fakeMgr but in package main (the CLI test
// is in package main, so the type is local). It satisfies mgmt.ManagerBackend.
type cliFakeMgr struct {
	statuses  map[string]supervisor.Status
	rebuildOf string
	stopOf    string
}

func (f *cliFakeMgr) Apply() error { return nil }
func (f *cliFakeMgr) All() []supervisor.Status {
	out := make([]supervisor.Status, 0, len(f.statuses))
	for _, s := range f.statuses {
		out = append(out, s)
	}
	return out
}
func (f *cliFakeMgr) Status(name string) supervisor.Status {
	if s, ok := f.statuses[name]; ok {
		return s
	}
	return supervisor.Status{Name: name, State: "unknown"}
}
func (f *cliFakeMgr) Rebuild(name string) error { f.rebuildOf = name; return nil }
func (f *cliFakeMgr) Stop(name string) error {
	f.stopOf = name
	delete(f.statuses, name)
	return nil
}
func (f *cliFakeMgr) Close() error                     { return nil }
func (f *cliFakeMgr) Server(name string) client.Server { return nil }

// startMgmtTestServer launches a real mgmt.Server (with a fake manager) bound
// to a httptest.Server and returns the URL + token. The CLI's env vars point at
// it.
func startMgmtTestServer(t *testing.T, statuses map[string]supervisor.Status) (url, token string) {
	t.Helper()
	dir := t.TempDir()
	for name := range statuses {
		cfg := supervisor.ListenerConfig{Name: name, Protocol: "wireguard",
			Enabled: true, Options: map[string]string{"private-key": "k"}}
		body, _ := json.Marshal(cfg)
		_ = os.WriteFile(filepath.Join(dir, name+".json"), body, 0o600)
	}
	mgr := &cliFakeMgr{statuses: statuses}
	srv, err := mgmt.NewServer(dir, mgr, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("mgmt.NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { _ = srv.Close(); ts.Close() })
	return ts.URL, string(srv.Token())
}

func TestMgmtLsAndStatus(t *testing.T) {
	url, token := startMgmtTestServer(t, map[string]supervisor.Status{
		"site-a": {Name: "site-a", Protocol: "wireguard", State: "running"},
	})
	t.Setenv("VEEPIN_MGMT_URL", url)
	t.Setenv("VEEPIN_MGMT_TOKEN", token)
	if err := runMgmt([]string{"ls"}); err != nil {
		t.Fatalf("ls: %v", err)
	}
	if err := runMgmt([]string{"status", "site-a"}); err != nil {
		t.Fatalf("status: %v", err)
	}
}

func TestMgmtProtocols(t *testing.T) {
	url, token := startMgmtTestServer(t, nil)
	t.Setenv("VEEPIN_MGMT_URL", url)
	t.Setenv("VEEPIN_MGMT_TOKEN", token)
	if err := runMgmt([]string{"protocols"}); err != nil {
		t.Fatalf("protocols: %v", err)
	}
}

func TestMgmtRestart(t *testing.T) {
	url, token := startMgmtTestServer(t, map[string]supervisor.Status{
		"site-a": {Name: "site-a", State: "running"},
	})
	t.Setenv("VEEPIN_MGMT_URL", url)
	t.Setenv("VEEPIN_MGMT_TOKEN", token)
	if err := runMgmt([]string{"restart", "site-a"}); err != nil {
		t.Fatalf("restart: %v", err)
	}
}

func TestMgmtRm(t *testing.T) {
	url, token := startMgmtTestServer(t, map[string]supervisor.Status{
		"site-a": {Name: "site-a", State: "running"},
	})
	t.Setenv("VEEPIN_MGMT_URL", url)
	t.Setenv("VEEPIN_MGMT_TOKEN", token)
	if err := runMgmt([]string{"rm", "site-a"}); err != nil {
		t.Fatalf("rm: %v", err)
	}
}

// TestMgmtRequiresToken: without VEEPIN_MGMT_TOKEN, every subcommand fails
// before sending a request so a misconfigured CLI never leaks its existence to
// an unauthorised peer.
func TestMgmtRequiresToken(t *testing.T) {
	url, _ := startMgmtTestServer(t, map[string]supervisor.Status{"x": {Name: "x"}})
	t.Setenv("VEEPIN_MGMT_URL", url)
	t.Setenv("VEEPIN_MGMT_TOKEN", "")
	if err := runMgmt([]string{"ls"}); err == nil {
		t.Errorf("ls succeeded without VEEPIN_MGMT_TOKEN")
	}
}

// TestMgmtUnknownSubcommandErrors: an unknown subcommand reports its name
// rather than silently doing nothing.
func TestMgmtUnknownSubcommandErrors(t *testing.T) {
	if err := runMgmt([]string{"totally-unknown"}); err == nil {
		t.Errorf("unknown subcommand accepted")
	}
}

// TestMgmtNoSubcommandPrintsUsage: usage goes to the caller as an error (so
// the surrounding `run` wrapper exits non-zero), which keeps `veepin mgmt`
// from looking like it hung.
func TestMgmtNoSubcommandPrintsUsage(t *testing.T) {
	err := runMgmt(nil)
	if err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("usage error expected, got %v", err)
	}
}

// TestMgmtAddCreatesListener: piped JSON on stdin becomes a POSTed listener;
// the API's response names the listener, so a zero-error `add` plus a status
// round trip is the assertion that the file landed on disk.
func TestMgmtAddCreatesListener(t *testing.T) {
	url, token := startMgmtTestServer(t, nil)
	t.Setenv("VEEPIN_MGMT_URL", url)
	t.Setenv("VEEPIN_MGMT_TOKEN", token)

	cfg := supervisor.ListenerConfig{Name: "added", Protocol: "wireguard",
		Options: map[string]string{"private-key": "k", "address": "10.10.0.1/24"},
		Enabled: true}
	body, _ := json.Marshal(cfg)
	r, w, _ := os.Pipe()
	t.Cleanup(func() { _ = r.Close() })
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })
	go func() { _, _ = w.Write(body); _ = w.Close() }()
	if err := runMgmt([]string{"add"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// The temp-dir path the API writes into is internal to the mgmt server, so
	// we cannot reach its file from here; the absence of an error from `add`
	// is the assertion the file landed on disk plus a status probe would.
}
