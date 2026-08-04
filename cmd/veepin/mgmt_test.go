package main

// End-to-end test of the mgmt CLI against a real mgmt.Server: the binary's CLI
// command is exercised exactly as an operator would, against an in-process
// supervisor with a fake manager. Tests both the happy path and the no-token
// error path that the usage text promises operators hit if VEEPIN_MGMT_TOKEN
// is unset.

import (
	"encoding/json"
	"errors"
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
	statuses   map[string]supervisor.Status
	rebuildOf  string
	stopOf     string
	rebuildErr error
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
func (f *cliFakeMgr) Rebuild(name string) error { f.rebuildOf = name; return f.rebuildErr }
func (f *cliFakeMgr) Stop(name string) error {
	f.stopOf = name
	delete(f.statuses, name)
	return nil
}
func (f *cliFakeMgr) Close() error { return nil }
func (f *cliFakeMgr) Peers(name string) ([]client.PeerInfo, supervisor.PeerAvailability) {
	if _, ok := f.statuses[name]; !ok {
		return nil, supervisor.PeersNoSuchListener
	}
	return nil, supervisor.PeersUnsupported
}

// startMgmtTestServer launches a real mgmt.Server (with a fake manager) bound
// to a httptest.Server and returns the URL + token. The CLI's env vars point at
// it.
func startMgmtTestServer(t *testing.T, statuses map[string]supervisor.Status) (url, token string) {
	u, tok, _, _ := startMgmtTestServerWithDir(t, statuses)
	return u, tok
}

// startMgmtTestServerWithDir is the same, and also hands back the config
// directory and the fake manager. The dir was previously created and dropped on
// the floor, so a test that wanted to assert `mgmt add` had written a file was
// told in a comment that it could not reach it -- it could, the helper just did
// not return it.
func startMgmtTestServerWithDir(t *testing.T, statuses map[string]supervisor.Status) (string, string, string, *cliFakeMgr) {
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
	return ts.URL, string(srv.Token()), dir, mgr
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

// TestMgmtRestart: `veepin mgmt restart <name>` reaches the manager's Rebuild
// for that listener, and no other.
//
// It used to assert only that runMgmt returned nil. The fake has recorded
// rebuildOf since it was written and no test ever read it -- state kept
// specifically for an assertion nobody made -- so a restart that POSTed to the
// wrong listener, or to nothing at all, passed.
func TestMgmtRestart(t *testing.T) {
	url, token, _, mgr := startMgmtTestServerWithDir(t, map[string]supervisor.Status{
		"site-a": {Name: "site-a", State: "running"},
		"site-b": {Name: "site-b", State: "running"},
	})
	t.Setenv("VEEPIN_MGMT_URL", url)
	t.Setenv("VEEPIN_MGMT_TOKEN", token)
	if err := runMgmt([]string{"restart", "site-a"}); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if mgr.rebuildOf != "site-a" {
		t.Errorf("rebuilt %q, want site-a", mgr.rebuildOf)
	}
}

// TestMgmtRm: `veepin mgmt rm <name> -y` stops the listener and removes its
// config file. Same story as restart -- stopOf was recorded and never read, and
// the file on disk was never checked, so an rm that deleted nothing passed.
func TestMgmtRm(t *testing.T) {
	url, token, dir, mgr := startMgmtTestServerWithDir(t, map[string]supervisor.Status{
		"site-a": {Name: "site-a", State: "running"},
		"site-b": {Name: "site-b", State: "running"},
	})
	t.Setenv("VEEPIN_MGMT_URL", url)
	t.Setenv("VEEPIN_MGMT_TOKEN", token)
	if err := runMgmt([]string{"rm", "site-a", "-y"}); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if mgr.stopOf != "site-a" {
		t.Errorf("stopped %q, want site-a", mgr.stopOf)
	}
	if _, err := os.Stat(filepath.Join(dir, "site-a.json")); !os.IsNotExist(err) {
		t.Errorf("site-a.json survives rm: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "site-b.json")); err != nil {
		t.Errorf("rm took another listener with it: %v", err)
	}
}

// TestMgmtRmNeedsConfirmation: rm is destructive, so a terminal run must be
// asked before it deletes. Scripts (non-terminal stdin) proceed as before; the
// guard is the interactive case, which a test cannot fake without a pty, so the
// -y path and the non-terminal path are what are pinned here.
func TestMgmtRmConfirmDelete(t *testing.T) {
	// Piped stdin (a script) proceeds without -y, and -y forces it anywhere.
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin; _ = r.Close() })
	go func() { _, _ = w.Write([]byte("\n")); _ = w.Close() }()
	if !confirmDelete("delete listener site-a", false) {
		t.Errorf("confirmDelete refused a non-terminal (script) run")
	}
	if !confirmDelete("delete listener site-a", true) {
		t.Errorf("confirmDelete refused with force (-y)")
	}
}

// TestMgmtEditSurfacesABuildError: PATCH answers 202 with build_error when the
// config was saved but the rebuild failed. The config IS on disk, so the CLI
// must not treat the response as a success -- the operator needs to know the
// listener is down and how to bring it back. The response still prints (so a
// -json script sees the envelope), but the command exits with an error naming
// the retry path.
func TestMgmtEditSurfacesABuildError(t *testing.T) {
	url, token := startMgmtTestServer(t, map[string]supervisor.Status{
		"site-a": {Name: "site-a", State: "running"},
	})
	t.Setenv("VEEPIN_MGMT_URL", url)
	t.Setenv("VEEPIN_MGMT_TOKEN", token)

	r, w, _ := os.Pipe()
	t.Cleanup(func() { _ = r.Close() })
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })
	// The fake manager is reachable through the real mgmt.Server the CLI talks
	// to, but the CLI has its own process-env view of the world. The rebuild
	// failure is injected server-side by making the fake return one; the API
	// then answers 202 with build_error, which is what the CLI must surface.
	// startMgmtTestServer builds its own fake, so use a fresh server here to
	// reach it.
	dir := t.TempDir()
	cfg := supervisor.ListenerConfig{Name: "site-a", Protocol: "wireguard",
		Enabled: true, Options: map[string]string{"private-key": "k", "address": "10.10.0.1/24"}}
	body, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(dir, "site-a.json"), body, 0o600)
	mgr := &cliFakeMgr{statuses: map[string]supervisor.Status{"site-a": {Name: "site-a", State: "running"}}}
	mgr.rebuildErr = errors.New("wireguard: listen udp 51820: address in use")
	srv, err := mgmt.NewServer(dir, mgr, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("mgmt.NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { _ = srv.Close(); ts.Close() })
	t.Setenv("VEEPIN_MGMT_URL", ts.URL)
	t.Setenv("VEEPIN_MGMT_TOKEN", string(srv.Token()))

	go func() { _, _ = w.Write([]byte(`{"options":{"address":"10.20.0.1/24"}}`)); _ = w.Close() }()
	err = runMgmt([]string{"edit", "site-a"})
	if err == nil {
		t.Fatalf("edit succeeded despite a rebuild failure")
	}
	if !strings.Contains(err.Error(), "rebuild failed") || !strings.Contains(err.Error(), "restart site-a") {
		t.Errorf("error does not name the failure and the retry path: %v", err)
	}
}

// TestMgmtClientHasATimeout: the CLI must not hang forever against a wedged
// supervisor. The mutation endpoints can block on a rebuild that waits out the
// supervisor's close grace, so the HTTP client carries a finite timeout.
func TestMgmtClientHasATimeout(t *testing.T) {
	t.Setenv("VEEPIN_MGMT_TOKEN", "tok")
	c, err := newMgmtClient()
	if err != nil {
		t.Fatalf("newMgmtClient: %v", err)
	}
	if c.http == nil || c.http.Timeout == 0 {
		t.Errorf("mgmt client has no HTTP timeout")
	}
}

// TestClientConfigBundleIsAllOrNothing: writeClientConfigBundle must not leave
// a half-bundle behind when a companion file fails to install. profile.json
// lands first, so a companion failure is exactly the case that used to strand
// a profile pointing at a CA that was never written.
func TestClientConfigBundleIsAllOrNothing(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bundle")
	// Occupy the companion's target name with a directory so the rename into
	// place fails after profile.json has already been installed.
	if err := os.MkdirAll(filepath.Join(out, "ca.crt"), 0o700); err != nil {
		t.Fatal(err)
	}
	resp := map[string]any{
		"protocol": "openvpn",
		"profile": map[string]any{
			"name": "site-a", "protocol": "openvpn",
			"options": map[string]any{"remote": "vpn.example.com", "ca": "ca.crt"},
		},
		"files": []any{
			map[string]any{"name": "ca.crt", "content": "-----BEGIN CERTIFICATE-----\n"},
		},
	}
	if err := writeClientConfigBundle(out, resp); err == nil {
		t.Fatal("bundle succeeded despite an uninstallable companion")
	}
	if _, err := os.Stat(filepath.Join(out, "profile.json")); !os.IsNotExist(err) {
		t.Errorf("profile.json survived a failed bundle")
	}
}

// TestClientConfigBundleRollbackRestoresWhatItReplaced: rollback removed every
// name it had installed, including the ones that already existed and had been
// overwritten. So re-running client-config over an existing bundle, and failing
// partway, took the operator's previous files with it -- and the all-or-nothing
// comment was wrong about which state it restored.
func TestClientConfigBundleRollbackRestoresWhatItReplaced(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	// A previous bundle the operator already has.
	const oldProfile = `{"name":"site-a","note":"the one that works"}`
	const oldCA = "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n"
	for name, body := range map[string]string{"profile.json": oldProfile, "ca.crt": oldCA} {
		if err := os.WriteFile(filepath.Join(out, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The SECOND companion cannot be installed, so the run fails after
	// profile.json and ca.crt have both been replaced.
	if err := os.MkdirAll(filepath.Join(out, "client.key"), 0o700); err != nil {
		t.Fatal(err)
	}
	resp := map[string]any{
		"protocol": "openvpn",
		"profile": map[string]any{
			"name": "site-a", "protocol": "openvpn",
			"options": map[string]any{"remote": "vpn.example.com", "ca": "ca.crt"},
		},
		"files": []any{
			map[string]any{"name": "ca.crt", "content": "NEW"},
			map[string]any{"name": "client.key", "content": "NEW"},
		},
	}
	if err := writeClientConfigBundle(out, resp); err == nil {
		t.Fatal("bundle succeeded despite an uninstallable companion")
	}
	for name, want := range map[string]string{"profile.json": oldProfile, "ca.crt": oldCA} {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Errorf("%s was deleted by the rollback rather than restored: %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s = %q, want the operator's original %q", name, got, want)
		}
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
// TestMgmtTokenFromFile: VEEPIN_MGMT_TOKEN unset falls back to the token file
// the supervisor mints, so `sudo veepin mgmt ls` works with no export. The
// explicit environment variable wins when both are present.
func TestMgmtTokenFromFile(t *testing.T) {
	t.Setenv("VEEPIN_MGMT_URL", "http://127.0.0.1:9")
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEEPIN_MGMT_TOKEN", "")
	t.Setenv("VEEPIN_MGMT_TOKEN_FILE", file)
	c, err := newMgmtClient()
	if err != nil {
		t.Fatalf("newMgmtClient with a token file: %v", err)
	}
	if c.token != "from-file" {
		t.Errorf("token = %q, want from-file", c.token)
	}

	t.Setenv("VEEPIN_MGMT_TOKEN", "from-env")
	c, err = newMgmtClient()
	if err != nil {
		t.Fatalf("newMgmtClient with env token: %v", err)
	}
	if c.token != "from-env" {
		t.Errorf("token = %q, want from-env (env must win)", c.token)
	}
}

// TestMgmtClientConfigWritesBundle drives the client-config CLI against a real
// mgmt server: the generated profile.json lands in -o with the listener's
// secrets filled in, so an operator can hand it straight to `veepin connect`.
func TestMgmtClientConfigWritesBundle(t *testing.T) {
	dir := t.TempDir()
	cfg := supervisor.ListenerConfig{Name: "site-a", Protocol: "toy", Enabled: true,
		Options: map[string]string{"user": "alice", "secret": "s3cret"}}
	body, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(dir, "site-a.json"), body, 0o600)
	mgr := &cliFakeMgr{statuses: map[string]supervisor.Status{}}
	srv, err := mgmt.NewServer(dir, mgr, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("mgmt.NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { _ = srv.Close(); ts.Close() })
	t.Setenv("VEEPIN_MGMT_URL", ts.URL)
	t.Setenv("VEEPIN_MGMT_TOKEN", string(srv.Token()))

	outDir := t.TempDir()
	if err := runMgmt([]string{"client-config", "site-a", "-endpoint", "vpn.example.com", "-o", outDir}); err != nil {
		t.Fatalf("client-config: %v", err)
	}
	profBody, err := os.ReadFile(filepath.Join(outDir, "profile.json"))
	if err != nil {
		t.Fatalf("no profile.json written: %v", err)
	}
	var prof map[string]any
	if err := json.Unmarshal(profBody, &prof); err != nil {
		t.Fatalf("profile.json not JSON: %v", err)
	}
	opts, _ := prof["options"].(map[string]any)
	if opts["server"] != "vpn.example.com" {
		t.Errorf("endpoint did not reach the profile: %+v", opts)
	}
	if opts["secret"] != "s3cret" {
		t.Errorf("listener secret did not carry over: %+v", opts)
	}
	if strings.Contains(string(profBody), "<redacted>") {
		t.Errorf("written profile contains a redaction placeholder: %s", profBody)
	}
}

// TestMgmtClientConfigRedactsOnStdoutUnlessAsked: without -o the generated
// profile goes to the terminal, and it is strictly more sensitive than anything
// `veepin profile show` prints -- it carries the client's freshly minted private
// key as well as every secret the listener supplied. `profile show` redacts by
// default and takes -secrets to opt in; this printed the lot and took nothing.
// A profile in scrollback, or in whatever a pipe fed, is a leak the operator
// never asked for.
func TestMgmtClientConfigRedactsOnStdoutUnlessAsked(t *testing.T) {
	dir := t.TempDir()
	cfg := supervisor.ListenerConfig{Name: "site-a", Protocol: "toy", Enabled: true,
		Options: map[string]string{"user": "alice", "secret": "s3cret"}}
	body, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(dir, "site-a.json"), body, 0o600)
	mgr := &cliFakeMgr{statuses: map[string]supervisor.Status{}}
	srv, err := mgmt.NewServer(dir, mgr, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("mgmt.NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { _ = srv.Close(); ts.Close() })
	t.Setenv("VEEPIN_MGMT_URL", ts.URL)
	t.Setenv("VEEPIN_MGMT_TOKEN", string(srv.Token()))

	out, err := captureStdout(t, func() error {
		return runMgmt([]string{"client-config", "site-a", "-endpoint", "vpn.example.com"})
	})
	if err != nil {
		t.Fatalf("client-config: %v", err)
	}
	if strings.Contains(out, "s3cret") {
		t.Errorf("client-config printed a secret value to stdout: %s", out)
	}
	if !strings.Contains(out, "<redacted>") {
		t.Errorf("client-config did not mark the secret redacted: %s", out)
	}
	// The non-secret options are still there: a redacted profile is meant to be
	// readable, not useless.
	if !strings.Contains(out, "vpn.example.com") {
		t.Errorf("redaction ate the endpoint too: %s", out)
	}

	// -secrets is the opt-in, and it must print the real value.
	out, err = captureStdout(t, func() error {
		return runMgmt([]string{"client-config", "site-a", "-endpoint", "vpn.example.com", "-secrets"})
	})
	if err != nil {
		t.Fatalf("client-config -secrets: %v", err)
	}
	if !strings.Contains(out, "s3cret") {
		t.Errorf("-secrets did not print the value: %s", out)
	}
}

// TestMgmtRequiresTokenErrorsWithoutBoth: with neither env token nor a readable
// token file, the CLI refuses to start rather than sending an unauthenticated
// request that leaks its existence.
func TestMgmtRequiresTokenErrorsWithoutBoth(t *testing.T) {
	t.Setenv("VEEPIN_MGMT_TOKEN", "")
	t.Setenv("VEEPIN_MGMT_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := newMgmtClient(); err == nil {
		t.Errorf("newMgmtClient succeeded without any token source")
	}
}

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
	url, token, dir, _ := startMgmtTestServerWithDir(t, nil)
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
	// The config directory IS reachable -- the helper creates it and now
	// returns it. The previous version asserted nothing at all and explained in
	// a comment that it could not, which was not true.
	stored, err := supervisor.ParseListenerFile(filepath.Join(dir, "added.json"))
	if err != nil {
		t.Fatalf("add wrote no config file: %v", err)
	}
	if stored.Protocol != "wireguard" || stored.Options["address"] != "10.10.0.1/24" {
		t.Errorf("stored config is not the one submitted: %+v", stored)
	}
	if !stored.Enabled {
		t.Error("the listener was stored disabled")
	}
}
