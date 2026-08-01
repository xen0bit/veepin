package mgmt

// Tests for the management API. They use httptest and a fake supervisor
// (a *fakeMgr implementing the manager-ish surface the API calls) so the
// endpoint behavior is verified without sockets or TUNs.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/keygen"
	"github.com/xen0bit/veepin/internal/profile"
	"github.com/xen0bit/veepin/internal/supervisor"
	"github.com/xen0bit/veepin/wireguard"

	// Blank-import the production facades so the registry the API reads from
	// (client.ServerProtocols, client.ServerOptsFor) knows every server
	// protocol, matching the binary's runtime surface. Without these, the
	// registry appears empty and the protocol/redaction paths would silently
	// take their fallback branches during tests.
	_ "github.com/xen0bit/veepin/amneziawg"
	_ "github.com/xen0bit/veepin/anyconnect"
	_ "github.com/xen0bit/veepin/cisco"
	_ "github.com/xen0bit/veepin/fortinet"
	_ "github.com/xen0bit/veepin/gp"
	_ "github.com/xen0bit/veepin/ikev2"
	_ "github.com/xen0bit/veepin/l2tp"
	_ "github.com/xen0bit/veepin/l2tpv3"
	_ "github.com/xen0bit/veepin/masque"
	_ "github.com/xen0bit/veepin/nebula"
	_ "github.com/xen0bit/veepin/openvpn"
	_ "github.com/xen0bit/veepin/pulse"
	_ "github.com/xen0bit/veepin/softether"
	_ "github.com/xen0bit/veepin/ssh"
	_ "github.com/xen0bit/veepin/sstp"
	_ "github.com/xen0bit/veepin/toy"
	_ "github.com/xen0bit/veepin/wireguard"
)

// fakeMgr stands in for *supervisor.Manager so the API tests don't need a
// directory of listener files or a real ctor. The methods the API uses are
// ticked-through; the test asserts the API calls them as expected by reading the
// counters and the recorded calls back.
type fakeMgr struct {
	applyCalls int
	statuses   map[string]supervisor.Status
	rebuildOf  string
	stopOf     string
	rebuildErr error
	stopErr    error
	peerServer client.Server // optional, returned by Server()
}

func (f *fakeMgr) Apply() error { f.applyCalls++; return nil }
func (f *fakeMgr) All() []supervisor.Status {
	out := make([]supervisor.Status, 0, len(f.statuses))
	for _, s := range f.statuses {
		out = append(out, s)
	}
	return out
}
func (f *fakeMgr) Status(name string) supervisor.Status {
	if s, ok := f.statuses[name]; ok {
		return s
	}
	return supervisor.Status{Name: name, State: "unknown"}
}
func (f *fakeMgr) Rebuild(name string) error {
	f.rebuildOf = name
	return f.rebuildErr
}
func (f *fakeMgr) Stop(name string) error {
	f.stopOf = name
	delete(f.statuses, name)
	return f.stopErr
}
func (f *fakeMgr) Close() error                     { return nil }
func (f *fakeMgr) Server(name string) client.Server { return f.peerServer }

// newTestServer wires a real mgmt.Server with a fake manager and a temp config
// dir, returning the server and its token-bearing client. One helper covers
// every test in this file.
func newTestServer(t *testing.T, statuses map[string]supervisor.Status) (*Server, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	// Pre-seed a couple of listener files for the GET endpoints to find.
	for name := range statuses {
		cfg := supervisor.ListenerConfig{Name: name, Protocol: "wireguard",
			Options: map[string]string{"private-key": "real-secret-value", "address": "10.10.0.1/24"},
			Enabled: true}
		body, _ := json.Marshal(cfg)
		_ = os.WriteFile(filepath.Join(dir, name+".json"), body, 0o600)
	}
	mgr := &fakeMgr{statuses: statuses}
	srv, err := NewServer(dir, mgr, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.mgr.Close() })
	return srv, "http://test", srv.token
}

// do sends an authenticated request and returns the response status plus body.
func (s *Server) do(method, path string, body any) (*http.Response, []byte) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if r != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+string(s.token))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec.Result(), rec.Body.Bytes()
}

// unauth exercises the missing-token path.
func (s *Server) doNoToken(method, path string, body any) *http.Response {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec.Result()
}

func TestHealthEndpoint(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	resp, body := s.do("GET", "/api/health", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"status"`) || !strings.Contains(string(body), `"ok"`) {
		t.Errorf("body = %s", body)
	}
}

func TestUnknownEndpointReturnsMuxDefault(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	resp, _ := s.do("GET", "/api/missing", nil)
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404 (no route)", resp.StatusCode)
	}
}

func TestMissingTokenReturns401(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	resp := s.doNoToken("GET", "/api/health", nil)
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401 (no auth)", resp.StatusCode)
	}
}

func TestBadTokenReturns401(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	req := httptest.NewRequest("GET", "/api/health", nil)
	req.Header.Set("Authorization", "Bearer wrong-token-of-deceptive-length")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Errorf("status = %d, want 401 (bad token)", rec.Code)
	}
}

// TestProtocolsEndpointListsEveryRegisteredProtocol pins that the protocols
// endpoint reports each registered server protocol alongside its declared
// OptSpec metadata. Since the test file's imports populate the registry, this
// verifies the API and the facade side-effect both cover the full set.
func TestProtocolsEndpointListsEveryRegisteredProtocol(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	resp, body := s.do("GET", "/api/protocols", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out ProtocolsResp
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, body)
	}
	names := make(map[string]bool, len(out.Protocols))
	for _, p := range out.Protocols {
		names[p.Name] = true
		if !p.Known {
			t.Errorf("protocol %q reported Known=false", p.Name)
		}
	}
	// Cross-check against the registry; the two lists must be equal as sets.
	for _, reg := range client.ServerProtocols() {
		if !names[reg] {
			t.Errorf("registered protocol %q missing from /api/protocols", reg)
		}
	}
}

func TestListListenersReturnsStatuses(t *testing.T) {
	statuses := map[string]supervisor.Status{
		"site-a": {Name: "site-a", Protocol: "wireguard", State: "running"},
		"site-b": {Name: "site-b", Protocol: "ikev2", State: "running"},
	}
	s, _, _ := newTestServer(t, statuses)
	resp, body := s.do("GET", "/api/listeners", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	// Both statuses should appear, sorted by name.
	if !strings.Contains(string(body), "site-a") || !strings.Contains(string(body), "site-b") {
		t.Errorf("body misses a listener: %s", body)
	}
}

func TestGetListenerStatusUnknownReturns404(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	resp, _ := s.do("GET", "/api/listeners/never-existed", nil)
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestGetListenerReturnsConfigWithSecretsRedacted(t *testing.T) {
	statuses := map[string]supervisor.Status{"site-a": {Name: "site-a", Protocol: "wireguard", State: "running"}}
	s, _, _ := newTestServer(t, statuses)
	resp, body := s.do("GET", "/api/listeners/site-a", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), redacted) {
		t.Errorf("response body lacks redaction marker (private-key should be redacted):\n%s", body)
	}
	if strings.Contains(string(body), "real-secret-value") {
		t.Errorf("response body leaks the real private-key value:\n%s", body)
	}
}

func TestCreateListenerPersistsAndApplies(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	cfg := supervisor.ListenerConfig{Name: "new-one", Protocol: "wireguard",
		Options: map[string]string{"private-key": "k", "address": "10.10.0.1/24"}, Enabled: true}
	resp, _ := s.do("POST", "/api/listeners", cfg)
	if resp.StatusCode != 201 {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "new-one.json")); err != nil {
		t.Errorf("persists: %v", err)
	}
	fake := s.mgr.(*fakeMgr)
	if fake.applyCalls == 0 {
		t.Errorf("Apply was not called after Create")
	}
}

// TestCreateGeneratesKeysAndSurfacesThem: a create that leaves a Generate
// option empty auto-generates key material before the config is written, and
// surfaces the parts the operator must act on (the WireGuard public key) once,
// in the response. The config file stores both halves so a later GET can still
// recover the public key.
func TestCreateGeneratesKeysAndSurfacesThem(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	cfg := supervisor.ListenerConfig{Name: "wg-1", Protocol: "wireguard",
		Options: map[string]string{"address": "10.10.0.1/24"}, Enabled: true}
	resp, body := s.do("POST", "/api/listeners", cfg)
	if resp.StatusCode != 201 {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	var out struct {
		Generated map[string]string `json:"generated"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("create response is not JSON: %v", err)
	}
	if out.Generated["public-key"] == "" {
		t.Fatalf("create response carries no generated public-key: %s", body)
	}
	got := readListenerFile(t, s.dir, "wg-1")
	if got.Options["private-key"] == "" {
		t.Errorf("private-key was not generated into the config")
	}
	if got.Options["public-key"] == "" {
		t.Errorf("public-key was not persisted with the config")
	}
}

// TestCreateRespectsOperatorSuppliedKeys: a create that fills a Generate option
// must not overwrite it. Generation is a convenience, not a claim on the
// operator's own key material.
func TestCreateRespectsOperatorSuppliedKeys(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	cfg := supervisor.ListenerConfig{Name: "wg-2", Protocol: "wireguard",
		Options: map[string]string{"private-key": "operator-key", "address": "10.10.0.1/24"}, Enabled: true}
	resp, body := s.do("POST", "/api/listeners", cfg)
	if resp.StatusCode != 201 {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	var out struct {
		Generated map[string]string `json:"generated"`
	}
	_ = json.Unmarshal(body, &out)
	if out.Generated != nil && out.Generated["public-key"] != "" {
		t.Errorf("operator-supplied key was regenerated and surfaced: %v", out.Generated)
	}
	if got := readListenerFile(t, s.dir, "wg-2"); got.Options["private-key"] != "operator-key" {
		t.Errorf("operator's private key was overwritten: %q", got.Options["private-key"])
	}
}

// TestCreateListenerRefusesToOverwrite: POST creates. Without the existence
// check it also silently overwrote, so a double-submitted form or a re-run
// script replaced a live listener's config -- keys and all -- and answered 201.
func TestCreateListenerRefusesToOverwrite(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{"site-a": {Name: "site-a", State: "running"}})
	cfg := supervisor.ListenerConfig{Name: "site-a", Protocol: "wireguard",
		Options: map[string]string{"private-key": "different", "address": "10.9.0.1/24"}, Enabled: true}
	resp, _ := s.do("POST", "/api/listeners", cfg)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	// The stored config must be untouched.
	got := readListenerFile(t, s.dir, "site-a")
	if got.Options["private-key"] != "real-secret-value" {
		t.Errorf("a refused create still overwrote the key: %q", got.Options["private-key"])
	}
}

// readListenerFile reads a listener config straight off disk, so a test can
// assert what was persisted rather than what the API reported.
func readListenerFile(t *testing.T, dir, name string) supervisor.ListenerConfig {
	t.Helper()
	cfg, err := supervisor.ParseListenerFile(filepath.Join(dir, name+".json"))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return cfg
}

// TestPatchCanTurnABooleanOff is the defect this whole presence-aware patch
// shape exists for. The merge used to be `in.Enabled || existing.Enabled`, so
// every boolean was one-way: unchecking "enabled" in the panel silently did
// nothing, and there was no way to disable a listener through the API at all.
func TestPatchCanTurnABooleanOff(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{"site-a": {Name: "site-a", State: "running"}})
	resp, body := s.do("PATCH", "/api/listeners/site-a", map[string]any{"enabled": false})
	if resp.StatusCode >= 300 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if got := readListenerFile(t, s.dir, "site-a"); got.Enabled {
		t.Error("PATCH {\"enabled\": false} left the listener enabled")
	}
}

// TestPatchLeavesUnmentionedFieldsAlone is the other half of the same contract:
// a partial PATCH -- the shape a hand-written curl sends -- must not reset the
// fields it did not mention to their zero values.
func TestPatchLeavesUnmentionedFieldsAlone(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{"site-a": {Name: "site-a", State: "running"}})
	resp, body := s.do("PATCH", "/api/listeners/site-a", map[string]any{"wan": "eth1"})
	if resp.StatusCode >= 300 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	got := readListenerFile(t, s.dir, "site-a")
	if got.WAN != "eth1" {
		t.Errorf("wan = %q, want eth1", got.WAN)
	}
	if !got.Enabled {
		t.Error("a PATCH that never mentioned enabled disabled the listener")
	}
	if got.Options["address"] != "10.10.0.1/24" {
		t.Errorf("options lost: %+v", got.Options)
	}
	if got.Protocol != "wireguard" {
		t.Errorf("protocol = %q, want wireguard", got.Protocol)
	}
}

// TestPatchRedactedSecretKeepsTheStoredValue: the API answers a GET with
// "<redacted>" for secret options, and the panel submits the form it was shown.
// Reading that literal back as "keep what you have" is what stops a
// GET-then-PATCH round trip from replacing a private key with the placeholder.
func TestPatchRedactedSecretKeepsTheStoredValue(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{"site-a": {Name: "site-a", State: "running"}})
	resp, body := s.do("PATCH", "/api/listeners/site-a", map[string]any{
		"options": map[string]string{"private-key": redacted, "address": "10.11.0.1/24"},
	})
	if resp.StatusCode >= 300 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	got := readListenerFile(t, s.dir, "site-a")
	if got.Options["private-key"] != "real-secret-value" {
		t.Errorf("private-key = %q, want the stored value", got.Options["private-key"])
	}
	if got.Options["address"] != "10.11.0.1/24" {
		t.Errorf("address = %q, want the patched value", got.Options["address"])
	}
}

// TestPatchEmptyOptionValueClearsTheKey: the panel submits every option the
// protocol declares on every save, so it needs a way to say "unset". Empty is
// that way, and it is safe to overload because the server parse functions
// already read a missing key and an empty one identically.
func TestPatchEmptyOptionValueClearsTheKey(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{"site-a": {Name: "site-a", State: "running"}})
	resp, body := s.do("PATCH", "/api/listeners/site-a", map[string]any{
		"options": map[string]string{"address": ""},
	})
	if resp.StatusCode >= 300 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	got := readListenerFile(t, s.dir, "site-a")
	if _, still := got.Options["address"]; still {
		t.Errorf("an empty value did not clear the key: %+v", got.Options)
	}
	if got.Options["private-key"] != "real-secret-value" {
		t.Errorf("clearing one key disturbed another: %+v", got.Options)
	}
}

// TestPatchRefusesARename: a rename would have to move the config file and
// retire the old listener. The previous version did neither -- it wrote
// <newname>.json, left <oldname>.json in place, and rebuilt the old name -- so
// one edit produced two listeners.
func TestPatchRefusesARename(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{"site-a": {Name: "site-a", State: "running"}})
	resp, _ := s.do("PATCH", "/api/listeners/site-a", map[string]any{"name": "site-b"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "site-b.json")); !os.IsNotExist(err) {
		t.Errorf("a refused rename still created site-b.json")
	}
}

// TestPatchUnknownListenerReturns404 pins that PATCH does not create.
func TestPatchUnknownListenerReturns404(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	resp, _ := s.do("PATCH", "/api/listeners/nope", map[string]any{"wan": "eth0"})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestCreateListenerValidatesName(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	bad := supervisor.ListenerConfig{Name: "UPPERCASE", Protocol: "wireguard"}
	resp, _ := s.do("POST", "/api/listeners", bad)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400 (bad name)", resp.StatusCode)
	}
}

func TestCreateListenerRejectsUnknownProtocol(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	cfg := supervisor.ListenerConfig{Name: "x", Protocol: "nonsense-example"}
	resp, _ := s.do("POST", "/api/listeners", cfg)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400 (unknown protocol)", resp.StatusCode)
	}
}

func TestCreateListenerRequiresAuth(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	resp := s.doNoToken("POST", "/api/listeners", supervisor.ListenerConfig{Name: "x"})
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401 (no auth)", resp.StatusCode)
	}
}

// TestDeleteListenerRemovesFileAndCallsStop covers the DELETE endpoint: it
// calls Stop on the manager and deletes the on-disk config, leaving the API
// idempotent for a listener whose server crashed but whose file is still
// present.
func TestDeleteListenerRemovesFileAndCallsStop(t *testing.T) {
	statuses := map[string]supervisor.Status{"site-a": {Name: "site-a", State: "running"}}
	s, _, _ := newTestServer(t, statuses)
	resp, _ := s.do("DELETE", "/api/listeners/site-a", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "site-a.json")); !os.IsNotExist(err) {
		t.Errorf("listener file not removed after DELETE: %v", err)
	}
	if s.mgr.(*fakeMgr).stopOf != "site-a" {
		t.Errorf("Stop was called on %q, want site-a", s.mgr.(*fakeMgr).stopOf)
	}
}

func TestRestartEndpointCallsRebuild(t *testing.T) {
	statuses := map[string]supervisor.Status{"site-a": {Name: "site-a", State: "running"}}
	s, _, _ := newTestServer(t, statuses)
	resp, _ := s.do("POST", "/api/listeners/site-a/restart", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if s.mgr.(*fakeMgr).rebuildOf != "site-a" {
		t.Errorf("Rebuild was called on %q, want site-a", s.mgr.(*fakeMgr).rebuildOf)
	}
}

// TestPatchRebuildFailureIsSavedNotSunk: a PATCH whose rebuild fails must
// report 202 "saved, build_error=..." rather than 500 or a false success. The
// config file is already on disk; the operator can retry via /restart, and the
// panel keeps the page open on this status instead of redirecting.
func TestPatchRebuildFailureIsSavedNotSunk(t *testing.T) {
	statuses := map[string]supervisor.Status{"site-a": {Name: "site-a", State: "running"}}
	s, _, _ := newTestServer(t, statuses)
	s.mgr.(*fakeMgr).rebuildErr = errors.New("wireguard: listen udp 51820: address in use")
	resp, body := s.do("PATCH", "/api/listeners/site-a",
		map[string]any{"options": map[string]string{"address": "10.20.0.1/24"}})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if out["status"] != "saved" {
		t.Errorf(`status = %v, want "saved"`, out["status"])
	}
	if be, _ := out["build_error"].(string); !strings.Contains(be, "address in use") {
		t.Errorf("build_error = %q, want the rebuild failure", be)
	}
	// The file must still have been updated, so a retry of /restart rebuilds the
	// new config rather than the old one.
	cfg, err := supervisor.ParseListenerFile(supervisor.ListenerPath(s.dir, "site-a"))
	if err != nil {
		t.Fatalf("on-disk config unreadable after saved-with-error: %v", err)
	}
	if cfg.Options["address"] != "10.20.0.1/24" {
		t.Errorf("on-disk address = %q, want the patched value", cfg.Options["address"])
	}
}

// newTestServerWithProfiles wires the same fake-manager server as
// newTestServer, plus a profile directory for the /api/profiles endpoints.
func newTestServerWithProfiles(t *testing.T, statuses map[string]supervisor.Status, profiles string) (*Server, string, []byte) {
	t.Helper()
	// The token is read off the server that is returned, not off a discarded
	// one: an earlier version built a server via newTestServer purely to borrow
	// its dir and manager, then handed back the DISCARDED server's URL and
	// token alongside the new server.
	s, _, _ := newTestServer(t, statuses)
	withProfiles, err := NewServer(s.dir, s.mgr, log.New(io.Discard, "", 0), WithProfileDir(profiles))
	if err != nil {
		t.Fatalf("NewServer with profiles: %v", err)
	}
	return withProfiles, "http://test", withProfiles.token
}

// TestProfileListIsEmptyBeforeTheDirectoryExists: the supervisor defaults
// -profiles to <config>/profiles and nothing creates it, so LoadDir's ENOENT
// used to surface as a 500 that the dashboard re-polled every five seconds
// forever. An absent directory is an empty fleet.
func TestProfileListIsEmptyBeforeTheDirectoryExists(t *testing.T) {
	s, _, _ := newTestServerWithProfiles(t, map[string]supervisor.Status{},
		filepath.Join(t.TempDir(), "never-created"))
	resp, body := s.do("GET", "/api/profiles", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, body)
	}
	var out struct {
		Profiles []profile.Config `json:"profiles"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if len(out.Profiles) != 0 {
		t.Errorf("profiles = %+v, want an empty list", out.Profiles)
	}
}

// TestProfilesNotMountedWithoutDir: without a profile directory the profile
// endpoints are not registered, so a request is a plain 404 rather than a
// misleading empty list.
func TestProfilesNotMountedWithoutDir(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	resp, _ := s.do("GET", "/api/profiles", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when no profile dir is configured", resp.StatusCode)
	}
}

// TestProfileCreateStoresAndListsItRedacted pins the profile CRUD surface: create persists a
// file, list returns it with secrets redacted, and get reads it back.
func TestProfileCreateStoresAndListsItRedacted(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := newTestServerWithProfiles(t, map[string]supervisor.Status{}, dir)
	cfg := map[string]any{"name": "home", "protocol": "toy",
		"options": map[string]string{"server": "1.2.3.4", "user": "alice", "secret": "topsecret"}}
	resp, body := s.do("POST", "/api/profiles", cfg)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201: %s", resp.StatusCode, body)
	}
	if _, err := os.Stat(filepath.Join(dir, "home.json")); err != nil {
		t.Fatalf("profile not persisted: %v", err)
	}
	resp, body = s.do("GET", "/api/profiles", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	if strings.Contains(string(body), "topsecret") {
		t.Errorf("list leaked a secret: %s", body)
	}
	if !strings.Contains(string(body), redacted) {
		t.Errorf("list did not redact the secret: %s", body)
	}
}

// TestProfilePatchMergesOptions: a partial PATCH changes only what it names and
// preserves a redacted secret round trip.
func TestProfilePatchMergesOptions(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := newTestServerWithProfiles(t, map[string]supervisor.Status{}, dir)
	s.do("POST", "/api/profiles", map[string]any{"name": "home", "protocol": "toy",
		"options": map[string]string{"server": "old.example", "user": "alice", "secret": "s3cret"}})
	resp, _ := s.do("PATCH", "/api/profiles/home", map[string]any{
		"options": map[string]string{"server": "new.example", "secret": redacted}})
	if resp.StatusCode != 200 {
		t.Fatalf("patch status = %d, want 200", resp.StatusCode)
	}
	resp, body := s.do("GET", "/api/profiles/home", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("get status = %d", resp.StatusCode)
	}
	var out profile.Config
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("get body is not a profile: %v", err)
	}
	if out.Options["server"] != "new.example" {
		t.Errorf("server = %q, want new.example", out.Options["server"])
	}
	if out.Options["user"] != "alice" {
		t.Errorf("unmentioned option was clobbered: %q", out.Options["user"])
	}
	if out.Options["secret"] != redacted {
		t.Errorf("redacted round trip lost the secret key entirely: %q", out.Options["secret"])
	}
	// The stored value must survive.
	stored := readProfileFile(t, dir, "home")
	if stored.Options["secret"] != "s3cret" {
		t.Errorf("stored secret was clobbered by the redacted round trip: %q", stored.Options["secret"])
	}
}

// TestProfileDeleteRemovesTheFileAndIsNotIdempotent removes the file.
func TestProfileDeleteRemovesTheFileAndIsNotIdempotent(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := newTestServerWithProfiles(t, map[string]supervisor.Status{}, dir)
	s.do("POST", "/api/profiles", map[string]any{"name": "home", "protocol": "toy"})
	resp, _ := s.do("DELETE", "/api/profiles/home", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(dir, "home.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("profile file survives delete: %v", err)
	}
}

// readProfileFile reads a profile straight off disk.
func readProfileFile(t *testing.T, dir, name string) profile.Config {
	t.Helper()
	cfg, err := profile.ParseFile(filepath.Join(dir, name+".json"))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return cfg
}

// TestAuditRecordsMutations: every mutation lands in the audit log with its
// outcome, so the panel's "recent activity" and `veepin mgmt audit` answer
// "what changed on this fleet" without accounts or storage.
func TestAuditRecordsMutations(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	s.do("POST", "/api/listeners", map[string]any{"name": "site-a", "protocol": "wireguard",
		"options": map[string]string{"private-key": "k", "address": "10.0.0.1/24"}})
	s.do("POST", "/api/listeners/site-a/restart", nil)
	// A failed delete (unknown name) records the failure as the outcome.
	s.do("DELETE", "/api/listeners/nope", nil)

	resp, body := s.do("GET", "/api/audit", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("audit status = %d", resp.StatusCode)
	}
	var out struct {
		Events []auditEvent `json:"events"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("audit body not JSON: %v", err)
	}
	// Newest first: delete failure, restart, create.
	if len(out.Events) < 3 {
		t.Fatalf("audit has %d events, want >= 3: %s", len(out.Events), body)
	}
	if out.Events[0].Action != "listener.delete" || out.Events[0].Name != "nope" {
		t.Errorf("newest event = %+v, want the failed delete", out.Events[0])
	}
	if out.Events[0].Outcome == "ok" {
		t.Errorf("the failed delete recorded outcome 'ok': %+v", out.Events[0])
	}
	if out.Events[2].Action != "listener.create" || out.Events[2].Name != "site-a" {
		t.Errorf("oldest event = %+v, want the create", out.Events[2])
	}
	if out.Events[2].Outcome != "ok" {
		t.Errorf("the create recorded a failure: %+v", out.Events[2])
	}
}

// TestDeletingAStoppedListenerIsNotAnAuditFailure: Manager.Stop reports "no
// listener named X" for anything not in the live set, which is the normal case
// for a disabled or crashed listener. Routing that into the audit outcome put a
// red failure in "recent activity" next to the delete's own 200. The fake used
// by TestAuditRecordsMutations always succeeds, so nothing caught it.
func TestDeletingAStoppedListenerIsNotAnAuditFailure(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	s.do("POST", "/api/listeners", map[string]any{"name": "site-a", "protocol": "wireguard",
		"options": map[string]string{"private-key": "k", "address": "10.0.0.1/24"}})
	s.mgr.(*fakeMgr).stopErr = errors.New("supervisor: no listener named \"site-a\"")

	resp, _ := s.do("DELETE", "/api/listeners/site-a", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("delete status = %d, want 200: a stopped listener is still deletable", resp.StatusCode)
	}
	_, body := s.do("GET", "/api/audit", nil)
	var out struct {
		Events []auditEvent `json:"events"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("audit body not JSON: %v", err)
	}
	if out.Events[0].Action != "listener.delete" {
		t.Fatalf("newest event = %+v, want the delete", out.Events[0])
	}
	if out.Events[0].Outcome != "ok" {
		t.Errorf("a successful delete of a stopped listener recorded %q", out.Events[0].Outcome)
	}
}

// TestClientConfigMapKeysAreDeclared ties the clientconfig derivation table to
// the registry's OptSpecs: every client key it writes must be a declared client
// option, and every server key it reads must be a declared server option. The
// table is a hand-written map of strings; this is the guard that keeps it from
// drifting from what the facades actually emit.
func TestClientConfigMapKeysAreDeclared(t *testing.T) {
	for proto, m := range clientProtoMaps {
		clientSpecs, cok := client.ClientOptsFor(proto)
		serverSpecs, sok := client.ServerOptsFor(proto)
		if !cok {
			t.Errorf("%s: client-config derives options but the facade declares no client OptSpecs", proto)
			continue
		}
		if !sok {
			t.Errorf("%s: client-config reads server options but the facade declares no server OptSpecs", proto)
			continue
		}
		cdecl := map[string]bool{}
		for _, sp := range clientSpecs {
			cdecl[sp.Key] = true
		}
		sdecl := map[string]bool{}
		for _, sp := range serverSpecs {
			sdecl[sp.Key] = true
		}
		if m.endpointKey != "" && !cdecl[m.endpointKey] {
			t.Errorf("%s: endpoint key %q is not a declared client option", proto, m.endpointKey)
		}
		// serverPort and clientDefaultPort were outside this guard, which is
		// exactly where the port derivation was broken: the port was folded into
		// the host option and no test looked at either field.
		if m.serverPort != "" && !sdecl[m.serverPort] {
			t.Errorf("%s: serverPort key %q is not a declared server option, so the listener's "+
				"port will never be found and every client dials the default", proto, m.serverPort)
		}
		if m.endpointKey != "" && m.clientDefaultPort == "" {
			t.Errorf("%s: no clientDefaultPort, so a derived port can never be recognised as "+
				"redundant and every profile carries one", proto)
		}
		// The declared default and the table's must agree, or the derivation
		// omits a port the client does not actually default to.
		for _, sp := range clientSpecs {
			if sp.Key == clientPortKey && sp.Default != "" && m.clientDefaultPort != "" && sp.Default != m.clientDefaultPort {
				t.Errorf("%s: table says the client defaults to port %s, the OptSpec says %s",
					proto, m.clientDefaultPort, sp.Default)
			}
		}
		for ck, sk := range m.carry {
			if !cdecl[ck] {
				t.Errorf("%s: carry client key %q is not a declared client option", proto, ck)
			}
			if !sdecl[sk] {
				t.Errorf("%s: carry server key %q is not a declared server option", proto, sk)
			}
		}
	}
	// The WireGuard family must be present in the registry with the option the
	// provisioner writes to.
	for _, proto := range []string{"wireguard", "amneziawg"} {
		specs, ok := client.ServerOptsFor(proto)
		if !ok {
			t.Errorf("%s: no server OptSpecs for client-config provisioning", proto)
			continue
		}
		found := false
		for _, sp := range specs {
			if sp.Key == wireguard.OptServerPeers {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: client-config provisions via %q but the OptSpec does not declare it", proto, wireguard.OptServerPeers)
		}
	}
}

// TestClientConfigGeneratesProfile: a simple username/password protocol derives
// a complete profile from the listener's stored options plus the endpoint, with
// real secrets and no "<redacted>" placeholder.
func TestClientConfigGeneratesProfile(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	s.do("POST", "/api/listeners", map[string]any{"name": "site-a", "protocol": "toy",
		"options": map[string]string{"user": "alice", "secret": "s3cret"}, "enabled": true})
	resp, body := s.do("POST", "/api/listeners/site-a/client-config",
		map[string]any{"endpoint": "vpn.example.com"})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	var out clientConfigResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if out.Profile.Name != "site-a" || out.Profile.Protocol != "toy" {
		t.Errorf("profile identity wrong: %+v", out.Profile)
	}
	if out.Profile.Options["server"] != "vpn.example.com" {
		t.Errorf("endpoint did not become the server option: %+v", out.Profile.Options)
	}
	if out.Profile.Options["user"] != "alice" || out.Profile.Options["secret"] != "s3cret" {
		t.Errorf("listener secrets did not carry over: %+v", out.Profile.Options)
	}
	if strings.Contains(string(body), redacted) {
		t.Errorf("generated config contains a redaction placeholder: %s", body)
	}
}

// TestClientConfigRequiresEndpoint: the supervisor cannot know its own public
// hostname, so an endpoint is required for every protocol whose client carries
// one.
func TestClientConfigRequiresEndpoint(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	s.do("POST", "/api/listeners", map[string]any{"name": "site-a", "protocol": "toy",
		"options": map[string]string{"user": "alice", "secret": "s3cret"}, "enabled": true})
	resp, _ := s.do("POST", "/api/listeners/site-a/client-config", map[string]any{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 without an endpoint", resp.StatusCode)
	}
}

// TestClientConfigBundlesFileCompanions: a file-path client option is bundled
// into the response and the profile rewritten to the file's base name.
func TestClientConfigBundlesFileCompanions(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	caPath := filepath.Join(s.dir, "ca.crt")
	if err := os.WriteFile(caPath, []byte("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.do("POST", "/api/listeners", map[string]any{"name": "site-a", "protocol": "openvpn",
		"options": map[string]string{"ca": caPath}, "enabled": true})
	resp, body := s.do("POST", "/api/listeners/site-a/client-config",
		map[string]any{"endpoint": "vpn.example.com"})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	var out clientConfigResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if out.Profile.Options["remote"] != "vpn.example.com" {
		t.Errorf("remote = %q", out.Profile.Options["remote"])
	}
	if out.Profile.Options["ca"] != "ca.crt" {
		t.Errorf("ca option not rewritten to the bundled base name: %q", out.Profile.Options["ca"])
	}
	if len(out.Files) != 1 || out.Files[0].Name != "ca.crt" || !strings.Contains(out.Files[0].Content, "MOCK") {
		t.Errorf("CA file not bundled: %+v", out.Files)
	}
}

// TestClientConfigPutsThePortInThePortOption: every derived protocol's client
// dials net.JoinHostPort(<host option>, <port option>), so a port folded into
// the host option produces "vpn.example.com:1195:1194" and a resolve failure.
// Both sources of a non-default port -- the listener's config and one the
// operator typed into the endpoint -- have to land in the port option.
func TestClientConfigPutsThePortInThePortOption(t *testing.T) {
	cases := []struct {
		name       string
		listenPort string
		endpoint   string
		wantHost   string
		wantPort   string
	}{
		{"from the listener", "1195", "vpn.example.com", "vpn.example.com", "1195"},
		{"from the endpoint", "", "vpn.example.com:8443", "vpn.example.com", "8443"},
		{"endpoint wins", "1195", "vpn.example.com:8443", "vpn.example.com", "8443"},
		{"default is left out", "1194", "vpn.example.com", "vpn.example.com", ""},
		{"bare IPv6 has no port to find", "", "fd00::1", "fd00::1", ""},
		{"bracketed IPv6", "", "[fd00::1]:8443", "fd00::1", "8443"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, _ := newTestServer(t, map[string]supervisor.Status{})
			opts := map[string]string{"ca": ""}
			if c.listenPort != "" {
				opts["port"] = c.listenPort
			}
			s.do("POST", "/api/listeners", map[string]any{"name": "ovpn", "protocol": "openvpn",
				"options": opts, "enabled": true})
			resp, body := s.do("POST", "/api/listeners/ovpn/client-config",
				map[string]any{"endpoint": c.endpoint})
			if resp.StatusCode != 200 {
				t.Fatalf("status = %d: %s", resp.StatusCode, body)
			}
			var out clientConfigResponse
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("response not JSON: %v", err)
			}
			if got := out.Profile.Options["remote"]; got != c.wantHost {
				t.Errorf("remote = %q, want %q", got, c.wantHost)
			}
			if got := out.Profile.Options["port"]; got != c.wantPort {
				t.Errorf("port = %q, want %q", got, c.wantPort)
			}
			// The pair must survive the client's own join without a stray colon.
			if strings.Count(out.Profile.Options["remote"], ":") > 0 && !strings.Contains(c.endpoint, "[") && !strings.Contains(c.wantHost, "::") {
				t.Errorf("remote %q carries a port that belongs in the port option", out.Profile.Options["remote"])
			}
		})
	}
}

// TestEveryDerivedProtocolDeclaresThePortOption backs the clientPortKey
// constant: the derivation writes the port to one fixed key rather than a
// per-row field, which is only safe while every derived protocol's client spells
// it that way.
func TestEveryDerivedProtocolDeclaresThePortOption(t *testing.T) {
	for proto, m := range clientProtoMaps {
		if m.endpointKey == "" {
			continue // no server address, so no port either
		}
		specs, ok := client.ClientOptsFor(proto)
		if !ok {
			t.Errorf("%s: no client OptSpecs", proto)
			continue
		}
		found := slices.ContainsFunc(specs, func(sp client.OptSpec) bool { return sp.Key == clientPortKey })
		if !found {
			t.Errorf("%s: client declares no %q option, so the derived port would be dropped", proto, clientPortKey)
		}
	}
}

// TestL2TPv3ClientConfigSwapsTheEndsOfEverySymmetricPair: a static pseudowire
// has no control plane, so the two ends are mirror images. This derivation used
// to sit behind an early return that made it unreachable.
func TestL2TPv3ClientConfigSwapsTheEndsOfEverySymmetricPair(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	s.do("POST", "/api/listeners", map[string]any{"name": "pw", "protocol": "l2tpv3",
		"options": map[string]string{
			"session-id": "10", "peer-session-id": "20",
			"cookie": "aabbccdd", "peer-cookie": "11223344",
			"ccid": "1", "peer-ccid": "2",
			"sublayer": "true",
		}, "enabled": true})
	resp, body := s.do("POST", "/api/listeners/pw/client-config",
		map[string]any{"endpoint": "vpn.example.com"})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	var out clientConfigResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	o := out.Profile.Options
	for _, c := range []struct{ key, want string }{
		{"gateway", "vpn.example.com"},
		{"session-id", "20"}, {"peer-session-id", "10"},
		{"cookie", "11223344"}, {"peer-cookie", "aabbccdd"},
		{"ccid", "2"}, {"peer-ccid", "1"},
		{"sublayer", "true"},
	} {
		if o[c.key] != c.want {
			t.Errorf("%s = %q, want %q", c.key, o[c.key], c.want)
		}
	}
}

// TestNebulaClientConfigCarriesTheCAButNotTheLighthouseIdentity: every host in a
// nebula mesh shares the CA and nothing else. The lighthouse's own certificate
// and X25519 key are its identity; bundling them would clone the lighthouse
// rather than provision a peer.
func TestNebulaClientConfigCarriesTheCAButNotTheLighthouseIdentity(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	write := func(name, body string) string {
		p := filepath.Join(s.dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caPath := write("ca.crt", "CA-BUNDLE")
	certPath := write("lighthouse.crt", "LIGHTHOUSE-CERT")
	keyPath := write("lighthouse.key", "LIGHTHOUSE-KEY")
	s.do("POST", "/api/listeners", map[string]any{"name": "mesh", "protocol": "nebula",
		"options": map[string]string{"ca": caPath, "cert": certPath, "key": keyPath, "cipher": "chachapoly"},
		"enabled": true})

	// Without the per-host identity the generation must fail loudly, naming the
	// keys, rather than return a profile that cannot dial.
	resp, body := s.do("POST", "/api/listeners/mesh/client-config", map[string]any{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 without a per-host cert: %s", resp.StatusCode, body)
	}
	for _, want := range []string{"cert", "key"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("error does not name the missing %q option: %s", want, body)
		}
	}

	// With them supplied as overrides it succeeds, and only the CA is bundled.
	resp, body = s.do("POST", "/api/listeners/mesh/client-config", map[string]any{
		"overrides": map[string]string{"cert": "/etc/nebula/host.crt", "key": "/etc/nebula/host.key"}})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	var out clientConfigResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if len(out.Files) != 1 || out.Files[0].Name != "ca.crt" {
		t.Fatalf("want only the CA bundled, got %+v", out.Files)
	}
	if strings.Contains(string(body), "LIGHTHOUSE-CERT") || strings.Contains(string(body), "LIGHTHOUSE-KEY") {
		t.Error("the lighthouse's own identity was handed to a client")
	}
	if out.Profile.Options["cipher"] != "chachapoly" {
		t.Errorf("mesh-wide cipher did not carry: %q", out.Profile.Options["cipher"])
	}
}

// TestNebulaClientConfigRefusesAnEndpoint: nebula hosts are reached at the
// underlay address their lighthouse publishes, so an endpoint here means the
// operator misunderstood. Dropping it silently would hand back a profile that
// looks right and is not.
func TestNebulaClientConfigRefusesAnEndpoint(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	s.do("POST", "/api/listeners", map[string]any{"name": "mesh", "protocol": "nebula",
		"options": map[string]string{"ca": "/x/ca.crt"}, "enabled": true})
	resp, _ := s.do("POST", "/api/listeners/mesh/client-config",
		map[string]any{"endpoint": "vpn.example.com"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an endpoint nebula cannot use", resp.StatusCode)
	}
}

// TestClientConfigNeverReadsAnOperatorSuppliedPath is the arbitrary-file-read
// guard. Override VALUES were unchecked while only their keys were validated,
// so a token holder could name any path a file-path option accepts and read it
// back out of the bundle — as root. Overridden paths are passed through, never
// opened.
func TestClientConfigNeverReadsAnOperatorSuppliedPath(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	secret := filepath.Join(s.dir, "not-mine")
	if err := os.WriteFile(secret, []byte("root:$6$SUPERSECRETHASH"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.do("POST", "/api/listeners", map[string]any{"name": "site-a", "protocol": "openvpn",
		"options": map[string]string{}, "enabled": true})
	resp, body := s.do("POST", "/api/listeners/site-a/client-config",
		map[string]any{"endpoint": "vpn.example.com", "overrides": map[string]string{"ca": secret}})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "SUPERSECRETHASH") {
		t.Fatalf("an operator-supplied path was read and returned: %s", body)
	}
	var out clientConfigResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if len(out.Files) != 0 {
		t.Errorf("override path was bundled: %+v", out.Files)
	}
	if out.Profile.Options["ca"] != secret {
		t.Errorf("override path was rewritten rather than passed through: %q", out.Profile.Options["ca"])
	}
}

// TestClientConfigWarnsAboutAFileItCannotBundle: an unreadable CA used to be
// swallowed, leaving a profile that pointed at an absolute path on the server
// with no companion file and nothing to say the bundle was incomplete.
func TestClientConfigWarnsAboutAFileItCannotBundle(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	missing := filepath.Join(s.dir, "gone.crt")
	s.do("POST", "/api/listeners", map[string]any{"name": "site-a", "protocol": "openvpn",
		"options": map[string]string{"ca": missing}, "enabled": true})
	_, body := s.do("POST", "/api/listeners/site-a/client-config",
		map[string]any{"endpoint": "vpn.example.com"})
	var out clientConfigResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if len(out.Warnings) != 1 || !strings.Contains(out.Warnings[0], "gone.crt") {
		t.Errorf("no warning for the file that could not be bundled: %+v", out.Warnings)
	}
	if out.Profile.Options["ca"] != missing {
		t.Errorf("ca = %q, want the server path left in place", out.Profile.Options["ca"])
	}
}

// TestAllocatedPeerPrefixIsAHostRouteInEitherFamily: a hardcoded /32 turns an
// IPv6 allocation into a route across a quarter of the address space.
func TestAllocatedPeerPrefixIsAHostRouteInEitherFamily(t *testing.T) {
	cases := []struct{ subnet, want string }{
		{"10.20.0.1/24", "10.20.0.2/32"},
		{"fd00::1/64", "fd00::2/128"},
	}
	for _, c := range cases {
		// usedWGAddresses always claims the server's own address first; pass the
		// set the production path would.
		used := usedWGAddresses(map[string]string{wireguard.OptServerAddress: c.subnet})
		got, err := allocateWGAddress(c.subnet, used)
		if err != nil {
			t.Fatalf("allocateWGAddress(%q): %v", c.subnet, err)
		}
		if got.String() != c.want {
			t.Errorf("allocateWGAddress(%q) = %s, want %s", c.subnet, got, c.want)
		}
	}
}

// TestAllocationStopsBeforeTheIPv4Broadcast: the all-ones host is the subnet
// broadcast, and a peer handed it has an address the host stack will not source
// from.
func TestAllocationStopsBeforeTheIPv4Broadcast(t *testing.T) {
	used := map[netip.Addr]bool{}
	for i := 1; i <= 2; i++ {
		used[netip.MustParseAddr("10.0.0."+strconv.Itoa(i))] = true
	}
	// A /30 holds .0 network, .1, .2, .3 broadcast; .1 and .2 are taken.
	if got, err := allocateWGAddress("10.0.0.1/30", used); err == nil {
		t.Errorf("allocated %s, want an error rather than the broadcast address", got)
	}
}

// TestClientConfigWireGuardProvisionsPeer: the WireGuard-family path mints a
// client keypair, allocates an address, appends the peer to the listener, and
// rebuilds it — and the returned profile has everything the client needs.
func TestClientConfigWireGuardProvisionsPeer(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	serverPriv, serverPub, err := keygen.WireGuardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	s.do("POST", "/api/listeners", map[string]any{"name": "wg", "protocol": "wireguard",
		"options": map[string]string{"private-key": serverPriv, "address": "10.20.0.1/24"},
		"enabled": true})
	resp, body := s.do("POST", "/api/listeners/wg/client-config",
		map[string]any{"endpoint": "vpn.example.com"})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	var out clientConfigResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if out.PeersAdded != 1 {
		t.Errorf("PeersAdded = %d, want 1", out.PeersAdded)
	}
	opts := out.Profile.Options
	if opts["private-key"] == "" || opts["public-key"] != serverPub {
		t.Errorf("profile keys wrong: public-key=%q want %q, has private-key=%v", opts["public-key"], serverPub, opts["private-key"] != "")
	}
	if opts["endpoint"] != "vpn.example.com:51820" {
		t.Errorf("endpoint = %q, want vpn.example.com:51820", opts["endpoint"])
	}
	if opts["address"] != "10.20.0.2/32" {
		t.Errorf("allocated address = %q, want 10.20.0.2/32", opts["address"])
	}
	// The peer must be on the listener and the rebuild invoked. The peer's
	// public key is the CLIENT's half — the profile's private key — so the
	// server accepts the generated config's own key.
	cfg := readListenerFile(t, s.dir, "wg")
	var peers []wireguard.ServerPeer
	if err := json.Unmarshal([]byte(cfg.Options[wireguard.OptServerPeers]), &peers); err != nil {
		t.Fatalf("peers option is not JSON: %v", err)
	}
	wantPub, err := keygen.WireGuardPublicKey(out.Profile.Options["private-key"])
	if err != nil {
		t.Fatalf("deriving client pubkey: %v", err)
	}
	if len(peers) != 1 || peers[0].PublicKey != wantPub {
		t.Errorf("peer not provisioned for the generated private key: %+v", peers)
	}
	if s.mgr.(*fakeMgr).rebuildOf != "wg" {
		t.Errorf("Rebuild was not called for the provisioned listener")
	}
	// A second generation allocates the next free address.
	resp2, body2 := s.do("POST", "/api/listeners/wg/client-config",
		map[string]any{"endpoint": "vpn.example.com"})
	if resp2.StatusCode != 200 {
		t.Fatalf("second generation status = %d: %s", resp2.StatusCode, body2)
	}
	var out2 clientConfigResponse
	_ = json.Unmarshal(body2, &out2)
	if out2.Profile.Options["address"] != "10.20.0.3/32" {
		t.Errorf("second allocation = %q, want 10.20.0.3/32", out2.Profile.Options["address"])
	}
}

// TestConcurrentClientConfigAllocatesDistinctAddresses: provisioning is a
// read-modify-write of one listener file, so without the mutate lock two
// operators generating at once each read the same peer array, each allocate the
// same tunnel address, and the second write drops the first peer -- handing out
// a private key the server has never heard of. Both peers must survive and hold
// different addresses.
func TestConcurrentClientConfigAllocatesDistinctAddresses(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	serverPriv, _, err := keygen.WireGuardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	s.do("POST", "/api/listeners", map[string]any{"name": "wg", "protocol": "wireguard",
		"options": map[string]string{"private-key": serverPriv, "address": "10.20.0.1/24"},
		"enabled": true})

	const n = 8
	addrs := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func() {
			defer wg.Done()
			resp, body := s.do("POST", "/api/listeners/wg/client-config",
				map[string]any{"endpoint": "vpn.example.com"})
			if resp.StatusCode != 200 {
				t.Errorf("status = %d: %s", resp.StatusCode, body)
				return
			}
			var out clientConfigResponse
			if err := json.Unmarshal(body, &out); err != nil {
				t.Errorf("response not JSON: %v", err)
				return
			}
			addrs[i] = out.Profile.Options["address"]
		}()
	}
	wg.Wait()

	seen := map[string]bool{}
	for _, a := range addrs {
		if a == "" {
			t.Fatal("a generation returned no address")
		}
		if seen[a] {
			t.Errorf("address %s allocated twice", a)
		}
		seen[a] = true
	}
	cfg := readListenerFile(t, s.dir, "wg")
	var peers []wireguard.ServerPeer
	if err := json.Unmarshal([]byte(cfg.Options[wireguard.OptServerPeers]), &peers); err != nil {
		t.Fatalf("peers option is not JSON: %v", err)
	}
	if len(peers) != n {
		t.Errorf("listener carries %d peers, want %d: a concurrent write was lost", len(peers), n)
	}
}

// TestFailedRebuildRollsBackTheProvisionedPeer: the client's private key exists
// only in the response body, so a provision whose rebuild fails must leave no
// trace. Otherwise the listener permanently carries a peer nobody holds the key
// for, and its address is consumed for good.
func TestFailedRebuildRollsBackTheProvisionedPeer(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	serverPriv, _, err := keygen.WireGuardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	s.do("POST", "/api/listeners", map[string]any{"name": "wg", "protocol": "wireguard",
		"options": map[string]string{"private-key": serverPriv, "address": "10.20.0.1/24"},
		"enabled": true})

	s.mgr.(*fakeMgr).rebuildErr = errors.New("tun busy")
	resp, _ := s.do("POST", "/api/listeners/wg/client-config",
		map[string]any{"endpoint": "vpn.example.com"})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when the rebuild fails", resp.StatusCode)
	}
	cfg := readListenerFile(t, s.dir, "wg")
	if v := cfg.Options[wireguard.OptServerPeers]; v != "" {
		t.Fatalf("failed provision left a peer behind: %s", v)
	}

	// The address it tried to use is free again for the next attempt.
	s.mgr.(*fakeMgr).rebuildErr = nil
	_, body := s.do("POST", "/api/listeners/wg/client-config",
		map[string]any{"endpoint": "vpn.example.com"})
	var out clientConfigResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if out.Profile.Options["address"] != "10.20.0.2/32" {
		t.Errorf("retry allocated %q, want the rolled-back 10.20.0.2/32",
			out.Profile.Options["address"])
	}
}

// TestMergeOptionsRedactedPreservesExisting verifies that a round-trip GET-
// then-PATCH does not clobber a secret: a "<redacted>" value in the patch is
// "do not touch" rather than "replace with <redacted>".
func TestMergeOptionsRedactedPreservesExisting(t *testing.T) {
	existing := map[string]string{"private-key": "the-real-secret", "address": "10.10.0.1/24"}
	patch := map[string]string{"private-key": redacted, "address": "10.20.0.1/24"}
	out := mergeOptions(existing, patch)
	if out["private-key"] != "the-real-secret" {
		t.Errorf("redacted secret was replaced: got %q want the-real-secret", out["private-key"])
	}
	if out["address"] != "10.20.0.1/24" {
		t.Errorf("non-secret patch was not applied: got %q want 10.20.0.1/24", out["address"])
	}
}

// TestBootTokenReadsExistingFile pins the read path: if /path/token exists,
// NewServer uses it; if absent, it mint one with the right perms.
func TestBootTokenReadsExistingFile(t *testing.T) {
	dir := t.TempDir()
	mgmtDir := filepath.Join(dir, "mgmt")
	_ = os.MkdirAll(mgmtDir, 0o700)
	tokenPath := filepath.Join(mgmtDir, tokenName)
	_ = os.WriteFile(tokenPath, []byte("operator-chosen\n"), 0o600)
	tok, fresh, err := bootToken(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if fresh {
		t.Errorf("bootToken reported 'fresh' for an existing file")
	}
	if string(tok) != "operator-chosen" {
		t.Errorf("token = %q, want operator-chosen", tok)
	}
}

// TestBootTokenGeneratesOnFirstRun pins the mint path: the API server boots a
// supervisor against an empty config dir, and the bearer token is created,
// hex-encoded, and 0600 root-only.
func TestBootTokenGeneratesOnFirstRun(t *testing.T) {
	dir := t.TempDir()
	// bootToken's parent is created by NewServer normally; the test reaches it
	// directly so it must create the dir, matching NewServer's contract.
	_ = os.MkdirAll(filepath.Join(dir, "mgmt"), 0o700)
	tokenPath := filepath.Join(dir, "mgmt", tokenName)
	tok, fresh, err := bootToken(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Errorf("bootToken reported not-fresh for a missing file")
	}
	if len(tok) != 64 {
		t.Errorf("token len = %d, want 64 (32 bytes hex-encoded)", len(tok))
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestBearerHeaderParsing pins the "Bearer " prefix parsing; a basic-auth-style
// header or wrong scheme returns no token rather than a half-parse.
// TestRequireHostRejectsRebinding is the DNS-rebinding guard. The panel cannot
// require a token -- it is what hands the browser one -- so a page that rebinds
// its own hostname to the loopback address would become same-origin with the
// panel, read the token out of the DOM, and drive every endpoint. The rebound
// request still carries the name the browser dialled in its Host header, which
// is what this rejects.
func TestRequireHostRejectsRebinding(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := RequireHost([]string{"10.0.0.5:8443"}, inner)

	for _, tc := range []struct {
		host string
		want int
	}{
		{"127.0.0.1:8443", http.StatusOK},
		{"127.0.0.1", http.StatusOK},
		{"localhost:8443", http.StatusOK},
		{"[::1]:8443", http.StatusOK},
		{"10.0.0.5:8443", http.StatusOK}, // the address the operator bound to
		{"attacker.example:8443", http.StatusForbidden},
		{"attacker.example", http.StatusForbidden},
		{"localhost.attacker.example", http.StatusForbidden},
		{"10.0.0.9:8443", http.StatusForbidden}, // some other address on the host
		{"", http.StatusForbidden},
	} {
		req := httptest.NewRequest("GET", "/api/health", nil)
		req.Host = tc.host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("Host %q -> %d, want %d", tc.host, rec.Code, tc.want)
		}
	}
}

// TestPathNameIsValidatedBeforeItBecomesAFilename: only DeleteListenerFile
// checked the name, so the GET and PATCH handlers joined whatever the router
// matched into a path. Go's ServeMux makes that hard to abuse, but a string that
// becomes a filename gets checked.
func TestPathNameIsValidatedBeforeItBecomesAFilename(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	for _, bad := range []string{"UPPERCASE", "has.dot", "-leading-hyphen", "with%20space"} {
		resp, _ := s.do("GET", "/api/listeners/"+bad, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET name %q -> %d, want 404", bad, resp.StatusCode)
		}
	}
}

func TestBearerHeaderParsing(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Bearer abc", "abc"},
		{"bearer abc", "abc"},
		{"BEARER abc", "abc"},
		{"Bearer abc ", "abc"},
		{"Bearer  abc ", "abc"},
		{"Token abc", ""},
		{"", ""},
		{"abc", ""},
	} {
		got := bearer(tc.in)
		if tc.want == "" {
			if got != nil {
				t.Errorf("%q: got %q, want nil", tc.in, got)
			}
		} else if string(got) != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRedactOptionsLeavesNonSecretKeysUntouched verifies redaction only
// touches keys declared Secret by the protocol's OptSpec metadata.
func TestRedactOptionsLeavesNonSecretKeysUntouched(t *testing.T) {
	opts := map[string]string{"private-key": "k", "address": "10.10.0.1/24"}
	out := redactOptions("wireguard", opts)
	if out["private-key"] != redacted {
		t.Errorf("private-key not redacted: %q", out["private-key"])
	}
	if out["address"] != "10.10.0.1/24" {
		t.Errorf("non-secret address was redacted: %q", out["address"])
	}
}

// TestPeerEndpointReturnsPeersForDescriber protocol that implements PeerDescriber
// returns real peer data; a protocol that does not returns an empty array.
func TestPeerEndpointReturnsPeersForDescriber(t *testing.T) {
	statuses := map[string]supervisor.Status{"site-a": {Name: "site-a", Protocol: "wireguard", State: "running"}}
	dir := t.TempDir()
	for name := range statuses {
		cfg := supervisor.ListenerConfig{Name: name, Protocol: "wireguard",
			Options: map[string]string{"private-key": "k"}, Enabled: true}
		body, _ := json.Marshal(cfg)
		_ = os.WriteFile(filepath.Join(dir, name+".json"), body, 0o600)
	}
	mgr := &fakeMgr{
		statuses:   statuses,
		peerServer: &fakePeerDescriber{peers: []client.PeerInfo{{ID: "AAAA", Address: "10.10.0.2", State: "connected"}}},
	}
	srv, err := NewServer(dir, mgr, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	resp, body := srv.do("GET", "/api/listeners/site-a/peers", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "AAAA") {
		t.Errorf("peer list does not contain the fake peer: %s", body)
	}
}

// fakePeerDescriber is a client.Server + client.PeerDescriber for testing
// the peers endpoint without opening a real TUN.
type fakePeerDescriber struct {
	peers []client.PeerInfo
}

func (f *fakePeerDescriber) ListenAndServe() error { return nil }
func (f *fakePeerDescriber) Close() error          { return nil }
func (f *fakePeerDescriber) TUNName() string       { return "tun0" }
func (f *fakePeerDescriber) Gateway() net.IP       { return net.IPv4(10, 10, 0, 1) }
func (f *fakePeerDescriber) Network() *net.IPNet {
	_, n, _ := net.ParseCIDR("10.10.0.0/24")
	return n
}
func (f *fakePeerDescriber) Peers() []client.PeerInfo { return f.peers }

// Suppress "unused" errors for net.IP we want to keep imported for parity with
// a future IPv6 listener status field.
var _ = net.IP{}
