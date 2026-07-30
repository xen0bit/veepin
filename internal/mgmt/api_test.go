package mgmt

// Tests for the management API. They use httptest and a fake supervisor
// (a *fakeMgr implementing the manager-ish surface the API calls) so the
// endpoint behavior is verified without sockets or TUNs.

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/supervisor"

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
	return nil
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
