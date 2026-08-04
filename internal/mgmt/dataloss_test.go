package mgmt

// The tests for the four ways the management plane could destroy or expose
// something it was holding. Each one failed before the fix that shares its
// name's subject, and each names the operator-visible consequence rather than
// the mechanism, because the mechanism is the part that moves.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/internal/supervisor"
)

// TestDeleteRefusesTheConfigRootsOwnDirectories: the DELETE handler cleans up a
// listener's generated key material with os.RemoveAll(<dir>/<name>), before the
// file-existence check so an orphaned key directory is still reachable. The
// name grammar admitted "mgmt" and "profiles", which are the config root's own
// two subdirectories -- so DELETE /api/listeners/profiles deleted every client
// profile on the box and answered 404 "no such listener", and
// DELETE /api/listeners/mgmt deleted the bearer token, which breaks nothing
// until the next restart mints a new one and every stored token goes dead.
func TestDeleteRefusesTheConfigRootsOwnDirectories(t *testing.T) {
	profiles := t.TempDir()
	s, _, _ := newTestServerWithProfiles(t, map[string]supervisor.Status{}, profiles)
	s.do("POST", "/api/profiles", map[string]any{"name": "home", "protocol": "toy",
		"options": map[string]string{"server": "vpn.example.com", "user": "a", "secret": "s"}})

	// The token directory NewServer created, and a profile, both under names the
	// grammar would otherwise accept as listeners.
	tokenDir := filepath.Join(s.dir, "mgmt")
	if _, err := os.Stat(tokenDir); err != nil {
		t.Fatalf("token dir missing before the test even starts: %v", err)
	}

	for _, name := range []string{"mgmt", "profiles"} {
		resp, body := s.do("DELETE", "/api/listeners/"+name, nil)
		if resp.StatusCode != 400 {
			t.Errorf("DELETE /api/listeners/%s = %d, want 400: %s", name, resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "reserved") {
			t.Errorf("DELETE /api/listeners/%s did not say why: %s", name, body)
		}
	}

	if _, err := os.Stat(tokenDir); err != nil {
		t.Errorf("the bearer token directory was deleted: %v", err)
	}
	resp, body := s.do("GET", "/api/profiles/home", nil)
	if resp.StatusCode != 200 {
		t.Errorf("the profile was deleted: GET = %d: %s", resp.StatusCode, body)
	}
}

// TestReservedNamesCannotBeCreatedEither closes the other half: refusing the
// delete would be no help if a listener could be created under the name in the
// first place, since generateListenerKeys writes its PEMs into <dir>/<name>/.
func TestReservedNamesCannotBeCreatedEither(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	for _, name := range []string{"mgmt", "profiles"} {
		resp, body := s.do("POST", "/api/listeners", map[string]any{
			"name": name, "protocol": "toy", "enabled": true})
		if resp.StatusCode != 400 {
			t.Errorf("POST a listener named %q = %d, want 400: %s", name, resp.StatusCode, body)
		}
	}
}

// TestPatchToAnotherProtocolDoesNotDeclassifyTheOldOnesSecrets: redaction is
// resolved against the listener's CURRENT protocol, and the patch merge kept
// every key it was not told about. So one PATCH moved a live secret out of the
// redaction set:
//
//	POST  {"protocol":"ikev2","options":{"psk":"REAL"}}
//	PATCH {"protocol":"toy"}
//	GET   -> the psk, in the clear, because toy declares no psk spec
func TestPatchToAnotherProtocolDoesNotDeclassifyTheOldOnesSecrets(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	const secret = "the-real-preshared-key"
	resp, body := s.do("POST", "/api/listeners", map[string]any{
		"name": "site-a", "protocol": "ikev2",
		"options": map[string]string{"psk": secret, "subnet": "10.9.0.0/24"},
		"enabled": true})
	if resp.StatusCode != 201 {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	if resp, body = s.do("PATCH", "/api/listeners/site-a",
		map[string]any{"protocol": "toy"}); resp.StatusCode >= 400 {
		t.Fatalf("patch = %d: %s", resp.StatusCode, body)
	}

	_, body = s.do("GET", "/api/listeners/site-a", nil)
	if strings.Contains(string(body), secret) {
		t.Errorf("the ikev2 psk is readable through the API after switching to toy: %s", body)
	}
	// And it is not merely hidden by the response: the option is gone from the
	// stored config, because a key the new protocol never reads is dead config
	// whose only remaining property was that it could leak.
	stored, err := os.ReadFile(filepath.Join(s.dir, "site-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), secret) {
		t.Errorf("the ikev2 psk survives in the stored config after switching to toy: %s", stored)
	}
}

// TestCreateRefusesTheRedactionSentinelAsAValue: the sentinel means "keep what
// is stored", and only PATCH goes through the merge that honours it. A create
// decoded straight into the config, so GET-edit-POST-under-a-new-name -- the
// obvious way to clone a listener -- stored the literal string "<redacted>" as
// the private key. Being non-empty it then suppressed key generation, and the
// whole thing answered 201.
func TestCreateRefusesTheRedactionSentinelAsAValue(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	resp, body := s.do("POST", "/api/listeners", map[string]any{
		"name": "clone", "protocol": "wireguard",
		"options": map[string]string{"private-key": redacted, "address": "10.10.0.1/24"},
		"enabled": true})
	if resp.StatusCode != 400 {
		t.Fatalf("create with the sentinel = %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "private-key") {
		t.Errorf("the refusal does not name the offending option: %s", body)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "clone.json")); !os.IsNotExist(err) {
		t.Errorf("a config was written anyway: %v", err)
	}
}

// TestPartialKeySupplyIsRefusedRatherThanHalfGenerated: whether a generator ran
// was decided per spec, and the loop skipped a spec the operator had already
// filled BEFORE recording that its generator had been considered. So supplying
// one of x509-chain's three outputs left the other two empty, ran the generator
// anyway, O_TRUNC-wrote all three PEMs, and merged only into the empty keys --
// storing a freshly generated certificate next to the operator's unrelated
// private key. 201 Created, and every TLS handshake fails.
func TestPartialKeySupplyIsRefusedRatherThanHalfGenerated(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	keyPath := filepath.Join(t.TempDir(), "my-own.key")
	const mine = "-----BEGIN EC PRIVATE KEY-----\nMINE\n-----END EC PRIVATE KEY-----\n"
	if err := os.WriteFile(keyPath, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, body := s.do("POST", "/api/listeners", map[string]any{
		"name": "site-a", "protocol": "openvpn",
		"options": map[string]string{"key": keyPath, "subnet": "10.8.0.0/24"},
		"enabled": true})
	if resp.StatusCode < 400 {
		t.Fatalf("partial key supply = %d, want a refusal: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "all of them or none") {
		t.Errorf("the refusal does not explain the rule: %s", body)
	}
	// The operator's own key is untouched, and no half-set was left behind.
	got, err := os.ReadFile(keyPath)
	if err != nil || string(got) != mine {
		t.Errorf("the operator's key was overwritten: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "site-a")); !os.IsNotExist(err) {
		t.Errorf("a key directory survives the refusal: %v", err)
	}
}

// TestProfileCreateRunsTheProtocolsOwnParse: Config.Validate checks only the
// envelope -- a name and a known protocol -- so the panel saved a wireguard
// profile with no options at all, answered 201, and the operator found out at
// `veepin connect` that private-key was required. `veepin profile add` refused
// the identical document, which is the tell: the CLI validated and the API,
// the consumer the OptSpec tables were actually written for, did not.
func TestProfileCreateRunsTheProtocolsOwnParse(t *testing.T) {
	profiles := t.TempDir()
	s, _, _ := newTestServerWithProfiles(t, map[string]supervisor.Status{}, profiles)

	resp, body := s.do("POST", "/api/profiles",
		map[string]any{"name": "home", "protocol": "wireguard", "options": map[string]string{}})
	if resp.StatusCode != 400 {
		t.Fatalf("empty wireguard profile = %d, want 400: %s", resp.StatusCode, body)
	}
	if _, err := os.Stat(filepath.Join(profiles, "home.json")); !os.IsNotExist(err) {
		t.Errorf("an unusable profile was written: %v", err)
	}

	// The same document the CLI accepts is accepted here.
	resp, body = s.do("POST", "/api/profiles", map[string]any{"name": "home", "protocol": "toy",
		"options": map[string]string{"server": "vpn.example.com", "user": "a", "secret": "s"}})
	if resp.StatusCode != 201 {
		t.Fatalf("valid profile = %d, want 201: %s", resp.StatusCode, body)
	}

	// And a PATCH cannot walk it back into an unusable state.
	resp, body = s.do("PATCH", "/api/profiles/home", map[string]any{
		"options": map[string]string{"server": ""}})
	if resp.StatusCode != 400 {
		t.Errorf("PATCH clearing a required option = %d, want 400: %s", resp.StatusCode, body)
	}
	var stored map[string]any
	_, raw := s.do("GET", "/api/profiles/home", nil)
	_ = json.Unmarshal(raw, &stored)
	if opts, _ := stored["options"].(map[string]any); opts["server"] != "vpn.example.com" {
		t.Errorf("the rejected PATCH still changed the stored profile: %v", stored)
	}
}

// TestClientConfigWarnsWhenTheCertDoesNotCoverTheEndpoint: a listener's
// certificate SANs are fixed when it is created; the endpoint is supplied here,
// possibly months later by someone else. Nothing compared them, so the generated
// profile was well-formed and every connection made with it failed name
// verification -- which reads as a certificate problem long after anyone could
// connect it to a hostnames field they left empty.
func TestClientConfigWarnsWhenTheCertDoesNotCoverTheEndpoint(t *testing.T) {
	s, _, _ := newTestServer(t, map[string]supervisor.Status{})
	resp, body := s.do("POST", "/api/listeners", map[string]any{
		"name": "site-a", "protocol": "openvpn",
		"options": map[string]string{"subnet": "10.8.0.0/24"},
		"enabled": true})
	if resp.StatusCode != 201 {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	// No hostnames given, so the chain covers loopback and "site-a" only.
	_, body = s.do("POST", "/api/listeners/site-a/client-config",
		map[string]any{"endpoint": "vpn.example.com"})
	var out clientConfigResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	var found string
	for _, w := range out.Warnings {
		if strings.Contains(w, "vpn.example.com") {
			found = w
		}
	}
	if found == "" {
		t.Fatalf("no warning that the cert does not cover the endpoint: %+v", out.Warnings)
	}
	if !strings.Contains(found, "hostnames") {
		t.Errorf("the warning does not say how to fix it: %q", found)
	}

	// A listener whose hostnames DO cover the endpoint warns about nothing.
	resp, body = s.do("POST", "/api/listeners", map[string]any{
		"name": "site-b", "protocol": "openvpn",
		"options":   map[string]string{"subnet": "10.8.1.0/24"},
		"hostnames": []string{"vpn.example.com"},
		"enabled":   true})
	if resp.StatusCode != 201 {
		t.Fatalf("create site-b = %d: %s", resp.StatusCode, body)
	}
	_, body = s.do("POST", "/api/listeners/site-b/client-config",
		map[string]any{"endpoint": "vpn.example.com"})
	out = clientConfigResponse{}
	_ = json.Unmarshal(body, &out)
	for _, w := range out.Warnings {
		if strings.Contains(w, "does not cover") {
			t.Errorf("warned about a certificate that does cover the endpoint: %q", w)
		}
	}
}
