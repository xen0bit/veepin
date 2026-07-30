package supervisor

// Tests for the listener config parser and validation. Run under `go test`
// without privileges -- no TUN is opened, no sockets bound.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func mustWriteFile(t *testing.T, path, name, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

// TestParseListenerBytesRoundTrip pins the JSON shape: marshal a config and
// parse it back, the roundtrip the management API relies on (a POST=parsed,
// GET=re-serialized would lose a field otherwise).
func TestParseListenerBytesRoundTrip(t *testing.T) {
	in := ListenerConfig{
		Name:     "site-a",
		Protocol: "wireguard",
		Options:  map[string]string{"private-key": "k", "address": "10.10.0.1/24"},
		SetupNAT: true,
		WAN:      "eth0",
		Enabled:  true,
	}
	body, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out, err := parseListenerBytes(body)
	if err != nil {
		t.Fatalf("parseListenerBytes: %v", err)
	}
	if out.Name != in.Name || out.Protocol != in.Protocol || out.SetupNAT != in.SetupNAT ||
		out.WAN != in.WAN || out.Enabled != in.Enabled || out.Options["address"] != "10.10.0.1/24" {
		t.Errorf("roundtrip lost fields: %+v", out)
	}
}

// TestParseListenerBytesRejectsUnknownFields pins DisallowUnknownFields: a
// config with a key the struct does not have is a typo a future config schema
// change must not silently ignore.
func TestParseListenerBytesRejectsUnknownFields(t *testing.T) {
	body := []byte(`{"name":"x","protocol":"wireguard","bogus":true}`)
	if _, err := parseListenerBytes(body); err == nil {
		t.Errorf("accepted unknown field 'bogus'")
	}
}

// TestValidateRejectsBadName covers the name grammar: each rejected case is
// either an unsafe filename character or an unsafe iptables comment fragment.
// The list is not exhaustive -- it names the categories that matter.
// TestEnabledDefaultsToTrue: the obvious minimal config -- name, protocol,
// options and nothing else -- describes a listener the operator wants running.
// A zero-value Go bool defaulted the other way, so such a file parsed,
// validated, listed, and never started, with no error and no log line.
func TestEnabledDefaultsToTrue(t *testing.T) {
	c, err := parseListenerBytes([]byte(`{"name":"site-a","protocol":"wireguard"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !c.Enabled {
		t.Error("a config that does not mention enabled parsed as disabled")
	}
}

// TestEnabledFalseIsHonoured: the default must not swallow an explicit opt-out.
func TestEnabledFalseIsHonoured(t *testing.T) {
	c, err := parseListenerBytes([]byte(`{"name":"site-a","protocol":"wireguard","enabled":false}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Enabled {
		t.Error(`"enabled": false was ignored`)
	}
}

// TestDisabledSurvivesAWriteReadRoundTrip is why the enabled tag carries no
// omitempty. With omitempty a disabled listener's file would omit the key
// entirely, and the default above would read it straight back as enabled -- so
// disabling a listener through the API would not survive the write.
func TestDisabledSurvivesAWriteReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := ListenerConfig{Name: "site-a", Protocol: "wireguard", Enabled: false}
	if err := WriteListenerFile(dir, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := ParseListenerFile(filepath.Join(dir, "site-a.json"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if out.Enabled {
		t.Error("a disabled listener came back enabled after a write/read round trip")
	}
}

func TestValidateRejectsBadName(t *testing.T) {
	for _, bad := range []string{
		"", "UPPER", "with space", "with.dot", "with/slash", "with\\back",
		"-leading-dash", "012345678901234567890123456789012", // 33 octets
		"ä-umlaut",
	} {
		if err := (ListenerConfig{Name: bad, Protocol: "wireguard"}).Validate(); err == nil {
			t.Errorf("name %q should be rejected", bad)
		}
	}
}

// TestValidateAcceptsGoodName covers names the manager and hostnet will both
// accept in the same form.
func TestValidateAcceptsGoodName(t *testing.T) {
	for _, good := range []string{"a", "site-a", "branch1", "edge-2-of-3"} {
		if err := (ListenerConfig{Name: good, Protocol: "wireguard"}).Validate(); err != nil {
			t.Errorf("name %q rejected: %v", good, err)
		}
	}
}

// TestValidateRequiresProtocol pins the one non-name field the parser checks.
func TestValidateRequiresProtocol(t *testing.T) {
	if err := (ListenerConfig{Name: "a"}).Validate(); err == nil {
		t.Errorf("accepted empty protocol")
	}
}

// TestLoadDirParsesAndDedupes covers the directory read side: the listener set
// is keyed by the parsed "name" field, and a duplicate across two files is an
// error because one name maps to exactly one listener.
func TestLoadDirParsesAndDedupes(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "site-a.json"), "site-a.json",
		`{"name":"site-a","protocol":"wireguard","options":{"private-key":"k"}}`)
	mustWriteFile(t, filepath.Join(dir, "site-b.json"), "site-b.json",
		`{"name":"site-b","protocol":"ikev2","options":{"psk":"x"}}`)
	// Non-json files are ignored.
	mustWriteFile(t, filepath.Join(dir, "notes.txt"), "notes.txt", "ignore me")
	// Subdirectories are ignored by ReadDir's non-recursive read.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfgs, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(cfgs) != 2 || cfgs["site-a"].Protocol != "wireguard" || cfgs["site-b"].Protocol != "ikev2" {
		t.Errorf("cfgs = %+v", cfgs)
	}
}

// TestLoadDirDuplicateNameIsError pins the one-pool rule.
func TestLoadDirDuplicateNameIsError(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "a.json"), "a.json",
		`{"name":"dup","protocol":"wireguard"}`)
	mustWriteFile(t, filepath.Join(dir, "b.json"), "b.json",
		`{"name":"dup","protocol":"ikev2"}`)
	if _, err := LoadDir(dir); err == nil {
		t.Errorf("accepted duplicate name 'dup'")
	}
}

// TestLoadDirStopsAtFirstBrokenFile pins that a malformed file aborts the whole
// apply: a config error must surface, not silently drop one listener while the
// rest come up.
func TestLoadDirStopsAtFirstBrokenFile(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "good.json"), "good.json",
		`{"name":"good","protocol":"wireguard"}`)
	mustWriteFile(t, filepath.Join(dir, "bad.json"), "bad.json",
		`{"name":"bad","protocol":`)
	if _, err := LoadDir(dir); err == nil {
		t.Errorf("accepted malformed JSON")
	}
}

// TestWriteListenerFileIsAtomicAndPermsLocked covers the persistence side:
// a write is atomic (no .tmp left behind, no half-written file) and 0600 so
// the Options map's secrets stay root-only.
func TestWriteListenerFileIsAtomicAndPermsLocked(t *testing.T) {
	dir := t.TempDir()
	cfg := ListenerConfig{Name: "site-a", Protocol: "wireguard",
		Options: map[string]string{"private-key": "secret"}}
	if err := WriteListenerFile(dir, cfg); err != nil {
		t.Fatalf("WriteListenerFile: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "site-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("listener file mode = %v, want 0600", info.Mode().Perm())
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(matches) != 0 {
		t.Errorf("temp file left behind: %v", matches)
	}
}

// TestWriteThenDeleteRoundTrip pins the management API's delete path.
func TestWriteThenDeleteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := ListenerConfig{Name: "x", Protocol: "wireguard"}
	if err := WriteListenerFile(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := DeleteListenerFile(dir, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x.json")); !os.IsNotExist(err) {
		t.Errorf("file still exists: %v", err)
	}
}

// TestDeleteListenerFileRejectsBadName pins path-traversal safety: the file
// delete path interpolates a child of name into a target path; an unchecked name
// would let a caller reach ../etc/anything.
func TestDeleteListenerFileRejectsBadName(t *testing.T) {
	dir := t.TempDir()
	if err := DeleteListenerFile(dir, "../escape"); err == nil {
		t.Error("accepted a name with a path separator")
	}
}
