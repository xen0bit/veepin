package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func mustWriteJSON(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", filepath.Base(path), err)
	}
}

func TestParseBytesRoundTrip(t *testing.T) {
	in := Config{
		Name:     "home",
		Protocol: "wireguard",
		Options:  map[string]string{"private-key": "k", "address": "10.10.0.2/24"},
	}
	body, _ := json.MarshalIndent(in, "", "  ")
	out, err := parseBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != "home" || out.Protocol != "wireguard" || out.Options["address"] != "10.10.0.2/24" {
		t.Errorf("roundtrip lost fields: %+v", out)
	}
}

func TestParseBytesRejectsUnknownFields(t *testing.T) {
	if _, err := parseBytes([]byte(`{"name":"x","protocol":"wireguard","bogus":true}`)); err == nil {
		t.Errorf("accepted unknown field 'bogus'")
	}
}

func TestValidateRejectsBadName(t *testing.T) {
	for _, bad := range []string{"", "UPPER", "with space", "../../escape"} {
		if err := (Config{Name: bad, Protocol: "wireguard"}).Validate(); err == nil {
			t.Errorf("name %q should be rejected", bad)
		}
	}
}

func TestValidateRejectsEmptyProtocol(t *testing.T) {
	if err := (Config{Name: "ok"}).Validate(); err == nil {
		t.Errorf("accepted empty protocol")
	}
}

func TestWriteThenReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Name: "home", Protocol: "wireguard",
		Options: map[string]string{"private-key": "secret"}}
	if err := Write(dir, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "home.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("profile file mode = %v, want 0600", info.Mode().Perm())
	}
	got, err := ParseFile(filepath.Join(dir, "home.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Options["private-key"] != "secret" {
		t.Errorf("secret lost: %+v", got)
	}
}

func TestWriteThenDeleteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Name: "home", Protocol: "wireguard"}
	if err := Write(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := Delete(dir, "home"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "home.json")); !os.IsNotExist(err) {
		t.Errorf("file still exists after delete: %v", err)
	}
}

func TestDeleteRejectsBadName(t *testing.T) {
	dir := t.TempDir()
	if err := Delete(dir, "../escape"); err == nil {
		t.Error("accepted a path-traversal name")
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	mustWriteJSON(t, filepath.Join(dir, "home.json"),
		`{"name":"home","protocol":"wireguard","options":{"endpoint":"1.2.3.4:51820"}}`)
	mustWriteJSON(t, filepath.Join(dir, "office.json"),
		`{"name":"office","protocol":"ikev2","options":{"psk":"x"}}`)
	mustWriteJSON(t, filepath.Join(dir, "notes.txt"), "ignore me")

	cfgs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 2 {
		t.Errorf("got %d profiles, want 2", len(cfgs))
	}
	if cfgs["home"].Protocol != "wireguard" || cfgs["office"].Protocol != "ikev2" {
		t.Errorf("profiles: %+v", cfgs)
	}
}

func TestLoadDirDuplicateNameIsError(t *testing.T) {
	dir := t.TempDir()
	mustWriteJSON(t, filepath.Join(dir, "a.json"), `{"name":"dup","protocol":"wg"}`)
	mustWriteJSON(t, filepath.Join(dir, "b.json"), `{"name":"dup","protocol":"ikev2"}`)
	if _, err := LoadDir(dir); err == nil {
		t.Errorf("accepted duplicate name")
	}
}
