package main

// Tests for the client profile commands. Each test operates on a temp dir,
// injecting it as VEEPIN_PROFILE_DIR so the default XDG_CONFIG_HOME path is not
// touched. The connect-resolution path (knownProtocol guard) is tested directly.

import (
	"os"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/profile"
)

func TestProfileAddAndList(t *testing.T) {
	dir := tempProfileDir(t)
	writeStdin(t, `{"name":"home","protocol":"wireguard","options":{"endpoint":"1.2.3.4:51820"}}`)
	if err := runProfile([]string{"add"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	cfgs, err := profile.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 1 || cfgs["home"].Protocol != "wireguard" {
		t.Errorf("not persisted: %+v", cfgs)
	}
}

func TestProfileAddValidatesName(t *testing.T) {
	_ = tempProfileDir(t)
	writeStdin(t, `{"name":"UPPER","protocol":"wireguard"}`)
	if err := runProfile([]string{"add"}); err == nil {
		t.Errorf("accepted bad name")
	}
}

func TestProfileRm(t *testing.T) {
	dir := tempProfileDir(t)
	writeStdin(t, `{"name":"home","protocol":"wireguard"}`)
	_ = runProfile([]string{"add"})
	if err := runProfile([]string{"rm", "home"}); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("dir removed? %v", err)
	}
}

func TestKnownProtocolExists(t *testing.T) {
	if !knownProtocol("toy") {
		t.Errorf("toy not recognised as a known protocol")
	}
}

func TestKnownProfileFallback(t *testing.T) {
	if knownProtocol("this-is-not-a-protocol-i-hope") {
		t.Errorf("bogus name misidentified as a protocol")
	}
}

// TestApplyOverrides pins the -set merge: a key=value replaces the profile's
// stored value, an unknown key is added, and the profile map itself is not
// mutated (so a later dial without -set sees the original values).
func TestApplyOverrides(t *testing.T) {
	orig := map[string]string{"server": "old.example", "user": "alice"}
	out, err := applyOverrides(orig, []string{"server=new.example", "port=8443"})
	if err != nil {
		t.Fatalf("applyOverrides: %v", err)
	}
	if out["server"] != "new.example" {
		t.Errorf("server = %q, want new.example", out["server"])
	}
	if out["port"] != "8443" {
		t.Errorf("port = %q, want 8443", out["port"])
	}
	if orig["server"] != "old.example" {
		t.Errorf("the profile's own map was mutated: %v", orig)
	}
	if _, err := applyOverrides(orig, []string{"not-an-override"}); err == nil {
		t.Errorf("a -set without '=' was accepted")
	}
}

func TestConnectUsagePrintsProtocols(t *testing.T) {
	err := runConnect(nil)
	if err == nil || !strings.Contains(err.Error(), strings.Join(client.Protocols(), ", ")) {
		t.Errorf("usage error does not list protocols: %v", err)
	}
}

func TestProfileAddFromFlags(t *testing.T) {
	dir := tempProfileDir(t)
	if err := runProfile([]string{"add", "home", "toy",
		"-server", "1.2.3.4", "-user", "alice", "-insecure-shared-secret", "s3cret"}); err != nil {
		t.Fatalf("add from flags: %v", err)
	}
	cfgs, err := profile.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := cfgs["home"]
	if !ok {
		t.Fatalf("profile not persisted: %+v", cfgs)
	}
	if cfg.Protocol != "toy" {
		t.Errorf("protocol = %q, want toy", cfg.Protocol)
	}
	if cfg.Options["server"] != "1.2.3.4" || cfg.Options["user"] != "alice" {
		t.Errorf("flag values did not reach the options map: %+v", cfg.Options)
	}
}

func TestProfileAddFromFlagsRejectsUnknownProtocol(t *testing.T) {
	_ = tempProfileDir(t)
	if err := runProfile([]string{"add", "x", "no-such-protocol", "-server", "h"}); err == nil {
		t.Errorf("accepted an unknown protocol")
	}
}

func TestProfileShowRedactsSecrets(t *testing.T) {
	dir := tempProfileDir(t)
	cfg := profile.Config{Name: "home", Protocol: "toy",
		Options: map[string]string{"server": "1.2.3.4", "user": "alice", "secret": "topsecret"}}
	if err := profile.Write(dir, cfg); err != nil {
		t.Fatal(err)
	}
	out, err := runProfileCapturing(t, []string{"show", "home"})
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if strings.Contains(out, "topsecret") {
		t.Errorf("show leaked a secret value: %s", out)
	}
	if !strings.Contains(out, "<redacted>") {
		t.Errorf("show did not mark the secret redacted: %s", out)
	}
}

func TestProfileShowSecretsFlagDisplaysValues(t *testing.T) {
	dir := tempProfileDir(t)
	cfg := profile.Config{Name: "home", Protocol: "toy",
		Options: map[string]string{"server": "1.2.3.4", "user": "alice", "secret": "topsecret"}}
	if err := profile.Write(dir, cfg); err != nil {
		t.Fatal(err)
	}
	out, err := runProfileCapturing(t, []string{"show", "home", "-secrets"})
	if err != nil {
		t.Fatalf("show -secrets: %v", err)
	}
	if !strings.Contains(out, "topsecret") {
		t.Errorf("show -secrets did not print the value: %s", out)
	}
}

// runProfileCapturing runs runProfile with os.Stdout swapped for a pipe and
// returns what it printed, so a test can assert on output the command owns.
func runProfileCapturing(t *testing.T, args []string) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf strings.Builder
		b := make([]byte, 4096)
		for {
			n, err := r.Read(b)
			buf.Write(b[:n])
			if err != nil {
				break
			}
		}
		done <- buf.String()
	}()
	err := runProfile(args)
	_ = w.Close()
	out := <-done
	os.Stdout = old
	return out, err
}

// tempProfileDir creates a temp dir and points VEEPIN_PROFILE_DIR at it.
func tempProfileDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("VEEPIN_PROFILE_DIR", dir)
	return dir
}

// writeStdin replaces os.Stdin with a pipe carrying content. Callers should
// restore the original stdin after the test (temp dir cleanup does this via
// the test's TempDir, but stdin is a global so t.Setenv doesn't cover it).
func writeStdin(t *testing.T, content string) {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
	go func() { _, _ = w.Write([]byte(content)); _ = w.Close() }()
}
