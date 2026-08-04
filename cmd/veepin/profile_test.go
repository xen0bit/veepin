package main

// Tests for the client profile commands. Each test operates on a temp dir,
// injecting it as VEEPIN_PROFILE_DIR so the default XDG_CONFIG_HOME path is not
// touched. The connect-resolution path (knownProtocol guard) is tested directly.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/profile"
)

func TestProfileAddAndList(t *testing.T) {
	dir := tempProfileDir(t)
	writeStdin(t, `{"name":"home","protocol":"wireguard","options":{"private-key":"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=","public-key":"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=","endpoint":"1.2.3.4:51820","address":"10.0.0.2/32","allowed-ips":"0.0.0.0/0"}}`)
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

// TestProfileAddRejectsUndialableConfigs: a profile the protocol's parse would
// refuse is rejected at save time, by both forms. The alternative is a profile
// that saves cleanly and fails at `veepin connect` with a mystery error -- the
// exact gap client.ValidateOptions exists to close.
func TestProfileAddRejectsUndialableConfigs(t *testing.T) {
	// Stdin form: a wireguard profile with an endpoint and none of the keys the
	// parse requires.
	_ = tempProfileDir(t)
	writeStdin(t, `{"name":"bad-stdin","protocol":"wireguard","options":{"endpoint":"1.2.3.4:51820"}}`)
	if err := runProfile([]string{"add"}); err == nil {
		t.Error("stdin form saved a wireguard profile with no keys")
	} else if !strings.Contains(err.Error(), "required") {
		t.Errorf("error does not name the missing option: %v", err)
	}

	// And an unknown protocol must be refused, not silently saved.
	_ = tempProfileDir(t)
	writeStdin(t, `{"name":"bogus","protocol":"not-a-protocol","options":{}}`)
	if err := runProfile([]string{"add"}); err == nil {
		t.Error("stdin form saved a profile with an unknown protocol")
	} else if !strings.Contains(err.Error(), "unknown protocol") {
		t.Errorf("error does not name the unknown protocol: %v", err)
	}
}

func TestProfileRm(t *testing.T) {
	dir := tempProfileDir(t)
	writeStdin(t, `{"name":"home","protocol":"wireguard","options":{"private-key":"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=","public-key":"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=","endpoint":"1.2.3.4:51820","address":"10.0.0.2/32","allowed-ips":"0.0.0.0/0"}}`)
	_ = runProfile([]string{"add"})
	// -y: rm is destructive and prompts at a terminal, and a test must not
	// depend on the runner's stdin being a pipe rather than a tty.
	if err := runProfile([]string{"rm", "home", "-y"}); err != nil {
		t.Fatalf("rm: %v", err)
	}
	// The profile file is gone. This used to stat the DIRECTORY, which `rm`
	// never touches, so a no-op profile.Delete passed.
	if _, err := os.Stat(filepath.Join(dir, "home.json")); !os.IsNotExist(err) {
		t.Errorf("home.json survives rm: %v", err)
	}
	// And the directory it lived in is still there, ready for the next one.
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("rm removed the profile directory: %v", err)
	}
	// A second rm has nothing to remove and says so, rather than reporting
	// success for a profile that does not exist.
	if err := runProfile([]string{"rm", "home", "-y"}); err == nil {
		t.Error("rm of a missing profile reported success")
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

// TestConnectResolvesProfilesFromVEEPIN_PROFILE_DIR: `veepin connect <name>`
// must look in the same directory the profile subcommands write to. A profile
// saved into a custom VEEPIN_PROFILE_DIR that connect refuses to see is a
// profile that can be created but never dialed; the CLI resolved profiles from
// the XDG default regardless of the env var until the resolution was unified.
func TestConnectResolvesProfilesFromVEEPIN_PROFILE_DIR(t *testing.T) {
	dir := tempProfileDir(t)
	// A toy profile with no options: toy's ParseFunc rejects the empty set with
	// a fast, no-I/O "server is required", which is exactly the signal we want —
	// reaching that error proves the profile was found and dialed from the
	// custom dir, rather than the resolution having given up with "neither a
	// protocol nor a saved profile".
	cfg := profile.Config{Name: "mytoy", Protocol: "toy"}
	if err := profile.Write(dir, cfg); err != nil {
		t.Fatal(err)
	}
	err := runConnect([]string{"mytoy"})
	if err == nil {
		t.Fatal("connect succeeded for a toy profile with no server (it should fail the parse)")
	}
	if !strings.Contains(err.Error(), "toy: server is required") {
		t.Errorf("connect did not dial the custom-dir profile; got %v", err)
	}

	// And the inverse: with the dir set but the profile absent, the CLI must
	// report the name as unresolvable rather than silently dialing a profile
	// from the default directory (the old behavior, which made the env var a
	// lie).
	err = runConnect([]string{"missing-profile"})
	if err == nil || !strings.Contains(err.Error(), "neither a protocol nor a saved profile") {
		t.Errorf("connect did not report the missing custom-dir profile: %v", err)
	}
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
