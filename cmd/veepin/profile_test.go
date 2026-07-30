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

func TestConnectUsagePrintsProtocols(t *testing.T) {
	err := runConnect(nil)
	if err == nil || !strings.Contains(err.Error(), strings.Join(client.Protocols(), ", ")) {
		t.Errorf("usage error does not list protocols: %v", err)
	}
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
