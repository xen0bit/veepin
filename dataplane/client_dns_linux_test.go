package dataplane

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recorder collects the argv of every command a backend would run, so the
// command construction can be asserted on a machine that has neither
// systemd-resolved nor root.
type recorder struct {
	calls [][]string
	fail  error
}

func (r *recorder) run(args []string) error {
	r.calls = append(r.calls, args)
	return r.fail
}

func (r *recorder) joined() []string {
	out := make([]string, 0, len(r.calls))
	for _, c := range r.calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

// A full tunnel must claim "~." as well as setting the servers. Without the
// routing domain resolved consults the link for no names at all, so the
// servers are set, the command succeeds, and every query still leaves by the
// old resolver -- the exact silent shape this whole item exists to close.
func TestResolvectlClaimsTheRoutingDomainForAFullTunnel(t *testing.T) {
	rec := &recorder{}
	d := &resolvectlDNS{bin: "resolvectl", run: rec.run}
	if err := d.apply("tun0", []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}, true); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := rec.joined()
	want := []string{
		"resolvectl dns tun0 10.0.0.1 10.0.0.2",
		"resolvectl domain tun0 ~.",
	}
	if len(got) != len(want) {
		t.Fatalf("commands = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A split tunnel must NOT claim it: the user asked for some prefixes to go
// through the VPN, not for their whole name space to.
func TestResolvectlLeavesTheRoutingDomainAloneForASplitTunnel(t *testing.T) {
	rec := &recorder{}
	d := &resolvectlDNS{bin: "resolvectl", run: rec.run}
	if err := d.apply("tun0", []net.IP{net.ParseIP("10.0.0.1")}, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := rec.joined(); len(got) != 1 || got[0] != "resolvectl dns tun0 10.0.0.1" {
		t.Fatalf("commands = %v, want just the dns call", got)
	}
}

// Revert undoes the link in one call, and only if apply got that far. A revert
// that ran unconditionally would clear settings some other daemon owns on a
// link we never touched.
func TestResolvectlRevertsOnlyWhatItApplied(t *testing.T) {
	rec := &recorder{}
	d := &resolvectlDNS{bin: "resolvectl", run: rec.run}
	if err := d.revert(); err != nil {
		t.Fatalf("revert before apply: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("revert before apply ran %v", rec.joined())
	}

	if err := d.apply("tun7", []net.IP{net.ParseIP("10.0.0.1")}, true); err != nil {
		t.Fatalf("apply: %v", err)
	}
	rec.calls = nil
	if err := d.revert(); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if got := rec.joined(); len(got) != 1 || got[0] != "resolvectl revert tun7" {
		t.Fatalf("revert ran %v, want resolvectl revert tun7", got)
	}
	// Twice is once: Revert is reached from a defer that may also run on a
	// path that already reverted.
	rec.calls = nil
	if err := d.revert(); err != nil {
		t.Fatalf("second revert: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("second revert ran %v", rec.joined())
	}
}

// A failed apply must not mark itself applied, or Revert clears a link the
// host still owns.
func TestResolvectlDoesNotClaimAFailedApply(t *testing.T) {
	rec := &recorder{fail: errors.New("no such link")}
	d := &resolvectlDNS{bin: "resolvectl", run: rec.run}
	if err := d.apply("tun0", []net.IP{net.ParseIP("10.0.0.1")}, true); err == nil {
		t.Fatal("apply succeeded against a failing resolvectl")
	}
	rec.calls, rec.fail = nil, nil
	if err := d.revert(); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("revert after a failed apply ran %v", rec.joined())
	}
}

// A full tunnel keeps only the tunnel's resolvers. Keeping any other is the
// leak: a query answered by the host's old resolver leaves the machine in
// plaintext from its real address.
func TestResolvConfFullTunnelKeepsNoOtherNameserver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	orig := "nameserver 192.168.1.1\nsearch lan\n"
	if err := os.WriteFile(path, []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}

	d := &resolvConfDNS{path: path}
	if err := d.apply("tun0", []net.IP{net.ParseIP("10.0.0.53")}, true); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := readFile(t, path)
	if !strings.Contains(got, "nameserver 10.0.0.53") {
		t.Errorf("tunnel resolver missing from %q", got)
	}
	if strings.Contains(got, "192.168.1.1") {
		t.Errorf("pre-VPN resolver survived a full tunnel: %q", got)
	}
}

// A split tunnel keeps them, after ours: resolv.conf cannot say which server
// answers for which name, and the names outside the tunnel still have to
// resolve.
func TestResolvConfSplitTunnelKeepsTheHostResolversAfterOurs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 192.168.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	d := &resolvConfDNS{path: path}
	if err := d.apply("tun0", []net.IP{net.ParseIP("10.0.0.53")}, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := readFile(t, path)
	ours, theirs := strings.Index(got, "10.0.0.53"), strings.Index(got, "192.168.1.1")
	if ours < 0 || theirs < 0 {
		t.Fatalf("split tunnel dropped a resolver: %q", got)
	}
	if ours > theirs {
		t.Errorf("the tunnel's resolver must come first, got %q", got)
	}
}

// The file must come back byte-for-byte. Anything less means a disconnect
// leaves the host resolving through a server that is no longer reachable.
func TestResolvConfRevertRestoresTheOriginalExactly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	orig := "# hand-written\noptions edns0 trust-ad\nnameserver 192.168.1.1\nsearch lan example.com\n"
	if err := os.WriteFile(path, []byte(orig), 0600); err != nil {
		t.Fatal(err)
	}

	d := &resolvConfDNS{path: path}
	if err := d.apply("tun0", []net.IP{net.ParseIP("10.0.0.53")}, true); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := d.revert(); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if got := readFile(t, path); got != orig {
		t.Errorf("restored file =\n%q\nwant\n%q", got, orig)
	}
	// The permissions are part of "as it was": a 0600 resolv.conf restored as
	// 0644 is a change to the host nobody asked for.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("restored mode = %v, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(d.backupPath()); !os.IsNotExist(err) {
		t.Errorf("backup %s survived the revert", d.backupPath())
	}
}

// While the tunnel is up the pre-VPN file is on disk, so a veepin killed with
// SIGKILL -- which runs no defer -- leaves the operator something to restore
// rather than a file they must reconstruct.
func TestResolvConfLeavesABackupWhileApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	orig := "nameserver 192.168.1.1\n"
	if err := os.WriteFile(path, []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}

	d := &resolvConfDNS{path: path}
	if err := d.apply("tun0", []net.IP{net.ParseIP("10.0.0.53")}, true); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := readFile(t, d.backupPath()); got != orig {
		t.Errorf("backup = %q, want %q", got, orig)
	}
	// The generated file names the backup, so the recovery step is written on
	// the thing the operator is already looking at.
	if !strings.Contains(readFile(t, path), d.backupPath()) {
		t.Error("the generated resolv.conf does not name its backup")
	}
}

// A symlink into /run is how resolvconf(8), NetworkManager and resolved all
// publish a generated file. Overwriting the target corrupts their state and
// overwriting the link removes a mechanism the host relies on, so we refuse
// and say which file and which daemon-managed target.
func TestResolvConfRefusesAFileAnotherDaemonOwns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink("/run/systemd/resolve/stub-resolv.conf", path); err != nil {
		t.Fatal(err)
	}

	d := &resolvConfDNS{path: path}
	err := d.apply("tun0", []net.IP{net.ParseIP("10.0.0.53")}, true)
	if err == nil {
		t.Fatal("apply clobbered a daemon-managed resolv.conf")
	}
	if !strings.Contains(err.Error(), "/run/systemd/resolve/stub-resolv.conf") {
		t.Errorf("error does not name the target: %v", err)
	}
	if !strings.Contains(err.Error(), "-no-dns") {
		t.Errorf("error does not name the way out: %v", err)
	}
	// The link itself must still be a link to the same place.
	if dest, err := os.Readlink(path); err != nil || dest != "/run/systemd/resolve/stub-resolv.conf" {
		t.Errorf("symlink changed: dest=%q err=%v", dest, err)
	}
}

// A symlink that stays inside /etc is a plain administrative choice, not a
// daemon's publishing mechanism, and refusing it would strand those hosts.
func TestResolvConfAcceptsASymlinkOutsideRun(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.conf")
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(target, []byte("nameserver 192.168.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	d := &resolvConfDNS{path: path}
	if err := d.apply("tun0", []net.IP{net.ParseIP("10.0.0.53")}, true); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !strings.Contains(readFile(t, path), "10.0.0.53") {
		t.Error("resolvers not installed through a plain symlink")
	}
}

// Revert on a host that had no resolv.conf at all removes ours rather than
// leaving an empty one behind: "as it was" means the file was absent.
func TestResolvConfRevertRemovesAFileThatDidNotExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")

	d := &resolvConfDNS{path: path}
	if err := d.apply("tun0", []net.IP{net.ParseIP("10.0.0.53")}, true); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := d.revert(); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("revert left %s behind (err=%v)", path, err)
	}
}

// The router installs nothing when the caller opted out, and nothing when the
// server offered no servers to install. Both are checked here rather than in
// the backends because the decision is the router's.
func TestClientRouterSkipsDNSWhenAskedAndWhenThereIsNone(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  ClientNetConfig
	}{
		{"opted out", ClientNetConfig{NoDNS: true, DNS: []net.IP{net.ParseIP("10.0.0.53")}}},
		{"none offered", ClientNetConfig{DNS: nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewClientRouter(tc.cfg)
			if got := r.DNSBackend(); got != "" {
				t.Errorf("DNSBackend = %q before Apply, want empty", got)
			}
		})
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
