package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
)

// The property the whole generation rests on, and the one that would break
// things silently if it were wrong.
//
//	veepin connect openvpn -config work.ovpn
//
// where work.ovpn names a cipher. If an unset -cipher emitted its documented
// default into the option map, it would override the file and the operator
// would get a cipher they never asked for with nothing saying so. An unset flag
// contributes nothing; the protocol's own parse applies its own fallback.
func TestAnUnsetFlagContributesNothingToTheOptionMap(t *testing.T) {
	fs := newTestFlagSet()
	options := bindSpecFlags(fs, []client.OptSpec{
		{Key: "cipher", Kind: client.OptStr, Default: "AES-256-GCM"},
		{Key: "port", Kind: client.OptInt, Default: "1194"},
		{Key: "insecure", Kind: client.OptBool},
		{Key: "server", Kind: client.OptStr},
	})
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if got := options(); len(got) != 0 {
		t.Errorf("an all-defaults parse emitted %v, want nothing", got)
	}
}

// Passing the default value on purpose still emits it. That is how an operator
// overrides a config file with the stock value deliberately, and it is the
// distinction "omit anything equal to the default" would lose.
func TestPassingTheDefaultExplicitlyStillEmitsIt(t *testing.T) {
	fs := newTestFlagSet()
	options := bindSpecFlags(fs, []client.OptSpec{
		{Key: "cipher", Kind: client.OptStr, Default: "AES-256-GCM"},
	})
	if err := fs.Parse([]string{"-cipher", "AES-256-GCM"}); err != nil {
		t.Fatal(err)
	}
	if got := options()["cipher"]; got != "AES-256-GCM" {
		t.Errorf("cipher = %q, want the explicitly-passed default to survive", got)
	}
}

// Flag is the escape hatch for the handful of options whose command-line
// spelling has never matched their key. ikev2's key is "gateway" and its flag
// is -server; renaming either breaks every runbook or every profile on disk.
func TestFlagOverridesTheCommandLineSpelling(t *testing.T) {
	fs := newTestFlagSet()
	options := bindSpecFlags(fs, []client.OptSpec{
		{Key: "gateway", Flag: "server", Kind: client.OptStr},
	})
	if fs.Lookup("gateway") != nil {
		t.Error("the key was bound as a flag as well as its declared spelling")
	}
	if err := fs.Parse([]string{"-server", "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := options()["gateway"]; got != "vpn.example.com" {
		t.Errorf("gateway = %q; -server did not reach the key", got)
	}
}

// The real mappings, asserted against the registry rather than restated: these
// are the spellings runbooks and profiles on disk already use, and a rename
// breaks one or the other.
func TestTheLongstandingFlagSpellingsAreUnchanged(t *testing.T) {
	for _, tc := range []struct{ protocol, flag, key string }{
		{"ikev2", "server", "gateway"},
		{"ikev2", "id", "local-id"},
		{"ikev2", "pass", "password"},
		{"toy", "insecure-shared-secret", "secret"},
		{"gp", "pass", "password"},
		{"sstp", "pass", "password"},
	} {
		t.Run(tc.protocol+"/-"+tc.flag, func(t *testing.T) {
			fs := newTestFlagSet()
			options, err := connectFlags(tc.protocol, fs)
			if err != nil {
				t.Fatal(err)
			}
			if fs.Lookup(tc.flag) == nil {
				t.Fatalf("`veepin connect %s` no longer binds -%s", tc.protocol, tc.flag)
			}
			if err := fs.Set(tc.flag, "value"); err != nil {
				t.Fatal(err)
			}
			if got := options()[tc.key]; got != "value" {
				t.Errorf("-%s reaches key %q as %q, want it to reach %q",
					tc.flag, tc.key, got, tc.key)
			}
		})
	}
}

// Item 7: a secret must be reachable from a file, so it need not appear in the
// process table, the shell history, or the systemd unit carrying the command
// line. One generic rule off the Secret flag, rather than a companion written
// by hand in seven case blocks.
func TestEverySecretOptionHasAFileCompanion(t *testing.T) {
	check := func(t *testing.T, protocol string, specs []client.OptSpec, bind func(string) (*testFlagSetPair, error)) {
		pair, err := bind(protocol)
		if err != nil {
			t.Fatal(err)
		}
		for _, sp := range specs {
			if !sp.Secret || sp.Kind == client.OptFilePath {
				continue
			}
			name := flagName(sp) + "-file"
			if pair.fs.Lookup(name) == nil {
				t.Errorf("%s: %q is Secret but has no -%s; the secret can only be passed "+
					"on the command line, where ps can read it", protocol, sp.Key, name)
			}
		}
	}
	for _, protocol := range client.Protocols() {
		specs, ok := client.ClientOptsFor(protocol)
		if !ok {
			continue
		}
		t.Run("connect/"+protocol, func(t *testing.T) {
			check(t, protocol, specs, func(p string) (*testFlagSetPair, error) {
				fs := newTestFlagSet()
				opts, err := connectFlags(p, fs)
				return &testFlagSetPair{fs: fs, opts: opts}, err
			})
		})
	}
	for _, protocol := range client.ServerProtocols() {
		specs, ok := client.ServerOptsFor(protocol)
		if !ok {
			continue
		}
		t.Run("serve/"+protocol, func(t *testing.T) {
			check(t, protocol, specs, func(p string) (*testFlagSetPair, error) {
				fs := newTestFlagSet()
				opts, err := serveFlags(p, fs)
				return &testFlagSetPair{fs: fs, opts: opts}, err
			})
		})
	}
}

type testFlagSetPair struct {
	fs   *flag.FlagSet
	opts func() map[string]string
}

// The companion reads the secret out of the file and puts it in the option map
// under the primary key, so the facade parse sees no difference at all.
func TestASecretFileReachesTheOptionMapAsThePrimaryKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "psk")
	// A trailing newline, because `echo secret > psk` is how every operator
	// will make one of these and it is not part of the secret.
	if err := os.WriteFile(path, []byte("a-strong-preshared-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := newTestFlagSet()
	options, err := connectFlags("ikev2", fs)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"-psk-file", path}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := options()["psk"]; got != "a-strong-preshared-key" {
		t.Errorf("psk = %q, want the file's contents with the newline trimmed", got)
	}
}

// Leading and interior spaces are part of a secret; only the line terminator
// comes off. Trimming more would hash or send something the operator can never
// type again, and the failure would be a login that never succeeds.
func TestASecretFileTrimsOnlyTheLineTerminator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "psk")
	if err := os.WriteFile(path, []byte("  spaced secret  \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := newTestFlagSet()
	options, _ := connectFlags("ikev2", fs)
	if err := fs.Parse([]string{"-psk-file", path}); err != nil {
		t.Fatal(err)
	}
	if got := options()["psk"]; got != "  spaced secret  " {
		t.Errorf("psk = %q, want the spaces kept", got)
	}
}

// Both spellings at once is ambiguous, and picking one silently is how a
// rotated secret stays live. Reported at parse, with both names.
func TestGivingBothASecretAndItsFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "psk")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := newTestFlagSet()
	if _, err := connectFlags("ikev2", fs); err != nil {
		t.Fatal(err)
	}
	err := fs.Parse([]string{"-psk", "from-flag", "-psk-file", path})
	if err == nil {
		t.Fatal("both -psk and -psk-file were accepted")
	}
	if !strings.Contains(err.Error(), "-psk-file") || !strings.Contains(err.Error(), "use one") {
		t.Errorf("error does not name the conflict: %v", err)
	}
}

// An unreadable or empty file is a failure at parse, not a silently empty
// secret that produces an authentication error three layers down.
func TestASecretFileThatCannotBeUsedFailsAtParse(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path, want string }{
		{"missing", filepath.Join(dir, "absent"), "no such file"},
		{"empty", empty, "is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFlagSet()
			if _, err := connectFlags("ikev2", fs); err != nil {
				t.Fatal(err)
			}
			err := fs.Parse([]string{"-psk-file", tc.path})
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The companion must never hand back the secret it read. -h walks every flag's
// value, and a Getter that returns key material is a Getter that will
// eventually print some.
func TestASecretFileFlagReportsThePathNotTheSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "psk")
	if err := os.WriteFile(path, []byte("top-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := newTestFlagSet()
	if _, err := connectFlags("ikev2", fs); err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"-psk-file", path}); err != nil {
		t.Fatal(err)
	}
	f := fs.Lookup("psk-file")
	if got := f.Value.String(); got != path {
		t.Errorf("String() = %q, want the path", got)
	}
	if strings.Contains(f.Value.String(), "top-secret") {
		t.Error("the flag's String() leaks the secret it read")
	}
}

// The help text must not say the default twice. The flag package appends its
// own from the value now carried on the flag, so a Help that also spells it out
// produced "server IKE port (default 500) (default 500)".
func TestHelpDoesNotRepeatTheDefault(t *testing.T) {
	for _, sp := range []client.OptSpec{
		{Key: "port", Kind: client.OptInt, Default: "500", Help: "server IKE port (default 500)"},
		{Key: "rekey", Kind: client.OptInt, Default: "3600", Help: "rekey interval (0 = default 3600)"},
		{Key: "hub", Kind: client.OptStr, Default: "VPN", Help: "virtual hub name (default: VPN)"},
	} {
		if got := flagUsage(sp); strings.Contains(got, "default") {
			t.Errorf("usage for %q = %q, want the default parenthetical removed", sp.Key, got)
		}
	}
	// An option with no declared default keeps whatever its help says: there
	// is nothing for the flag package to append, so nothing is duplicated.
	sp := client.OptSpec{Key: "shape", Kind: client.OptInt, Help: "budget in bytes (0 = off)"}
	if got := flagUsage(sp); got != sp.Help {
		t.Errorf("usage = %q, want %q untouched", got, sp.Help)
	}
}
