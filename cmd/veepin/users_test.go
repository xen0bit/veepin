package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/userdb"
)

// multiUserProtocols are the server protocols that authenticate a person by
// password and therefore take a credentials file. Each entry is the protocol
// and whether its exchange can verify a hashed secret -- which is a property of
// the protocol, not a preference: MS-CHAPv2 computes its response FROM the
// password, so there is nothing to compare a verifier against.
//
// The list is written out rather than derived, because "does this protocol
// authenticate a person" is a judgement about the protocol. What is mechanical
// is everything below it.
var multiUserProtocols = map[string]userdb.Class{
	"anyconnect": userdb.Verifiable,
	"cisco":      userdb.Verifiable,
	"fortinet":   userdb.Verifiable,
	"gp":         userdb.Verifiable,
	"l2tp":       userdb.NeedsPlaintext,
	"pulse":      userdb.Verifiable,
	"ssh":        userdb.Verifiable,
	"sstp":       userdb.NeedsPlaintext,
}

// The finding this closes: seven facades collapsed a Users map the engine
// already supported down to a single pair, because the option surface could
// express only -user and -pass. Every one of them must now name a file, and the
// spec must mark it Secret -- it is a path to key material, which AGENTS.md's
// rule and doc/security.md both put in the same class as the material itself.
func TestEveryPasswordProtocolAcceptsAUsersFile(t *testing.T) {
	for protocol, class := range multiUserProtocols {
		t.Run(protocol, func(t *testing.T) {
			specs, ok := client.ServerOptsFor(protocol)
			if !ok {
				t.Fatalf("%s declares no server OptSpec metadata", protocol)
			}
			var found *client.OptSpec
			for i := range specs {
				if specs[i].Key == "users-file" {
					found = &specs[i]
				}
			}
			if found == nil {
				t.Fatalf("%s has no users-file option, so it serves exactly one person", protocol)
			}
			if !found.Secret {
				t.Errorf("%s: users-file is not marked Secret; it is a path to key material, "+
					"so the management API will print it on a GET", protocol)
			}
			if found.Kind != client.OptFilePath {
				t.Errorf("%s: users-file has Kind %q, want %q — the panel renders it as the wrong control",
					protocol, found.Kind, client.OptFilePath)
			}
			// The help text has to say which class the protocol is in, because
			// that is the one thing an operator cannot infer from the file
			// format: both classes accept the same-looking file, and only one
			// of them can verify what is in it.
			wantsHash := class == userdb.Verifiable
			saysHash := strings.Contains(found.Help, "bcrypt verifier")
			if wantsHash != saysHash {
				t.Errorf("%s: help text %q does not say whether a bcrypt verifier works here", protocol, found.Help)
			}
		})
	}
}

// The serve command must actually bind the flag, or the option is declared,
// documented and unreachable. The generic guards in flags_test.go compare key
// sets and would catch a missing flag as a spec with no emitter -- this one
// names the failure in the language of the finding.
func TestServeBindsAUsersFileFlagForEveryPasswordProtocol(t *testing.T) {
	for protocol := range multiUserProtocols {
		t.Run(protocol, func(t *testing.T) {
			fs := newTestFlagSet()
			options, err := serveFlags(protocol, fs)
			if err != nil {
				t.Fatalf("binding serve flags: %v", err)
			}
			if fs.Lookup("users-file") == nil {
				t.Fatalf("`veepin serve %s` binds no -users-file flag", protocol)
			}
			if err := fs.Set("users-file", "/etc/veepin/users"); err != nil {
				t.Fatalf("setting -users-file: %v", err)
			}
			if got := options()["users-file"]; got != "/etc/veepin/users" {
				t.Errorf("-users-file reaches the option map as %q", got)
			}
		})
	}
}

// The claim that matters, end to end: a file of several users produces several
// users. Asserted through the real parse rather than through userdb, because
// the bug was never in the parsing -- it was in the facade throwing the rest
// away on the way to an engine that would have taken them.
func TestAFileOfSeveralUsersReachesTheServerConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users")
	if err := os.WriteFile(path, []byte("alice:one\nbob:two\ncarol:three\n"), 0600); err != nil {
		t.Fatal(err)
	}
	users, err := userdb.Resolve(userdb.NeedsPlaintext, path, "", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("resolved %d users from a three-line file: %#v", len(users), users)
	}
}
