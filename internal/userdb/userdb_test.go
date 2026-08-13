package userdb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The format is username:secret, and the secret is everything after the first
// colon. A password containing a colon is a password, and splitting on the last
// one -- or on all of them -- would silently store a different string than the
// operator wrote.
func TestParseSplitsOnTheFirstColonOnly(t *testing.T) {
	users, err := Parse([]byte("alice:pass:with:colons\n"), Verifiable, "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := users["alice"]; got != "pass:with:colons" {
		t.Errorf("secret = %q, want %q", got, "pass:with:colons")
	}
}

// The secret is taken verbatim. A password ending in a space is a password, not
// a typo, and trimming it here produces a login that fails with no explanation
// anywhere in the system.
func TestParseDoesNotTrimTheSecret(t *testing.T) {
	users, err := Parse([]byte("alice:  spaced  \n"), Verifiable, "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := users["alice"]; got != "  spaced  " {
		t.Errorf("secret = %q, want %q", got, "  spaced  ")
	}
}

// A file written on Windows must work: the CR is a line terminator, not part of
// the password.
func TestParseStripsOnlyTheCarriageReturn(t *testing.T) {
	users, err := Parse([]byte("alice:hunter2\r\nbob:swordfish\r\n"), Verifiable, "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if users["alice"] != "hunter2" || users["bob"] != "swordfish" {
		t.Errorf("users = %#v", users)
	}
}

func TestParseIgnoresCommentsAndBlankLines(t *testing.T) {
	users, err := Parse([]byte("# the ops team\n\nalice:hunter2\n   \n  # bob is on leave\nbob:swordfish\n"), Verifiable, "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("users = %#v, want two", users)
	}
}

// A username twice is not last-wins. Which of the two the operator meant is
// unknowable, and picking one silently is how a revoked password stays live.
func TestParseRefusesADuplicateUsername(t *testing.T) {
	_, err := Parse([]byte("alice:old\nbob:x\nalice:new\n"), Verifiable, "creds")
	if err == nil {
		t.Fatal("a duplicate username was accepted")
	}
	if !strings.Contains(err.Error(), "creds:3") || !strings.Contains(err.Error(), "alice") {
		t.Errorf("error names neither the line nor the user: %v", err)
	}
}

func TestParseRejectsMalformedLines(t *testing.T) {
	for _, tc := range []struct{ name, data, want string }{
		{"no colon", "alice hunter2\n", "no colon"},
		{"empty username", ":hunter2\n", "empty username"},
		{"empty secret", "alice:\n", "empty secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.data), Verifiable, "creds"); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The class is the point of the two-class split: MS-CHAPv2 computes its
// response FROM the password, so a hash is not a substitute for it. Told at
// startup, because the alternative is a login that never succeeds and no
// message anywhere saying why.
func TestParseRefusesAHashForAProtocolThatDerivesItsResponse(t *testing.T) {
	hash, err := Hash("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse([]byte("alice:"+hash+"\n"), NeedsPlaintext, "creds")
	if err == nil {
		t.Fatal("a bcrypt verifier was accepted for an MS-CHAPv2 protocol")
	}
	if !strings.Contains(err.Error(), "MS-CHAPv2") {
		t.Errorf("error does not say why: %v", err)
	}
	// The same file is fine for a protocol that compares the password it is sent.
	if _, err := Parse([]byte("alice:"+hash+"\n"), Verifiable, "creds"); err != nil {
		t.Errorf("verifiable class rejected a hash: %v", err)
	}
}

func TestVerifyAcceptsAPasswordAndItsHashAndNothingElse(t *testing.T) {
	hash, err := Hash("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, stored, offered string
		want                  bool
	}{
		{"plaintext right", "hunter2", "hunter2", true},
		{"plaintext wrong", "hunter2", "hunter3", false},
		{"plaintext prefix", "hunter2", "hunter", false},
		{"hash right", hash, "hunter2", true},
		{"hash wrong", hash, "hunter3", false},
		{"hash offered as itself", hash, hash, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Verify(tc.stored, tc.offered); got != tc.want {
				t.Errorf("Verify(%q, %q) = %v, want %v", tc.stored, tc.offered, got, tc.want)
			}
		})
	}
}

// A stored hash must be recognised whichever of the three bcrypt spellings the
// operator's tool emitted, or their file is read as a plaintext password that
// literally begins "$2y$" and nobody can log in.
func TestIsHashRecognisesEveryBcryptSpelling(t *testing.T) {
	for _, p := range []string{"$2a$", "$2b$", "$2y$"} {
		if !IsHash(p + "12$xxxxxxxxxxxxxxxxxxxxxx") {
			t.Errorf("%s not recognised as a verifier", p)
		}
	}
	for _, s := range []string{"hunter2", "", "$1$md5crypt", "2a$12$x"} {
		if IsHash(s) {
			t.Errorf("%q read as a verifier", s)
		}
	}
}

// bcrypt ignores everything past 72 bytes, so a verifier for a longer password
// also accepts its first 72 bytes -- a silent weakening of a password chosen to
// be strong. Refused rather than truncated.
func TestHashRefusesAPasswordBcryptWouldTruncate(t *testing.T) {
	if _, err := Hash(strings.Repeat("a", 72)); err != nil {
		t.Errorf("72 bytes refused: %v", err)
	}
	_, err := Hash(strings.Repeat("a", 73))
	if err == nil {
		t.Fatal("73 bytes accepted; bcrypt would have ignored the last one")
	}
	if !strings.Contains(err.Error(), "72") {
		t.Errorf("error does not name the limit: %v", err)
	}
}

// Both sources are first-class, and the command line is the more specific and
// more recent statement -- an operator overriding one entry for a moment should
// not have to edit the file.
func TestResolveLetsTheCommandLineWinOverTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users")
	if err := os.WriteFile(path, []byte("alice:from-file\nbob:bobs-pass\n"), 0600); err != nil {
		t.Fatal(err)
	}

	users, err := Resolve(Verifiable, path, "alice", "from-flag")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if users["alice"] != "from-flag" {
		t.Errorf("alice = %q, want the command line to win", users["alice"])
	}
	if users["bob"] != "bobs-pass" {
		t.Errorf("bob = %q, want the file entry kept", users["bob"])
	}
}

// The single-pair shorthand is what every runbook and every interop cell
// passes, so it must keep working with no file at all.
func TestResolveWithNoFileIsTheSinglePairItAlwaysWas(t *testing.T) {
	users, err := Resolve(Verifiable, "", "alice", "hunter2")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(users) != 1 || users["alice"] != "hunter2" {
		t.Errorf("users = %#v", users)
	}
}

// Neither source is not an error here: the facades report it, with a message
// naming both ways to supply credentials.
func TestResolveWithNeitherSourceIsAnEmptyMap(t *testing.T) {
	users, err := Resolve(Verifiable, "", "", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("users = %#v, want empty", users)
	}
}

func TestLoadReportsAMissingFileByName(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent"), Verifiable)
	if err == nil {
		t.Fatal("a missing file was accepted")
	}
	if !strings.Contains(err.Error(), "absent") {
		t.Errorf("error does not name the file: %v", err)
	}
}
