package confstore

// Tests for the shared one-file-per-entity store. The supervisor's listener
// directory and the client's profile directory both sit on this, so a
// regression here is a regression in both.

import (
	"os"
	"path/filepath"
	"testing"
)

// thing is a stand-in for a stored config: a name, a value, and a field with a
// non-zero default so the defaults path is exercised.
type thing struct {
	Name    string `json:"name"`
	Value   string `json:"value,omitempty"`
	Enabled bool   `json:"enabled"`
}

func (t thing) ConfigName() string { return t.Name }

func (t thing) Validate() error {
	if !ValidName(t.Name) {
		return &badName{t.Name}
	}
	return nil
}

type badName struct{ name string }

func (b *badName) Error() string { return "bad name " + b.name }

func newThing() thing { return thing{Enabled: true} }

func newStore(t *testing.T) *Store[thing] {
	t.Helper()
	return New(t.TempDir(), "test", newThing)
}

// TestDefaultsSurviveAnAbsentField: a document that does not mention a field
// keeps the default the type wants, not Go's zero value. encoding/json only
// writes what the document carries, which is what makes decoding into a
// pre-filled value the whole mechanism.
func TestDefaultsSurviveAnAbsentField(t *testing.T) {
	s := newStore(t)
	got, err := s.ParseBytes([]byte(`{"name":"a"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled {
		t.Error("a document that omitted the field lost its default")
	}
}

// TestExplicitFalseBeatsTheDefault: the default must not swallow an opt-out.
func TestExplicitFalseBeatsTheDefault(t *testing.T) {
	s := newStore(t)
	got, err := s.ParseBytes([]byte(`{"name":"a","enabled":false}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled {
		t.Error("an explicit false was overridden by the default")
	}
}

// TestUnknownFieldsAreRejected: a key the type does not have is a typo or a
// config written for another version. Ignoring it means an operator's setting
// silently does nothing while the file looks right.
func TestUnknownFieldsAreRejected(t *testing.T) {
	s := newStore(t)
	if _, err := s.ParseBytes([]byte(`{"name":"a","bogus":1}`)); err == nil {
		t.Error("an unknown field was accepted")
	}
}

// TestParseRunsValidate: a document that decodes but does not validate is an
// error, so a malformed entity never leaves the disk unnoticed.
func TestParseRunsValidate(t *testing.T) {
	s := newStore(t)
	if _, err := s.ParseBytes([]byte(`{"name":"UPPERCASE"}`)); err == nil {
		t.Error("a name the grammar forbids was accepted")
	}
}

// TestWriteIsAtomicAndOwnerOnly: these files hold private keys and passphrases,
// so the mode is the protection. The temp file must not survive either -- a
// leftover .tmp is not *.json, so it would not be loaded, but it would be a
// world-visible copy of whatever the write was protecting if the mode slipped.
func TestWriteIsAtomicAndOwnerOnly(t *testing.T) {
	s := newStore(t)
	if err := s.Write(thing{Name: "site-a", Value: "secret", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.Path("site-a"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
	entries, err := os.ReadDir(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("write left a temp file behind: %s", e.Name())
		}
	}
}

// TestWriteReadRoundTrip covers the whole path, including that a false-valued
// field survives it -- the shape that broke when a tag carried omitempty and the
// default read it straight back as true.
func TestWriteReadRoundTrip(t *testing.T) {
	s := newStore(t)
	in := thing{Name: "site-a", Value: "v", Enabled: false}
	if err := s.Write(in); err != nil {
		t.Fatal(err)
	}
	out, err := s.ParseFile(s.Path("site-a"))
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Errorf("round trip: got %+v, want %+v", out, in)
	}
}

// TestWriteRejectsAnInvalidEntity: validation runs before the file is created,
// so a bad entity cannot leave a partial file behind.
func TestWriteRejectsAnInvalidEntity(t *testing.T) {
	s := newStore(t)
	if err := s.Write(thing{Name: "Bad Name"}); err == nil {
		t.Fatal("Write accepted an entity that does not validate")
	}
	entries, _ := os.ReadDir(s.Dir())
	if len(entries) != 0 {
		t.Errorf("a rejected write left files behind: %v", entries)
	}
}

// TestLoadDirSkipsSubdirectories is what lets the supervisor keep its own state
// in <dir>/mgmt/ without the loader trying to parse it.
func TestLoadDirSkipsSubdirectories(t *testing.T) {
	s := newStore(t)
	if err := s.Write(thing{Name: "site-a", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.Dir(), "mgmt"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir(), "notes.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadDir()
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(got) != 1 || got["site-a"].Name != "site-a" {
		t.Errorf("LoadDir = %+v, want just site-a", got)
	}
}

// TestLoadDirRejectsADuplicateName: two files naming the same entity means one
// is being ignored and the operator cannot tell which, so it is an error rather
// than a merge or a last-one-wins.
func TestLoadDirRejectsADuplicateName(t *testing.T) {
	s := newStore(t)
	body := []byte(`{"name":"site-a","enabled":true}`)
	for _, f := range []string{"site-a.json", "copy.json"} {
		if err := os.WriteFile(filepath.Join(s.Dir(), f), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.LoadDir(); err == nil {
		t.Error("two files naming the same entity were accepted")
	}
}

// TestDeleteRefusesABadName: the name is about to become a path element, and
// this is the last place that can refuse one that should never have got here.
func TestDeleteRefusesABadName(t *testing.T) {
	s := newStore(t)
	for _, bad := range []string{"../escape", "UPPER", "", "with/slash"} {
		if err := s.Delete(bad); err == nil {
			t.Errorf("Delete accepted %q", bad)
		}
	}
}

// TestValidNameGrammar pins the rule itself. A name is a filename and an
// iptables --comment value, so anything needing quoting in either is out.
func TestValidNameGrammar(t *testing.T) {
	for _, ok := range []string{"a", "site-a", "0", "a-b-c", "abcdefghijklmnopqrstuvwxyz012345"} {
		if !ValidName(ok) {
			t.Errorf("ValidName(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"", "-leading", "UPPER", "with space", "with/slash", "with.dot", "with_underscore",
		"abcdefghijklmnopqrstuvwxyz0123456", // 33 octets
	} {
		if ValidName(bad) {
			t.Errorf("ValidName(%q) = true, want false", bad)
		}
	}
}
