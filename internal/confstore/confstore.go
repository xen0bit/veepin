// Package confstore is the one-JSON-file-per-entity directory that both the
// supervisor's listener set and the client's saved profiles are.
//
//	<dir>/site-a.json      one file per entity, named for the entity
//	<dir>/branch.json
//
// The two callers arrived at the same shape independently -- the same name
// grammar, the same strict decode, the same atomic write-and-rename, the same
// duplicate-name check -- and then carried it as two near-identical copies. This
// is that shape written once.
//
// What a caller supplies is the type, its name, and its validation:
//
//	type Config struct{ Name string; ... }
//	func (c Config) ConfigName() string { return c.Name }
//	func (c Config) Validate() error    { ... }
//
//	store := confstore.New[Config]("/etc/veepin", "supervisor", newConfig)
//
// # Why the name grammar lives here
//
// An entity's name is its filename, so it is the one field that reaches the
// filesystem. ValidName is the single definition of what may do that -- lower
// case, digits and hyphens, at most 32 octets -- and every read and write path
// checks it. It is also safe as an iptables `--comment` value, which the
// supervisor relies on: it tags every rule it installs `veepin:<name>` and
// deletes by the same tag, so a name that needed quoting would be a name the
// teardown could not match.
//
// # Durability
//
// Write is temp file, write, fsync, close, rename. The fsync is what makes the
// rename mean anything: without it a crash between the two can leave the new
// name pointing at a file whose contents never reached the disk, which for a
// listener config is a listener that will not parse on the next boot.
package confstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// nameRe is the entity-name grammar: a lower-case, digit, or hyphen identifier
// of 1-32 octets, starting with a letter or digit.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidName reports whether name may be used as an entity name, and therefore
// as a path element. Callers validate with it rather than re-deriving the rule,
// so there is one answer to "what may become a filename here".
func ValidName(name string) bool { return nameRe.MatchString(name) }

// NameGrammar is the human-readable form of the rule, for error messages.
func NameGrammar() string { return nameRe.String() }

// Named is what a stored type must be able to say about itself: what it is
// called, and whether it makes sense.
type Named interface {
	// ConfigName is the entity's identifier and the stem of its filename.
	ConfigName() string
	// Validate reports whether the entity is internally consistent. The store
	// calls it on every read and before every write, so a malformed entity
	// never reaches the disk and never leaves it unnoticed.
	Validate() error
}

// Store reads and writes entities of one type under one directory.
type Store[T Named] struct {
	dir string
	// prefix is the package name errors are tagged with, per house style
	// ("supervisor: ...", "profile: ...").
	prefix string
	// defaults returns the value a decode starts from, so a field a document
	// omits keeps its intended default rather than Go's zero value.
	defaults func() T
}

// New returns a Store over dir. prefix tags the errors; defaults supplies the
// starting value for each decode and may be nil, which means the zero value.
func New[T Named](dir, prefix string, defaults func() T) *Store[T] {
	if defaults == nil {
		defaults = func() T { var zero T; return zero }
	}
	return &Store[T]{dir: dir, prefix: prefix, defaults: defaults}
}

// Dir is the directory the store reads and writes.
func (s *Store[T]) Dir() string { return s.dir }

// ParseFile reads and validates one file by path.
func (s *Store[T]) ParseFile(path string) (T, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("%s: reading %s: %w", s.prefix, filepath.Base(path), err)
	}
	return s.ParseBytes(body)
}

// ParseBytes is the I/O-free core, which is what makes it the obvious fuzz
// target: a hand-edited or API-written file must produce an error rather than a
// panic, whatever is in it.
//
// Unknown fields are rejected. A key the type does not have is a typo or a
// config written for a different version, and silently ignoring it means an
// operator's setting does nothing while the file looks right.
func (s *Store[T]) ParseBytes(body []byte) (T, error) {
	c := s.defaults()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		var zero T
		return zero, fmt.Errorf("%s: parsing config: %w", s.prefix, err)
	}
	if err := c.Validate(); err != nil {
		var zero T
		return zero, err
	}
	return c, nil
}

// LoadDir reads every *.json file in the directory, keyed by entity name.
//
// Two files naming the same entity is an error, not a merge: each name maps to
// exactly one entity, so a duplicate means one of the two files is being
// ignored and the operator cannot tell which. Subdirectories are skipped, which
// is what lets the supervisor keep its own state in <dir>/mgmt/.
func (s *Store[T]) LoadDir() (map[string]T, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("%s: reading config dir %q: %w", s.prefix, s.dir, err)
	}
	out := make(map[string]T, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		c, err := s.ParseFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", s.prefix, e.Name(), err)
		}
		name := c.ConfigName()
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%s: duplicate name %q (from %s)", s.prefix, name, e.Name())
		}
		out[name] = c
	}
	return out, nil
}

// Write stores c at <dir>/<name>.json atomically, mode 0600.
//
// 0600 because these files hold whatever the protocol needs: private keys,
// pre-shared keys, passphrases. That is the same filesystem-permission posture
// the protocol facades already rely on for PEM files and the IKEv2 EAP user
// list -- the secret is protected by the mode on the file, not by anything in
// the format.
func (s *Store[T]) Write(c T) error {
	if err := c.Validate(); err != nil {
		return err
	}
	name := c.ConfigName()
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: marshalling %q: %w", s.prefix, name, err)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("%s: creating config dir %q: %w", s.prefix, s.dir, err)
	}
	final := filepath.Join(s.dir, name+".json")
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("%s: opening temp file: %w", s.prefix, err)
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: writing %q: %w", s.prefix, name, err)
	}
	// Before the rename, not after: the rename is only atomic with respect to
	// the name, and a crash between the two would otherwise leave the final
	// name pointing at a file whose contents never reached the disk.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: syncing %q: %w", s.prefix, name, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: closing temp file: %w", s.prefix, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: installing %q: %w", s.prefix, name, err)
	}
	return nil
}

// Delete removes an entity's file. The name is checked first: it is about to
// become a path element, and this is the last place that can refuse one that
// should never have got this far.
func (s *Store[T]) Delete(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("%s: refusing to delete %q: bad name", s.prefix, name)
	}
	return os.Remove(filepath.Join(s.dir, name+".json"))
}

// Path is the file an entity of the given name lives at. Callers that need to
// stat or read the file directly use this rather than rebuilding the join.
func (s *Store[T]) Path(name string) string {
	return filepath.Join(s.dir, name+".json")
}
