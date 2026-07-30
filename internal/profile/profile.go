// Package profile saves named client connection configurations under
// $XDG_CONFIG_HOME/veepin/profiles/ (default ~/.config/veepin/profiles/), one
// JSON file per profile. It is the client-side analogue of the supervisor's
// ListenerConfig directory: the same one-file-per-entity shape, the same JSON
// schema over a protocol+options map, the same atomic write-and-rename.
//
// A profile is the unit the command resolves:
//
//	veepin connect home   # looks up ~/.config/veepin/profiles/home.json
//
// The lookup is tried after the registry: if "home" is not a known protocol
// name, the command checks the profiles directory. Profiles are additive to the
// bare `veepin connect <protocol> -flag ...` path; both use the same Dial.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultDir returns the profiles directory under the user's config home.
// XDG_CONFIG_HOME is consulted via os.UserConfigDir; if that fails (no $HOME),
// the caller (the command) supplies an explicit path.
func DefaultDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "veepin", "profiles"), nil
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Config is a single named client connection.
type Config struct {
	Name     string            `json:"name"`
	Protocol string            `json:"protocol"`
	Options  map[string]string `json:"options,omitempty"`
}

// Validate checks the profile's fields.
func (c Config) Validate() error {
	if !nameRe.MatchString(c.Name) {
		return fmt.Errorf("profile: name %q must match %s", c.Name, nameRe.String())
	}
	if c.Protocol == "" {
		return errors.New("profile: protocol is required")
	}
	return nil
}

// LoadDir reads every *.json file under dir as a profile, keyed by name.
func LoadDir(dir string) (map[string]Config, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("profile: reading profiles dir %q: %w", dir, err)
	}
	out := make(map[string]Config, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		c, err := ParseFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("profile: %s: %w", e.Name(), err)
		}
		if _, dup := out[c.Name]; dup {
			return nil, fmt.Errorf("profile: duplicate name %q (from %s)", c.Name, e.Name())
		}
		out[c.Name] = c
	}
	return out, nil
}

// ParseFile reads a profile JSON file from disk.
func ParseFile(path string) (Config, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("profile: reading %s: %w", filepath.Base(path), err)
	}
	return parseBytes(body)
}

func parseBytes(body []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("profile: parsing JSON: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Write stores a profile atomically at dir/<name>.json, mode 0600 so secrets
// in the options map stay root-only the same way listener config files do.
func Write(dir string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("profile: marshalling %q: %w", c.Name, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("profile: creating profile dir %q: %w", dir, err)
	}
	final := filepath.Join(dir, c.Name+".json")
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("profile: opening temp file: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("profile: writing %q: %w", c.Name, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("profile: closing temp file: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("profile: installing %q: %w", c.Name, err)
	}
	return nil
}

// Delete removes a profile by name from dir.
func Delete(dir, name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("profile: refusing to delete %q: bad name", name)
	}
	path := filepath.Join(dir, name+".json")
	return os.Remove(path)
}
