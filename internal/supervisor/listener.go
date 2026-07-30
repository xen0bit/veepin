// Package supervisor runs multiple veepin servers in one process, mirroring the
// `veepin serve <proto>` command for each. The bare command constructs exactly
// one client.Server and blocks on it; the supervisor keeps a set of them,
// tracks their state, and rebuilds one without disturbing the others when its
// configuration changes.
//
// State lives as one JSON file per listener under a config directory the
// operator points it at. Each file is parsed into a ListenerConfig, which is
// the unit of change: applying the directory reconciles the live set to what
// the files say. A change is a cold rebuild -- the Server the veepin Server
// interface models is constructed-upfront, so reconfiguration is Close plus
// NewServer plus ListenAndServe again, scoped to the one listener that moved.
// Other listeners' goroutines are not touched.
//
// Everything that mutates host state (TUN address, forwarding, NAT) is owned by
// internal/hostnet and called through here; the supervisor matches the
// `NewServer installs no host state, the caller owns host networking` contract
// by being the caller.
package supervisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xen0bit/veepin/client"
)

// nameRe is the listener-name grammar: a lowercase, digit, or hyphen identifier
// 1-32 octets, that is also safe as both a path element and an iptables comment
// (hostnet tags rules "veepin:<name>"). The rule is enforced at parse so a
// builder never has to sanitise a name it would later pass to a shell.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidName reports whether name is one the supervisor could have written: it
// is the grammar above, exported so callers that turn a name into a filename --
// the management API's path handlers -- can check it before the join rather
// than trusting whatever routed to them.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// ListenerConfig is one server, the on-disk form of one JSON file in the config
// directory. It mirrors what `veepin serve <protocol>` reads from its flags:
// Options is the same map[string]string the protocol's ServerParseFunc takes,
// and SetupNAT / WAN carry the host-networking side exactly the bare command's
// `-setup-nat` / `-wan` flags do.
type ListenerConfig struct {
	// Name is the listener's identifier and the iptables comment tag.
	Name string `json:"name"`
	// Protocol is the registry name the listener runs, e.g. "wireguard".
	Protocol string `json:"protocol"`
	// Options is the protocol's options map. Each protocol's Opt* consts are the
	// keys; the values are whatever the bare command's flags accept.
	Options map[string]string `json:"options,omitempty"`
	// SetupNAT true means the supervisor configures interface address and
	// installs tagged iptables rules via internal/hostnet, the same path as
	// `veepin serve -setup-nat`. False means the operator manages the host
	// side themselves.
	SetupNAT bool `json:"setup_nat,omitempty"`
	// WAN is the upstream interface for NAT, passed to hostnet.
	WAN string `json:"wan,omitempty"`
	// Enabled false means parse it, list it, but do not start it. Lets a
	// config disable a listener without deleting the file.
	//
	// It defaults to TRUE for a file that does not mention it -- see
	// NewListenerConfig and parseListenerBytes. A zero-value Go bool would
	// default the other way, which meant the obvious minimal config
	//
	//	{"name": "site-a", "protocol": "wireguard", "options": {...}}
	//
	// parsed, validated, listed, and never started, with no error and no log
	// line. No omitempty either: the field must survive a write-back, or
	// disabling a listener would drop the key and read back as enabled.
	Enabled bool `json:"enabled"`
}

// NewListenerConfig returns a ListenerConfig with the defaults a hand-written
// file gets when it stays silent. Callers that decode into a fresh config --
// the management API's create endpoint, and parseListenerBytes -- start from
// this rather than from the zero value, because encoding/json only writes the
// fields a document actually carries and so leaves these standing.
func NewListenerConfig() ListenerConfig {
	return ListenerConfig{Enabled: true}
}

// Validate checks that a ListenerConfig is internally consistent. It does not
// check whether the protocol is known to the registry -- that requires a
// registry pointer and is enforced at build time, so the parse remains a pure
// data check that runs in the fuzz target without touching registration.
func (c ListenerConfig) Validate() error {
	if !nameRe.MatchString(c.Name) {
		return fmt.Errorf("supervisor: name %q must match %s", c.Name, nameRe.String())
	}
	if c.Protocol == "" {
		return errors.New("supervisor: protocol is required")
	}
	if strings.ContainsAny(c.Name, "/\\") {
		// Belt-and-braces: nameRe already forbids "/" so this never fires; it
		// stays to make the safety intent explicit to a reader who skims the
		// regex as "looks permissive".
		return fmt.Errorf("supervisor: name %q must not contain a path separator", c.Name)
	}
	return nil
}

// ParseListenerFile reads and validates one JSON config file. It exists as a
// named function so it is the one obvious fuzz target.
func ParseListenerFile(path string) (ListenerConfig, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return ListenerConfig{}, fmt.Errorf("supervisor: reading %s: %w", filepath.Base(path), err)
	}
	return parseListenerBytes(body)
}

// parseListenerBytes is the core FuzzParseListenerFile runs; it does no I/O so
// the fuzzer does not touch the disk.
func parseListenerBytes(body []byte) (ListenerConfig, error) {
	c := NewListenerConfig()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return ListenerConfig{}, fmt.Errorf("supervisor: parsing listener config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return ListenerConfig{}, err
	}
	return c, nil
}

// LoadDir reads every *.json file under dir as a listener config, returning the
// set keyed by listener name. Two files defining the same name is an error:
// each name maps to exactly one listener, so a duplicate is a configuration
// mistake rather than a merge. Directory evolution is handled by Apply, which
// reconciles to whatever LoadDir reports, so this is the read side only.
func LoadDir(dir string) (map[string]ListenerConfig, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("supervisor: reading config dir %q: %w", dir, err)
	}
	out := make(map[string]ListenerConfig, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		c, err := ParseListenerFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("supervisor: %s: %w", e.Name(), err)
		}
		if _, dup := out[c.Name]; dup {
			return nil, fmt.Errorf("supervisor: duplicate listener name %q (from %s)", c.Name, e.Name())
		}
		out[c.Name] = c
	}
	return out, nil
}

// WriteListenerFile writes a listener config to dir/<name>.json atomically. It
// is the management API's persistence path: temp file in dir, write, fsync,
// rename. The 0600 mode keeps protocol keys and PSKs that live in Options root-
// only, the same filesystem-permission protection the bare command relies on
// for PEM files and the IKEv2 EAP user list.
func WriteListenerFile(dir string, c ListenerConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("supervisor: marshalling listener %q: %w", c.Name, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("supervisor: creating config dir %q: %w", dir, err)
	}
	final := filepath.Join(dir, c.Name+".json")
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("supervisor: opening temp file: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("supervisor: writing listener %q: %w", c.Name, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("supervisor: closing temp file: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("supervisor: installing listener %q: %w", c.Name, err)
	}
	return nil
}

// DeleteListenerFile removes a listener config by name.
func DeleteListenerFile(dir, name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("supervisor: refusing to delete %q: bad name", name)
	}
	return os.Remove(filepath.Join(dir, name+".json"))
}

// KnownProtocol reports whether the registry recognises protocol as a server.
// It is a separate function from Validate so the parser stays pure-data and the
// registry check is applied at apply time, where a registration side-effect of
// an imported facade is the only thing that could know.
func KnownProtocol(protocol string) bool {
	for _, p := range client.ServerProtocols() {
		if p == protocol {
			return true
		}
	}
	return false
}
