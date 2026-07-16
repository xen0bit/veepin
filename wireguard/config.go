package wireguard

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// A note on scope: this parses the subset of the wg-quick INI format that a
// userspace initiator needs. It reads one [Interface] and one [Peer]. The
// interface's own routing directives (Table, PreUp, PostUp, …) are wg-quick's
// business, not the tunnel's, and are ignored here — veepin's CLI applies
// routing through dataplane, and a second peer belongs to a later milestone.

// Config is a parsed WireGuard tunnel definition: our identity and address from
// the [Interface] section, the single peer from the [Peer] section. Fields are
// the wg-quick spellings, decoded no further than strings until Dial validates
// them, so a bad key surfaces as a config error rather than a handshake failure.
type Config struct {
	// [Interface]
	PrivateKey string   // our static private key, base64 (required)
	Address    []string // our tunnel addresses in CIDR form (required)
	DNS        []string // DNS servers to advertise (optional)
	MTU        int      // inner MTU (optional; 0 means the default)

	// [Peer]
	PublicKey    string   // the peer's static public key, base64 (required)
	PresharedKey string   // optional symmetric key, base64
	Endpoint     string   // host:port to dial (required)
	AllowedIPs   []string // inner destinations routed to this peer (required)
	Keepalive    int      // persistent-keepalive seconds (optional; 0 is off)

	// TUNName is the desired interface name; empty lets the kernel pick. It has
	// no wg-quick equivalent (there the file name is the interface) and is set
	// from a flag.
	TUNName string

	// Logger receives progress logs; nil discards them. It has no wg-quick
	// equivalent and is set by a Go caller.
	Logger *log.Logger
}

// ParseConfigFile reads a wg-quick style configuration file.
func ParseConfigFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := ParseConfig(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// section names the part of the file a line belongs to, so a key like PublicKey
// (which is valid in both sections with different meanings under full wg-quick)
// is attributed correctly.
type section int

const (
	sectionNone section = iota
	sectionInterface
	sectionPeer
)

// ParseConfig reads a wg-quick style configuration from r. Keys are matched
// case-insensitively, as wg does; values are taken verbatim, with comma or
// whitespace separating list values. A second [Peer] is rejected rather than
// silently dropped — it means the file expects a topology this build does not
// implement.
func ParseConfig(r io.Reader) (*Config, error) {
	cfg := &Config{}
	sec := sectionNone
	peers := 0

	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := stripComment(sc.Text())
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "[") {
			switch strings.ToLower(strings.Trim(text, "[]")) {
			case "interface":
				sec = sectionInterface
			case "peer":
				sec = sectionPeer
				peers++
				if peers > 1 {
					return nil, fmt.Errorf("line %d: multiple [Peer] sections are not supported", line)
				}
			default:
				return nil, fmt.Errorf("line %d: unknown section %q", line, text)
			}
			continue
		}

		key, val, ok := splitKV(text)
		if !ok {
			return nil, fmt.Errorf("line %d: not a key = value: %q", line, text)
		}
		if err := cfg.set(sec, key, val); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// set applies one key/value to the config under the current section.
func (c *Config) set(sec section, key, val string) error {
	switch sec {
	case sectionInterface:
		switch strings.ToLower(key) {
		case "privatekey":
			c.PrivateKey = val
		case "address":
			c.Address = append(c.Address, splitList(val)...)
		case "dns":
			c.DNS = append(c.DNS, splitList(val)...)
		case "mtu":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("MTU %q: %w", val, err)
			}
			c.MTU = n
		case "listenport", "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark":
			// Accepted and ignored: these configure a kernel interface or
			// wg-quick's own scripting, neither of which applies to a userspace
			// initiator.
		default:
			return fmt.Errorf("unknown [Interface] key %q", key)
		}
	case sectionPeer:
		switch strings.ToLower(key) {
		case "publickey":
			c.PublicKey = val
		case "presharedkey":
			c.PresharedKey = val
		case "endpoint":
			c.Endpoint = val
		case "allowedips":
			c.AllowedIPs = append(c.AllowedIPs, splitList(val)...)
		case "persistentkeepalive":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("PersistentKeepalive %q: %w", val, err)
			}
			c.Keepalive = n
		default:
			return fmt.Errorf("unknown [Peer] key %q", key)
		}
	default:
		return fmt.Errorf("key %q before any section", key)
	}
	return nil
}

// stripComment removes a trailing comment and surrounding whitespace. wg-quick
// treats '#' as a comment leader.
func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

// splitKV splits "key = value" on the first '='.
func splitKV(line string) (key, val string, ok bool) {
	k, v, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}
	key = strings.TrimSpace(k)
	val = strings.TrimSpace(v)
	if key == "" {
		return "", "", false
	}
	return key, val, true
}

// splitList splits a value on commas and whitespace, dropping empties, so
// "AllowedIPs = 10.0.0.0/24, 192.168.1.0/24" and repeated keys both work.
func splitList(val string) []string {
	fields := strings.FieldsFunc(val, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	return fields
}

// applyOverrides layers non-empty option-map values over a parsed config, so the
// CLI's flags win over a -config file. Keys match the Opt* constants.
func (c *Config) applyOverrides(opts map[string]string) error {
	if v := opts[OptPrivateKey]; v != "" {
		c.PrivateKey = v
	}
	if v := opts[OptAddress]; v != "" {
		c.Address = splitList(v)
	}
	if v := opts[OptDNS]; v != "" {
		c.DNS = splitList(v)
	}
	if v := opts[OptMTU]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%s %q: %w", OptMTU, v, err)
		}
		c.MTU = n
	}
	if v := opts[OptPublicKey]; v != "" {
		c.PublicKey = v
	}
	if v := opts[OptPresharedKey]; v != "" {
		c.PresharedKey = v
	}
	if v := opts[OptEndpoint]; v != "" {
		c.Endpoint = v
	}
	if v := opts[OptAllowedIPs]; v != "" {
		c.AllowedIPs = splitList(v)
	}
	if v := opts[OptKeepalive]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%s %q: %w", OptKeepalive, v, err)
		}
		c.Keepalive = n
	}
	if v := opts[OptTUNName]; v != "" {
		c.TUNName = v
	}
	return nil
}

// prefixes parses a list of CIDRs (Address or AllowedIPs) into netip.Prefix.
func prefixes(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// wg-quick accepts a bare address as a host route; mirror that.
			if a, aerr := netip.ParseAddr(s); aerr == nil {
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
				continue
			}
			return nil, fmt.Errorf("bad CIDR %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}
