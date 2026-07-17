package ssh

import (
	"fmt"
	"net"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// parseCIDR splits a CIDR address into the host address and its netmask, e.g.
// "10.200.0.2/30" -> 10.200.0.2, 255.255.255.252.
func parseCIDR(cidr string) (ip net.IP, netmask net.IP, err error) {
	addr, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	v4 := addr.To4()
	if v4 == nil {
		return nil, nil, fmt.Errorf("only IPv4 addresses are supported: %q", cidr)
	}
	return v4, net.IP(ipnet.Mask), nil
}

// hostKeyCallback selects the host-key verification policy: insecure (skip),
// a known_hosts file, or an error if neither is configured — a client must state
// how it trusts the server.
func hostKeyCallback(cfg *Config) (cryptossh.HostKeyCallback, error) {
	if cfg.Insecure {
		return cryptossh.InsecureIgnoreHostKey(), nil //nolint:gosec // opt-in; documented
	}
	if cfg.KnownHosts != "" {
		cb, err := knownhosts.New(cfg.KnownHosts)
		if err != nil {
			return nil, fmt.Errorf("known-hosts: %w", err)
		}
		return cb, nil
	}
	return nil, fmt.Errorf("host-key verification required: set a known-hosts file or -insecure")
}

// splitComma splits a comma/space-separated list, dropping empties.
func splitComma(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
}
