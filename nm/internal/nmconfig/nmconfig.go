// Package nmconfig maps a NetworkManager VPN connection dictionary
// (a{sa{sv}}, as delivered over D-Bus) to a protocol name plus the option map
// client.Dial parses, along with the handful of NM-specific knobs (full-tunnel,
// mtu) the plugin needs. It is pure data mapping with no D-Bus method calls, so
// it is unit-testable without a bus.
//
// The data and secret keys are passed through to the protocol untouched, so a
// new protocol's options need no change here: only the NM-specific keys are
// consumed. Their names deliberately match the protocol packages' option
// constants (ikev2.OptGateway and friends).
package nmconfig

import (
	"fmt"
	"strconv"

	"github.com/godbus/dbus/v5"
)

// Settings is the wire shape NetworkManager passes to VPN.Plugin.Connect:
// setting-name -> key -> variant. The "vpn" setting nests "data" (a{ss}) and
// "secrets" (a{ss}).
type Settings = map[string]map[string]dbus.Variant

// DefaultProtocol is dialed when a connection does not name one. It keeps
// profiles written before veepin gained a second protocol working unchanged.
const DefaultProtocol = "ikev2"

// Connection is the parsed, validated form of a VPN connection.
type Connection struct {
	Protocol   string            // which protocol to dial (default "ikev2")
	Options    map[string]string // protocol options, passed to client.Dial
	FullTunnel bool              // maps to Ip4Config never-default = !FullTunnel
	MTU        int               // 0 = use the client's default tunnel MTU
}

// Data-dictionary keys recognised in vpn.data.
const (
	KeyProtocol   = "protocol" // which VPN protocol to dial; default "ikev2"
	KeyGateway    = "gateway"
	KeyPort       = "port"
	KeyLocalID    = "local-id"
	KeyServerID   = "server-id"
	KeyUser       = "user"
	KeyFullTunnel = "full-tunnel" // "yes"/"no", default "yes"
	KeyMTU        = "mtu"         // optional inner-interface MTU override
)

// Secret keys recognised in vpn.secrets.
const (
	KeyPSK      = "psk"
	KeyPassword = "password"
)

// nmOnlyKeys are consumed by the plugin itself and are not protocol options.
var nmOnlyKeys = map[string]bool{
	KeyProtocol:   true,
	KeyFullTunnel: true,
	KeyMTU:        true,
}

// Parse extracts and validates a Connection from the NM settings dict.
func Parse(s Settings) (Connection, error) {
	data := stringMap(s, "vpn", "data")
	secrets := stringMap(s, "vpn", "secrets")

	c := Connection{
		Protocol:   DefaultProtocol,
		Options:    protocolOptions(data, secrets),
		FullTunnel: boolData(data, KeyFullTunnel, true),
	}
	if p := data[KeyProtocol]; p != "" {
		c.Protocol = p
	}

	if p := data[KeyPort]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return Connection{}, fmt.Errorf("nmconfig: invalid %q: %q", KeyPort, p)
		}
	}

	if m := data[KeyMTU]; m != "" {
		n, err := strconv.Atoi(m)
		// 576 is the IPv4 minimum practical MTU; 9000 covers jumbo frames.
		if err != nil || n < 576 || n > 9000 {
			return Connection{}, fmt.Errorf("nmconfig: invalid %q: %q", KeyMTU, m)
		}
		c.MTU = n
	}

	// NM wants a clear error before it spawns anything, so the required keys are
	// checked here as well as by the protocol's own parser. These are IKEv2's
	// requirements; a protocol with different ones needs a branch here.
	if err := requireKeys(c.Protocol, c.Options); err != nil {
		return Connection{}, err
	}
	return c, nil
}

// protocolOptions merges the data and secret dictionaries into the option map a
// protocol parses, dropping the keys the plugin consumes itself.
func protocolOptions(data, secrets map[string]string) map[string]string {
	opts := make(map[string]string, len(data)+len(secrets))
	for k, v := range data {
		if !nmOnlyKeys[k] {
			opts[k] = v
		}
	}
	for k, v := range secrets {
		opts[k] = v
	}
	return opts
}

// requireKeys checks the non-secret options a protocol cannot start without.
func requireKeys(protocol string, opts map[string]string) error {
	switch protocol {
	case "ikev2":
		for _, k := range []string{KeyGateway, KeyLocalID} {
			if opts[k] == "" {
				return fmt.Errorf("nmconfig: missing required %q", k)
			}
		}
		return nil
	default:
		return fmt.Errorf("nmconfig: unsupported %q: %q", KeyProtocol, protocol)
	}
}

// MissingSecret reports the name of the setting whose secrets NM must still
// supply (for VPN.Plugin.NeedSecrets), or "" if all required secrets are
// present. For IKEv2 the PSK is always required; the EAP password is required
// only when a username is configured. An error is returned if the non-secret
// config is itself invalid.
func MissingSecret(s Settings) (string, error) {
	conn, err := Parse(s)
	if err != nil {
		return "", err
	}
	switch conn.Protocol {
	case "ikev2":
		if conn.Options[KeyPSK] == "" {
			return "vpn", nil
		}
		if conn.Options[KeyUser] != "" && conn.Options[KeyPassword] == "" {
			return "vpn", nil
		}
		return "", nil
	default:
		return "", fmt.Errorf("nmconfig: unsupported %q: %q", KeyProtocol, conn.Protocol)
	}
}

// stringMap returns settings[section][key] interpreted as an a{ss} map, or nil.
func stringMap(s Settings, section, key string) map[string]string {
	sec, ok := s[section]
	if !ok {
		return nil
	}
	v, ok := sec[key]
	if !ok {
		return nil
	}
	m, _ := v.Value().(map[string]string)
	return m
}

// boolData interprets a "yes"/"no"/"true"/"false"/"1"/"0" data value.
func boolData(data map[string]string, key string, def bool) bool {
	switch data[key] {
	case "yes", "true", "1":
		return true
	case "no", "false", "0":
		return false
	default:
		return def
	}
}
