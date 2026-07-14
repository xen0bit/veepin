// Package nmconfig maps a NetworkManager VPN connection dictionary
// (a{sa{sv}}, as delivered over D-Bus) to this project's client.Config, plus the
// handful of NM-specific knobs (full-tunnel) the plugin needs. It is pure data
// mapping with no D-Bus method calls, so it is unit-testable without a bus.
package nmconfig

import (
	"fmt"
	"strconv"

	"github.com/godbus/dbus/v5"
	"github.com/xen0bit/ikennkt/client"
)

// Settings is the wire shape NetworkManager passes to VPN.Plugin.Connect:
// setting-name -> key -> variant. The "vpn" setting nests "data" (a{ss}) and
// "secrets" (a{ss}).
type Settings = map[string]map[string]dbus.Variant

// Connection is the parsed, validated form of a VPN connection.
type Connection struct {
	Client     client.Config
	FullTunnel bool // maps to Ip4Config never-default = !FullTunnel
}

// Data-dictionary keys recognised in vpn.data.
const (
	KeyGateway    = "gateway"
	KeyPort       = "port"
	KeyLocalID    = "local-id"
	KeyServerID   = "server-id"
	KeyUser       = "user"
	KeyFullTunnel = "full-tunnel" // "yes"/"no", default "yes"
)

// Secret keys recognised in vpn.secrets.
const (
	KeyPSK      = "psk"
	KeyPassword = "password"
)

// Parse extracts and validates a Connection from the NM settings dict.
func Parse(s Settings) (Connection, error) {
	data := stringMap(s, "vpn", "data")
	secrets := stringMap(s, "vpn", "secrets")

	c := Connection{
		Client: client.Config{
			Server:      data[KeyGateway],
			LocalID:     data[KeyLocalID],
			ServerID:    data[KeyServerID],
			EAPUser:     data[KeyUser],
			PSK:         secrets[KeyPSK],
			EAPPassword: secrets[KeyPassword],
		},
		FullTunnel: boolData(data, KeyFullTunnel, true),
	}

	if p := data[KeyPort]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return Connection{}, fmt.Errorf("nmconfig: invalid %q: %q", KeyPort, p)
		}
		c.Client.Port = n
	}

	if c.Client.Server == "" {
		return Connection{}, fmt.Errorf("nmconfig: missing required %q", KeyGateway)
	}
	if c.Client.LocalID == "" {
		return Connection{}, fmt.Errorf("nmconfig: missing required %q", KeyLocalID)
	}
	return c, nil
}

// MissingSecret reports the name of the setting whose secrets NM must still
// supply (for VPN.Plugin.NeedSecrets), or "" if all required secrets are
// present. The PSK is always required; the EAP password is required only when a
// username is configured. An error is returned if the non-secret config is
// itself invalid.
func MissingSecret(s Settings) (string, error) {
	data := stringMap(s, "vpn", "data")
	secrets := stringMap(s, "vpn", "secrets")
	if data[KeyGateway] == "" || data[KeyLocalID] == "" {
		return "", fmt.Errorf("nmconfig: missing required connection data")
	}
	if secrets[KeyPSK] == "" {
		return "vpn", nil
	}
	if data[KeyUser] != "" && secrets[KeyPassword] == "" {
		return "vpn", nil
	}
	return "", nil
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
