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
	"maps"
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

// SupportedProtocols is every protocol the plugin can dial — the set the
// requireKeys and secretMissing switches below handle. The service command must
// blank-import each one's package so client.Dial can find it at runtime; the
// cmd package's TestAllSupportedProtocolsRegistered guards that the two lists
// agree. The insecure "toy" example protocol is intentionally excluded.
var SupportedProtocols = []string{
	"ikev2", "wireguard", "openvpn", "sstp", "ssh",
	"anyconnect", "nebula", "masque", "fortinet", "l2tp",
}

// Connection is the parsed, validated form of a VPN connection.
type Connection struct {
	Protocol   string            // which protocol to dial (default "ikev2")
	Options    map[string]string // protocol options, passed to client.Dial
	FullTunnel bool              // maps to Ip4Config never-default = !FullTunnel
	MTU        int               // 0 = use the client's default tunnel MTU
}

// Data-dictionary keys recognised in vpn.data. The protocol-option names match
// the protocol packages' Opt* constants, so they pass through untranslated.
const (
	KeyProtocol   = "protocol" // which VPN protocol to dial; default "ikev2"
	KeyGateway    = "gateway"
	KeyPort       = "port"
	KeyLocalID    = "local-id"
	KeyServerID   = "server-id"
	KeyUser       = "user"
	KeyFullTunnel = "full-tunnel" // "yes"/"no", default "yes"
	KeyMTU        = "mtu"         // optional inner-interface MTU override

	// WireGuard, non-secret.
	KeyConfig     = "config"      // path to a wg-quick file (substitutes for the keys below)
	KeyPublicKey  = "public-key"  // peer static public key
	KeyEndpoint   = "endpoint"    // peer host:port
	KeyAddress    = "address"     // our tunnel address(es)
	KeyAllowedIPs = "allowed-ips" // destinations routed to the peer

	// Shared by the TLS/UDP client protocols (SSTP, SSH, AnyConnect, Fortinet,
	// L2TP, MASQUE). The names match each protocol package's Opt* constants, so
	// they pass through untranslated; only the *required*-key bookkeeping differs.
	KeyServer   = "server"   // gateway host or IP
	KeyRemote   = "remote"   // OpenVPN's name for the server host
	KeyUsername = "username" // OpenVPN spells the user key differently from the rest
	KeyCA       = "ca"       // CA bundle path (Nebula, OpenVPN)
	KeyCert     = "cert"     // certificate path (Nebula)
	KeyKeyFile  = "key"      // private-key file path (Nebula)
	KeyIdentity = "identity" // SSH private-key file — an alternative to a password
)

// Secret keys recognised in vpn.secrets.
const (
	KeyPSK      = "psk"
	KeyPassword = "password"

	// WireGuard secrets.
	KeyPrivateKey   = "private-key"   // our static private key
	KeyPresharedKey = "preshared-key" // optional preshared key
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

	// NM wants a clear error before it spawns anything, so the minimum non-secret
	// keys each protocol cannot start without are checked here as well as by the
	// protocol's own parser.
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
	maps.Copy(opts, secrets)
	return opts
}

// requireKeys checks the non-secret options a protocol cannot start without.
// Adding a protocol is a case here plus a matching import in the service's main
// package (so client.Dial can find it) and a secretMissing branch below.
func requireKeys(protocol string, opts map[string]string) error {
	switch protocol {
	case "ikev2":
		return requirePresent(opts, KeyGateway, KeyLocalID)
	case "wireguard":
		// A wg-quick file carries everything, so it excuses the individual keys.
		if opts[KeyConfig] != "" {
			return nil
		}
		return requirePresent(opts, KeyPublicKey, KeyEndpoint, KeyAddress, KeyAllowedIPs)
	case "openvpn":
		// An .ovpn file carries the remote (and usually the CA/cert); without one,
		// a remote host is the minimum needed to dial.
		if opts[KeyConfig] != "" {
			return nil
		}
		return requirePresent(opts, KeyRemote)
	case "sstp", "ssh", "anyconnect", "fortinet", "l2tp":
		// Connection-oriented gateways authenticated by a username (plus a password
		// or, for SSH, an identity key).
		return requirePresent(opts, KeyServer, KeyUser)
	case "nebula":
		// A certificate mesh: the CA bundle, this host's certificate and its key.
		return requirePresent(opts, KeyCA, KeyCert, KeyKeyFile)
	case "masque":
		return requirePresent(opts, KeyServer)
	default:
		return fmt.Errorf("nmconfig: unsupported %q: %q", KeyProtocol, protocol)
	}
}

// requirePresent reports the first of keys missing from opts.
func requirePresent(opts map[string]string, keys ...string) error {
	for _, k := range keys {
		if opts[k] == "" {
			return fmt.Errorf("nmconfig: missing required %q", k)
		}
	}
	return nil
}

// MissingSecret reports the name of the setting whose secrets NM must still
// supply (for VPN.Plugin.NeedSecrets), or "" if all required secrets are
// present. An error is returned if the non-secret config is itself invalid.
func MissingSecret(s Settings) (string, error) {
	conn, err := Parse(s)
	if err != nil {
		return "", err
	}
	if secretMissing(conn.Protocol, conn.Options) {
		return "vpn", nil
	}
	return "", nil
}

// secretMissing reports whether a secret the protocol needs to dial is not yet
// present in opts (data and secrets merged). File-path credentials — CA/cert/key
// PEMs, wg-quick/.ovpn files, an SSH identity key — live in vpn.data, not
// vpn.secrets, so they are not treated as NM-prompted secrets here.
//
// Parse has already rejected any unknown protocol, so the default never fires for
// a Connection that reached this point.
func secretMissing(protocol string, opts map[string]string) bool {
	switch protocol {
	case "ikev2":
		// The PSK is always required; the EAP password only when a user is set.
		if opts[KeyPSK] == "" {
			return true
		}
		return opts[KeyUser] != "" && opts[KeyPassword] == ""
	case "wireguard":
		// A wg-quick file holds its own keys; otherwise the private key is required.
		// The preshared key is optional.
		return opts[KeyConfig] == "" && opts[KeyPrivateKey] == ""
	case "openvpn":
		// Password only when a username is configured; certificate-only auth (or an
		// .ovpn with embedded credentials) needs no NM-prompted secret.
		return opts[KeyUsername] != "" && opts[KeyPassword] == ""
	case "sstp", "anyconnect", "fortinet":
		return opts[KeyPassword] == ""
	case "ssh":
		// A private-key identity file is an alternative to a password.
		return opts[KeyIdentity] == "" && opts[KeyPassword] == ""
	case "l2tp":
		// Both the IPsec PSK and the PPP password are required.
		return opts[KeyPSK] == "" || opts[KeyPassword] == ""
	case "nebula", "masque":
		// Authenticated by a certificate / TLS only: no NM-prompted secret.
		return false
	default:
		return false
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
