package nmconfig

import (
	"maps"
	"testing"

	"github.com/godbus/dbus/v5"
)

// settings builds an NM VPN settings dict with the given data and secrets maps.
func settings(data, secrets map[string]string) Settings {
	return Settings{
		"vpn": {
			"data":    dbus.MakeVariant(data),
			"secrets": dbus.MakeVariant(secrets),
		},
	}
}

func TestParsePSK(t *testing.T) {
	c, err := Parse(settings(
		map[string]string{KeyGateway: "vpn.example.com", KeyLocalID: "client.example", KeyServerID: "vpn.example.com"},
		map[string]string{KeyPSK: "s3cret"},
	))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Protocol != DefaultProtocol {
		t.Errorf("protocol = %q, want %q by default", c.Protocol, DefaultProtocol)
	}
	if c.Options[KeyGateway] != "vpn.example.com" || c.Options[KeyLocalID] != "client.example" {
		t.Errorf("bad data mapping: %+v", c.Options)
	}
	if c.Options[KeyServerID] != "vpn.example.com" {
		t.Errorf("server-id not mapped: %q", c.Options[KeyServerID])
	}
	if c.Options[KeyPSK] != "s3cret" {
		t.Errorf("psk not mapped: %q", c.Options[KeyPSK])
	}
	if !c.FullTunnel {
		t.Error("full-tunnel should default to true")
	}
}

func TestParseEAPAndFullTunnelFalse(t *testing.T) {
	c, err := Parse(settings(
		map[string]string{KeyGateway: "g", KeyLocalID: "id", KeyUser: "alice", KeyFullTunnel: "no", KeyPort: "5000"},
		map[string]string{KeyPSK: "p", KeyPassword: "wonderland"},
	))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Options[KeyUser] != "alice" || c.Options[KeyPassword] != "wonderland" {
		t.Errorf("EAP creds not mapped: %+v", c.Options)
	}
	if c.FullTunnel {
		t.Error("full-tunnel=no should be false")
	}
	if c.Options[KeyPort] != "5000" {
		t.Errorf("port = %q, want 5000", c.Options[KeyPort])
	}
}

// TestParseProtocol covers the key that selects which protocol to dial.
func TestParseProtocol(t *testing.T) {
	// An explicit protocol is honoured...
	c, err := Parse(settings(
		map[string]string{KeyProtocol: "ikev2", KeyGateway: "g", KeyLocalID: "id"},
		map[string]string{KeyPSK: "p"},
	))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Protocol != "ikev2" {
		t.Errorf("protocol = %q, want ikev2", c.Protocol)
	}
	// ...and an unsupported one is rejected up front, rather than failing later
	// inside client.Dial.
	if _, err := Parse(settings(
		map[string]string{KeyProtocol: "carrier-pigeon", KeyGateway: "g", KeyLocalID: "id"},
		map[string]string{KeyPSK: "p"},
	)); err == nil {
		t.Error("unsupported protocol was accepted")
	}
}

// TestParseOptionsExcludeNMOnlyKeys ensures the keys the plugin consumes itself
// are not forwarded to the protocol as options.
func TestParseOptionsExcludeNMOnlyKeys(t *testing.T) {
	c, err := Parse(settings(
		map[string]string{
			KeyProtocol: "ikev2", KeyGateway: "g", KeyLocalID: "id",
			KeyFullTunnel: "no", KeyMTU: "1380",
		},
		map[string]string{KeyPSK: "p"},
	))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, k := range []string{KeyProtocol, KeyFullTunnel, KeyMTU} {
		if _, present := c.Options[k]; present {
			t.Errorf("NM-only key %q leaked into protocol options", k)
		}
	}
	// Secrets and data both reach the protocol.
	if c.Options[KeyPSK] != "p" || c.Options[KeyGateway] != "g" {
		t.Errorf("options missing data/secrets: %+v", c.Options)
	}
}

func TestParseMissingRequired(t *testing.T) {
	for _, tc := range []struct {
		name string
		data map[string]string
	}{
		{"no gateway", map[string]string{KeyLocalID: "id"}},
		{"no local-id", map[string]string{KeyGateway: "g"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(settings(tc.data, map[string]string{KeyPSK: "p"})); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// TestParseWireGuard covers the second protocol's data/secret mapping and its
// distinct required keys.
func TestParseWireGuard(t *testing.T) {
	c, err := Parse(settings(
		map[string]string{
			KeyProtocol: "wireguard", KeyPublicKey: "pub", KeyEndpoint: "h:51820",
			KeyAddress: "10.0.0.2/32", KeyAllowedIPs: "0.0.0.0/0",
		},
		map[string]string{KeyPrivateKey: "priv", KeyPresharedKey: "psk"},
	))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Protocol != "wireguard" {
		t.Errorf("protocol = %q, want wireguard", c.Protocol)
	}
	// Data and secrets both reach the protocol untranslated.
	for k, want := range map[string]string{
		KeyPublicKey: "pub", KeyEndpoint: "h:51820", KeyAddress: "10.0.0.2/32",
		KeyAllowedIPs: "0.0.0.0/0", KeyPrivateKey: "priv", KeyPresharedKey: "psk",
	} {
		if c.Options[k] != want {
			t.Errorf("option %q = %q, want %q", k, c.Options[k], want)
		}
	}
}

// TestParseWireGuardRequired checks the missing-key rejection, and that a
// wg-quick config file excuses the individual keys.
func TestParseWireGuardRequired(t *testing.T) {
	base := map[string]string{
		KeyProtocol: "wireguard", KeyPublicKey: "pub", KeyEndpoint: "h:1",
		KeyAddress: "10.0.0.2/32", KeyAllowedIPs: "0.0.0.0/0",
	}
	for _, drop := range []string{KeyPublicKey, KeyEndpoint, KeyAddress, KeyAllowedIPs} {
		data := map[string]string{}
		for k, v := range base {
			if k != drop {
				data[k] = v
			}
		}
		if _, err := Parse(settings(data, map[string]string{KeyPrivateKey: "priv"})); err == nil {
			t.Errorf("missing %q was accepted", drop)
		}
	}
	// A config file stands in for all of them.
	if _, err := Parse(settings(
		map[string]string{KeyProtocol: "wireguard", KeyConfig: "/etc/wireguard/wg0.conf"},
		map[string]string{},
	)); err != nil {
		t.Errorf("config file should satisfy the requirements: %v", err)
	}
}

// TestMissingSecretWireGuard checks that the private key is a required secret,
// unless a config file supplies it.
func TestMissingSecretWireGuard(t *testing.T) {
	data := map[string]string{
		KeyProtocol: "wireguard", KeyPublicKey: "pub", KeyEndpoint: "h:1",
		KeyAddress: "10.0.0.2/32", KeyAllowedIPs: "0.0.0.0/0",
	}
	// Private key present: satisfied.
	if got, err := MissingSecret(settings(data, map[string]string{KeyPrivateKey: "priv"})); err != nil || got != "" {
		t.Errorf("private key present: got %q, err %v", got, err)
	}
	// Private key missing: needs "vpn".
	if got, _ := MissingSecret(settings(data, map[string]string{})); got != "vpn" {
		t.Errorf("private key missing: got %q, want vpn", got)
	}
	// A config file carries its own keys, so no NM secret is required.
	if got, err := MissingSecret(settings(
		map[string]string{KeyProtocol: "wireguard", KeyConfig: "/etc/wireguard/wg0.conf"},
		map[string]string{},
	)); err != nil || got != "" {
		t.Errorf("config file: got %q, err %v", got, err)
	}
}

func TestParseBadPort(t *testing.T) {
	if _, err := Parse(settings(
		map[string]string{KeyGateway: "g", KeyLocalID: "id", KeyPort: "notanumber"},
		map[string]string{KeyPSK: "p"},
	)); err == nil {
		t.Fatal("expected error for bad port")
	}
}

func TestParseMTU(t *testing.T) {
	c, err := Parse(settings(
		map[string]string{KeyGateway: "g", KeyLocalID: "id", KeyMTU: "1380"},
		map[string]string{KeyPSK: "p"},
	))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.MTU != 1380 {
		t.Errorf("MTU = %d, want 1380", c.MTU)
	}

	// Absent -> 0 (use client default).
	c, _ = Parse(settings(map[string]string{KeyGateway: "g", KeyLocalID: "id"}, map[string]string{KeyPSK: "p"}))
	if c.MTU != 0 {
		t.Errorf("absent MTU = %d, want 0", c.MTU)
	}

	// Out of range / non-numeric -> error.
	for _, bad := range []string{"100", "99999", "nope"} {
		if _, err := Parse(settings(
			map[string]string{KeyGateway: "g", KeyLocalID: "id", KeyMTU: bad},
			map[string]string{KeyPSK: "p"},
		)); err == nil {
			t.Errorf("MTU %q should be rejected", bad)
		}
	}
}

// TestParseAllProtocolsPassThrough gives each supported protocol a minimal valid
// connection and checks that Parse accepts it, selects the right protocol, and
// forwards the protocol options untranslated (the plugin adds no per-protocol
// mapping — the data/secret keys already match each package's Opt* constants).
func TestParseAllProtocolsPassThrough(t *testing.T) {
	for _, tc := range []struct {
		proto   string
		data    map[string]string
		secrets map[string]string
		check   string // an option that must survive to c.Options
	}{
		{"ikev2", map[string]string{KeyGateway: "g", KeyLocalID: "id"}, map[string]string{KeyPSK: "p"}, KeyGateway},
		{"wireguard", map[string]string{KeyPublicKey: "pub", KeyEndpoint: "h:1", KeyAddress: "10.0.0.2/32", KeyAllowedIPs: "0.0.0.0/0"}, map[string]string{KeyPrivateKey: "k"}, KeyEndpoint},
		{"openvpn", map[string]string{KeyRemote: "vpn.example.com"}, map[string]string{}, KeyRemote},
		{"sstp", map[string]string{KeyServer: "h", KeyUser: "u"}, map[string]string{KeyPassword: "p"}, KeyServer},
		{"ssh", map[string]string{KeyServer: "h", KeyUser: "u", KeyIdentity: "/k"}, map[string]string{}, KeyIdentity},
		{"anyconnect", map[string]string{KeyServer: "h", KeyUser: "u"}, map[string]string{KeyPassword: "p"}, KeyUser},
		{"nebula", map[string]string{KeyCA: "/ca", KeyCert: "/c", KeyKeyFile: "/k"}, map[string]string{}, KeyCA},
		{"masque", map[string]string{KeyServer: "proxy"}, map[string]string{}, KeyServer},
		{"fortinet", map[string]string{KeyServer: "h", KeyUser: "u"}, map[string]string{KeyPassword: "p"}, KeyServer},
		{"l2tp", map[string]string{KeyServer: "h", KeyUser: "u"}, map[string]string{KeyPSK: "s", KeyPassword: "p"}, KeyServer},
	} {
		t.Run(tc.proto, func(t *testing.T) {
			data := map[string]string{KeyProtocol: tc.proto}
			maps.Copy(data, tc.data)
			c, err := Parse(settings(data, tc.secrets))
			if err != nil {
				t.Fatalf("Parse(%s): %v", tc.proto, err)
			}
			if c.Protocol != tc.proto {
				t.Errorf("protocol = %q, want %q", c.Protocol, tc.proto)
			}
			if c.Options[tc.check] != tc.data[tc.check] {
				t.Errorf("option %q = %q, want %q", tc.check, c.Options[tc.check], tc.data[tc.check])
			}
			// NeedSecrets must not error on a fully specified connection.
			if _, err := MissingSecret(settings(data, tc.secrets)); err != nil {
				t.Errorf("MissingSecret(%s): unexpected error %v", tc.proto, err)
			}
		})
	}
}

// TestRequireKeysPerProtocol checks that dropping a required non-secret key makes
// Parse reject the connection before anything is spawned.
func TestRequireKeysPerProtocol(t *testing.T) {
	for _, tc := range []struct {
		name string
		data map[string]string
		drop string // required key to remove; the reduced data must be rejected
	}{
		{"openvpn without remote or config", map[string]string{KeyProtocol: "openvpn", KeyRemote: "h"}, KeyRemote},
		{"sstp without server", map[string]string{KeyProtocol: "sstp", KeyServer: "h", KeyUser: "u"}, KeyServer},
		{"sstp without user", map[string]string{KeyProtocol: "sstp", KeyServer: "h", KeyUser: "u"}, KeyUser},
		{"ssh without user", map[string]string{KeyProtocol: "ssh", KeyServer: "h", KeyUser: "u"}, KeyUser},
		{"anyconnect without server", map[string]string{KeyProtocol: "anyconnect", KeyServer: "h", KeyUser: "u"}, KeyServer},
		{"fortinet without user", map[string]string{KeyProtocol: "fortinet", KeyServer: "h", KeyUser: "u"}, KeyUser},
		{"l2tp without server", map[string]string{KeyProtocol: "l2tp", KeyServer: "h", KeyUser: "u"}, KeyServer},
		{"nebula without key", map[string]string{KeyProtocol: "nebula", KeyCA: "/ca", KeyCert: "/c", KeyKeyFile: "/k"}, KeyKeyFile},
		{"nebula without ca", map[string]string{KeyProtocol: "nebula", KeyCA: "/ca", KeyCert: "/c", KeyKeyFile: "/k"}, KeyCA},
		{"masque without server", map[string]string{KeyProtocol: "masque", KeyServer: "h"}, KeyServer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The full data parses (secrets aren't checked by Parse).
			if _, err := Parse(settings(tc.data, map[string]string{})); err != nil {
				t.Fatalf("full config should parse: %v", err)
			}
			reduced := map[string]string{}
			for k, v := range tc.data {
				if k != tc.drop {
					reduced[k] = v
				}
			}
			if _, err := Parse(settings(reduced, map[string]string{})); err == nil {
				t.Errorf("dropping %q was accepted", tc.drop)
			}
		})
	}
}

// TestOpenVPNConfigExcusesRemote mirrors the wg-quick case: an .ovpn file carries
// the remote, so the individual remote key is not separately required.
func TestOpenVPNConfigExcusesRemote(t *testing.T) {
	if _, err := Parse(settings(
		map[string]string{KeyProtocol: "openvpn", KeyConfig: "/etc/openvpn/client.ovpn"},
		map[string]string{},
	)); err != nil {
		t.Errorf(".ovpn config should satisfy the requirement: %v", err)
	}
}

// TestMissingSecretPerProtocol checks the per-protocol secret bookkeeping NM uses
// to decide whether to prompt the user (NeedSecrets).
func TestMissingSecretPerProtocol(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    map[string]string
		secrets map[string]string
		want    string
	}{
		// OpenVPN: password only when a username is present.
		{"openvpn cert-only", map[string]string{KeyProtocol: "openvpn", KeyRemote: "h"}, map[string]string{}, ""},
		{"openvpn user no password", map[string]string{KeyProtocol: "openvpn", KeyRemote: "h", KeyUsername: "u"}, map[string]string{}, "vpn"},
		{"openvpn user and password", map[string]string{KeyProtocol: "openvpn", KeyRemote: "h", KeyUsername: "u"}, map[string]string{KeyPassword: "p"}, ""},
		// Username/password gateways: password always required.
		{"sstp no password", map[string]string{KeyProtocol: "sstp", KeyServer: "h", KeyUser: "u"}, map[string]string{}, "vpn"},
		{"sstp password", map[string]string{KeyProtocol: "sstp", KeyServer: "h", KeyUser: "u"}, map[string]string{KeyPassword: "p"}, ""},
		{"anyconnect no password", map[string]string{KeyProtocol: "anyconnect", KeyServer: "h", KeyUser: "u"}, map[string]string{}, "vpn"},
		{"fortinet password", map[string]string{KeyProtocol: "fortinet", KeyServer: "h", KeyUser: "u"}, map[string]string{KeyPassword: "p"}, ""},
		// SSH: an identity file is an alternative to a password.
		{"ssh identity no password", map[string]string{KeyProtocol: "ssh", KeyServer: "h", KeyUser: "u", KeyIdentity: "/k"}, map[string]string{}, ""},
		{"ssh no identity no password", map[string]string{KeyProtocol: "ssh", KeyServer: "h", KeyUser: "u"}, map[string]string{}, "vpn"},
		{"ssh password", map[string]string{KeyProtocol: "ssh", KeyServer: "h", KeyUser: "u"}, map[string]string{KeyPassword: "p"}, ""},
		// L2TP: both the IPsec PSK and the PPP password are required.
		{"l2tp missing both", map[string]string{KeyProtocol: "l2tp", KeyServer: "h", KeyUser: "u"}, map[string]string{}, "vpn"},
		{"l2tp missing password", map[string]string{KeyProtocol: "l2tp", KeyServer: "h", KeyUser: "u"}, map[string]string{KeyPSK: "s"}, "vpn"},
		{"l2tp missing psk", map[string]string{KeyProtocol: "l2tp", KeyServer: "h", KeyUser: "u"}, map[string]string{KeyPassword: "p"}, "vpn"},
		{"l2tp both present", map[string]string{KeyProtocol: "l2tp", KeyServer: "h", KeyUser: "u"}, map[string]string{KeyPSK: "s", KeyPassword: "p"}, ""},
		// Certificate/TLS-only protocols prompt for nothing.
		{"nebula no secret", map[string]string{KeyProtocol: "nebula", KeyCA: "/ca", KeyCert: "/c", KeyKeyFile: "/k"}, map[string]string{}, ""},
		{"masque no secret", map[string]string{KeyProtocol: "masque", KeyServer: "h"}, map[string]string{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MissingSecret(settings(tc.data, tc.secrets))
			if err != nil {
				t.Fatalf("MissingSecret: %v", err)
			}
			if got != tc.want {
				t.Errorf("MissingSecret = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMissingSecret(t *testing.T) {
	// PSK present, no user: satisfied.
	if got, err := MissingSecret(settings(
		map[string]string{KeyGateway: "g", KeyLocalID: "id"},
		map[string]string{KeyPSK: "p"},
	)); err != nil || got != "" {
		t.Errorf("psk present: got %q, err %v; want \"\"", got, err)
	}
	// PSK missing: needs "vpn".
	if got, _ := MissingSecret(settings(
		map[string]string{KeyGateway: "g", KeyLocalID: "id"},
		map[string]string{},
	)); got != "vpn" {
		t.Errorf("psk missing: got %q, want vpn", got)
	}
	// User set but no password: needs "vpn".
	if got, _ := MissingSecret(settings(
		map[string]string{KeyGateway: "g", KeyLocalID: "id", KeyUser: "alice"},
		map[string]string{KeyPSK: "p"},
	)); got != "vpn" {
		t.Errorf("password missing: got %q, want vpn", got)
	}
}
