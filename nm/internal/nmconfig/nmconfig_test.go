package nmconfig

import "testing"

import "github.com/godbus/dbus/v5"

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
	if c.Client.Server != "vpn.example.com" || c.Client.LocalID != "client.example" {
		t.Errorf("bad data mapping: %+v", c.Client)
	}
	if c.Client.ServerID != "vpn.example.com" {
		t.Errorf("server-id not mapped: %q", c.Client.ServerID)
	}
	if c.Client.PSK != "s3cret" {
		t.Errorf("psk not mapped: %q", c.Client.PSK)
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
	if c.Client.EAPUser != "alice" || c.Client.EAPPassword != "wonderland" {
		t.Errorf("EAP creds not mapped: %+v", c.Client)
	}
	if c.FullTunnel {
		t.Error("full-tunnel=no should be false")
	}
	if c.Client.Port != 5000 {
		t.Errorf("port = %d, want 5000", c.Client.Port)
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

func TestParseBadPort(t *testing.T) {
	if _, err := Parse(settings(
		map[string]string{KeyGateway: "g", KeyLocalID: "id", KeyPort: "notanumber"},
		map[string]string{KeyPSK: "p"},
	)); err == nil {
		t.Fatal("expected error for bad port")
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
