package l2tp

import (
	"net"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	base := Config{Server: "s", PSK: "k", Username: "u", Password: "p"}
	if err := base.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"no server":   func(c *Config) { c.Server = "" },
		"no psk":      func(c *Config) { c.PSK = "" },
		"no user":     func(c *Config) { c.Username = "" },
		"no password": func(c *Config) { c.Password = "" },
	} {
		c := base
		mut(&c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestParseOptions(t *testing.T) {
	d, err := parseOptions(map[string]string{
		OptServer: "vpn.example.com", OptPSK: "k", OptUser: "u", OptPassword: "p",
		OptPort: "4500", OptDNS: "1.1.1.1, 8.8.8.8",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := d.(dialer).cfg
	if cfg.Port != 4500 {
		t.Errorf("Port = %d, want 4500", cfg.Port)
	}
	if len(cfg.DNS) != 2 || !cfg.DNS[1].Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("DNS = %v, want [1.1.1.1 8.8.8.8]", cfg.DNS)
	}
	if _, err := parseOptions(map[string]string{OptServer: "s", OptPort: "nope"}); err == nil {
		t.Error("parseOptions accepted a non-numeric port")
	}
}

func TestParseIPListDropsJunk(t *testing.T) {
	got := parseIPList("1.1.1.1,,not-an-ip 9.9.9.9")
	if len(got) != 2 || !got[0].Equal(net.IPv4(1, 1, 1, 1)) || !got[1].Equal(net.IPv4(9, 9, 9, 9)) {
		t.Errorf("parseIPList = %v, want [1.1.1.1 9.9.9.9]", got)
	}
}

// A server with no PSK or no users cannot authenticate anyone, so NewServer must
// reject it before it opens a TUN or binds a socket.
func TestNewServerRequiresPSKAndUsers(t *testing.T) {
	if _, err := NewServer(ServerConfig{Users: map[string]string{"a": "b"}}); err == nil {
		t.Error("expected an error for a missing PSK")
	}
	if _, err := NewServer(ServerConfig{PSK: "k"}); err == nil {
		t.Error("expected an error for no configured users")
	}
}
