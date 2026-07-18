package anyconnect

import (
	"net"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	base := Config{Server: "vpn.example.com", Username: "alice", Password: "pw"}
	if err := base.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"no server":   func(c *Config) { c.Server = "" },
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
		OptServer: "vpn.example.com", OptUser: "alice", OptPassword: "pw",
		OptPort: "10443", OptInsecure: "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := d.(dialer).cfg
	if cfg.Port != 10443 {
		t.Errorf("Port = %d, want 10443", cfg.Port)
	}
	if !cfg.Insecure {
		t.Error("Insecure = false, want true")
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

// A server with no certificate or no users cannot serve anyone, so NewServer must
// reject it before it opens a TUN or binds a listener.
func TestNewServerRequiresCertAndUsers(t *testing.T) {
	if _, err := NewServer(ServerConfig{Users: map[string]string{"a": "b"}}); err == nil {
		t.Error("expected an error for a missing certificate")
	}
	if _, err := NewServer(ServerConfig{Cert: []byte("x"), Key: []byte("y")}); err == nil {
		t.Error("expected an error for no configured users")
	}
}
