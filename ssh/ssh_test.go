package ssh

import (
	"net"
	"testing"
)

func TestParseCIDR(t *testing.T) {
	ip, mask, err := parseCIDR("10.200.0.2/30")
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.IPv4(10, 200, 0, 2)) {
		t.Errorf("ip = %v, want 10.200.0.2", ip)
	}
	if got := net.IP(mask).String(); got != "255.255.255.252" {
		t.Errorf("mask = %v, want 255.255.255.252", got)
	}
	if _, _, err := parseCIDR("nonsense"); err == nil {
		t.Error("parseCIDR accepted a non-CIDR string")
	}
}

func TestConfigValidate(t *testing.T) {
	base := Config{Server: "s", User: "u", Address: "10.0.0.2/30", Identity: "k"}
	if err := base.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"no server":  func(c *Config) { c.Server = "" },
		"no user":    func(c *Config) { c.User = "" },
		"no address": func(c *Config) { c.Address = "" },
		"no auth":    func(c *Config) { c.Identity = ""; c.Password = "" },
	} {
		c := base
		mut(&c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestParseOptionsDefaultsPeerUnitToAny(t *testing.T) {
	d, err := parseOptions(map[string]string{
		OptServer: "s", OptUser: "u", OptAddress: "10.0.0.2/30", OptIdentity: "k",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.(dialer).cfg.PeerUnit != -1 {
		t.Errorf("PeerUnit = %d, want -1 (any)", d.(dialer).cfg.PeerUnit)
	}
}
