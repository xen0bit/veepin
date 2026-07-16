package wireguard

import (
	"encoding/base64"
	"strings"
	"testing"
)

// b64Key returns a valid 32-octet WireGuard key in base64, filled from seed so
// distinct seeds give distinct keys.
func b64Key(seed byte) string {
	var k [32]byte
	for i := range k {
		k[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

const sampleConf = `
# a wg-quick style client config
[Interface]
PrivateKey = QOfC1234567890abcdefghijklmnopqrstuvwxyzABCD=
Address = 10.0.0.2/32
DNS = 1.1.1.1, 1.0.0.1
MTU = 1420
ListenPort = 51820   # ignored for a userspace initiator

[Peer]
PublicKey = ZYXW1234567890abcdefghijklmnopqrstuvwxyzABCD=
PresharedKey = MNOP1234567890abcdefghijklmnopqrstuvwxyzABCD=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(sampleConf))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PrivateKey != "QOfC1234567890abcdefghijklmnopqrstuvwxyzABCD=" {
		t.Errorf("PrivateKey = %q", cfg.PrivateKey)
	}
	if len(cfg.Address) != 1 || cfg.Address[0] != "10.0.0.2/32" {
		t.Errorf("Address = %v", cfg.Address)
	}
	if len(cfg.DNS) != 2 || cfg.DNS[0] != "1.1.1.1" || cfg.DNS[1] != "1.0.0.1" {
		t.Errorf("DNS = %v", cfg.DNS)
	}
	if cfg.MTU != 1420 {
		t.Errorf("MTU = %d", cfg.MTU)
	}
	if cfg.Endpoint != "vpn.example.com:51820" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
	if len(cfg.AllowedIPs) != 1 || cfg.AllowedIPs[0] != "0.0.0.0/0" {
		t.Errorf("AllowedIPs = %v", cfg.AllowedIPs)
	}
	if cfg.Keepalive != 25 {
		t.Errorf("Keepalive = %d", cfg.Keepalive)
	}
	if cfg.PresharedKey == "" {
		t.Error("PresharedKey not parsed")
	}
}

// TestParseConfigListForms checks the two ways wg accepts multiple values:
// comma-separated on one line, and a repeated key.
func TestParseConfigListForms(t *testing.T) {
	const conf = `
[Interface]
PrivateKey = k
Address = 10.0.0.2/32
[Peer]
PublicKey = p
Endpoint = h:1
AllowedIPs = 10.0.0.0/24, 10.1.0.0/24
AllowedIPs = 192.168.0.0/16
`
	cfg, err := ParseConfig(strings.NewReader(conf))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/24", "10.1.0.0/24", "192.168.0.0/16"}
	if len(cfg.AllowedIPs) != len(want) {
		t.Fatalf("AllowedIPs = %v, want %v", cfg.AllowedIPs, want)
	}
	for i, w := range want {
		if cfg.AllowedIPs[i] != w {
			t.Errorf("AllowedIPs[%d] = %q, want %q", i, cfg.AllowedIPs[i], w)
		}
	}
}

func TestParseConfigRejects(t *testing.T) {
	for _, tc := range []struct {
		name, conf string
	}{
		{"two peers", "[Peer]\nPublicKey=a\n[Peer]\nPublicKey=b\n"},
		{"unknown section", "[Server]\nX=1\n"},
		{"key before section", "PrivateKey = k\n"},
		{"unknown interface key", "[Interface]\nColour = blue\n"},
		{"bad MTU", "[Interface]\nMTU = big\n"},
		{"no equals", "[Interface]\nPrivateKey\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConfig(strings.NewReader(tc.conf)); err == nil {
				t.Errorf("%s: parsed without error", tc.name)
			}
		})
	}
}

// TestApplyOverrides checks that individual options win over a parsed file, the
// contract that lets the CLI take -config and flags together.
func TestApplyOverrides(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(sampleConf))
	if err != nil {
		t.Fatal(err)
	}
	err = cfg.applyOverrides(map[string]string{
		OptEndpoint:   "10.9.9.9:51820",
		OptAllowedIPs: "10.0.0.0/24",
		OptTUNName:    "wg0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "10.9.9.9:51820" {
		t.Errorf("Endpoint override = %q", cfg.Endpoint)
	}
	if len(cfg.AllowedIPs) != 1 || cfg.AllowedIPs[0] != "10.0.0.0/24" {
		t.Errorf("AllowedIPs override = %v", cfg.AllowedIPs)
	}
	if cfg.TUNName != "wg0" {
		t.Errorf("TUNName override = %q", cfg.TUNName)
	}
	// An empty override must not clobber a parsed value.
	if err := cfg.applyOverrides(map[string]string{OptEndpoint: ""}); err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "10.9.9.9:51820" {
		t.Errorf("empty override clobbered Endpoint: %q", cfg.Endpoint)
	}
}

// TestResolveValidation checks that resolve rejects the incomplete configs a
// user is most likely to produce, naming the missing field.
func TestResolveValidation(t *testing.T) {
	// A valid baseline built from real 32-octet base64 keys.
	base := func() *Config {
		return &Config{
			PrivateKey: b64Key(1),
			PublicKey:  b64Key(2),
			Endpoint:   "10.0.0.1:51820",
			Address:    []string{"10.0.0.2/32"},
			AllowedIPs: []string{"0.0.0.0/0"},
		}
	}
	if _, err := base().resolve(); err != nil {
		t.Fatalf("baseline should resolve: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no private key", func(c *Config) { c.PrivateKey = "" }, OptPrivateKey},
		{"no public key", func(c *Config) { c.PublicKey = "" }, OptPublicKey},
		{"no endpoint", func(c *Config) { c.Endpoint = "" }, OptEndpoint},
		{"no address", func(c *Config) { c.Address = nil }, OptAddress},
		{"no allowed-ips", func(c *Config) { c.AllowedIPs = nil }, OptAllowedIPs},
		{"short key", func(c *Config) { c.PrivateKey = "dG9vc2hvcnQ=" }, OptPrivateKey},
		{"bad allowed-ip", func(c *Config) { c.AllowedIPs = []string{"nonsense"} }, OptAllowedIPs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(cfg)
			_, err := cfg.resolve()
			if err == nil {
				t.Fatalf("%s: resolved without error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.want)
			}
		})
	}
}

// TestResolveBareAddress checks the wg-quick convenience of a bare IP in
// AllowedIPs standing for a host route.
func TestResolveBareAddress(t *testing.T) {
	cfg := &Config{
		PrivateKey: b64Key(1),
		PublicKey:  b64Key(2),
		Endpoint:   "10.0.0.1:51820",
		Address:    []string{"10.0.0.2/32"},
		AllowedIPs: []string{"10.0.0.1"}, // bare, no /32
	}
	r, err := cfg.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.allowedIPs) != 1 || r.allowedIPs[0].Bits() != 32 {
		t.Errorf("bare address did not become a /32: %v", r.allowedIPs)
	}
}
