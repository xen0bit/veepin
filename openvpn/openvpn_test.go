package openvpn

import (
	"strings"
	"testing"
)

func TestParseConfigInlineAndDirectives(t *testing.T) {
	const cfgText = `
# a comment
client
dev tun
proto udp
remote vpn.example.com 1194
cipher AES-256-GCM
<ca>
CA-PEM-BODY
</ca>
<cert>
CERT-PEM-BODY
</cert>
<key>
KEY-PEM-BODY
</key>
`
	cfg, err := parseConfig(strings.NewReader(cfgText), ".")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Remote != "vpn.example.com" || cfg.Port != 1194 {
		t.Errorf("remote = %s:%d", cfg.Remote, cfg.Port)
	}
	if cfg.Cipher != "AES-256-GCM" {
		t.Errorf("cipher = %q", cfg.Cipher)
	}
	if !strings.Contains(string(cfg.CA), "CA-PEM-BODY") {
		t.Errorf("ca not captured: %q", cfg.CA)
	}
	if !strings.Contains(string(cfg.Cert), "CERT-PEM-BODY") || !strings.Contains(string(cfg.Key), "KEY-PEM-BODY") {
		t.Error("cert/key inline blocks not captured")
	}
}

func TestParseConfigRejectsTCP(t *testing.T) {
	if _, err := parseConfig(strings.NewReader("proto tcp\nremote h 1\n"), "."); err == nil {
		t.Error("tcp proto accepted")
	}
}

func TestValidateDefaultsAndRejects(t *testing.T) {
	base := func() *Config {
		return &Config{Remote: "h", CA: []byte("ca"), Cert: []byte("c"), Key: []byte("k")}
	}
	cfg := base()
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Port != defaultPort || cfg.Cipher != defaultCipher {
		t.Errorf("defaults not applied: port=%d cipher=%q", cfg.Port, cfg.Cipher)
	}

	missing := base()
	missing.CA = nil
	if err := missing.validate(); err == nil {
		t.Error("missing CA accepted")
	}

	badCipher := base()
	badCipher.Cipher = "AES-128-CBC"
	if err := badCipher.validate(); err == nil {
		t.Error("unsupported cipher accepted")
	}
}

func TestApplyOverridesWins(t *testing.T) {
	cfg := &Config{Remote: "fromfile", Port: 1194}
	err := cfg.applyOverrides(map[string]string{
		OptRemote: "override.example.com",
		OptPort:   "443",
		OptCipher: "AES-256-GCM",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Remote != "override.example.com" || cfg.Port != 443 {
		t.Errorf("overrides not applied: %s:%d", cfg.Remote, cfg.Port)
	}
}
