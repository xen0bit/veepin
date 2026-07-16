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

func TestParsePushSubnet(t *testing.T) {
	reply := "PUSH_REPLY,route-gateway 10.8.0.1,topology subnet,ifconfig 10.8.0.2 255.255.255.0,peer-id 3,cipher AES-256-GCM,tun-mtu 1400"
	p, err := parsePush(reply)
	if err != nil {
		t.Fatal(err)
	}
	if p.localIP.String() != "10.8.0.2" {
		t.Errorf("localIP = %s", p.localIP)
	}
	if p.netmask.String() != "255.255.255.0" {
		t.Errorf("netmask = %s", p.netmask)
	}
	if p.gateway.String() != "10.8.0.1" {
		t.Errorf("gateway = %s", p.gateway)
	}
	if p.peerID != 3 {
		t.Errorf("peerID = %d", p.peerID)
	}
	if p.mtu != 1400 {
		t.Errorf("mtu = %d", p.mtu)
	}
}

func TestParsePushNet30(t *testing.T) {
	// ifconfig LOCAL REMOTE (point-to-point): the second field is a gateway, not a
	// mask.
	p, err := parsePush("PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,peer-id 0")
	if err != nil {
		t.Fatal(err)
	}
	if p.gateway.String() != "10.8.0.5" {
		t.Errorf("ptp gateway = %s, want 10.8.0.5", p.gateway)
	}
	if p.netmask.String() != "255.255.255.255" {
		t.Errorf("ptp netmask = %s, want /32", p.netmask)
	}
}

func TestParsePushRejects(t *testing.T) {
	if _, err := parsePush("AUTH_FAILED"); err == nil {
		t.Error("AUTH_FAILED not surfaced as error")
	}
	if _, err := parsePush("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,cipher AES-128-CBC"); err == nil {
		t.Error("unsupported pushed cipher accepted")
	}
	if _, err := parsePush("PUSH_REPLY,peer-id 0"); err == nil {
		t.Error("missing ifconfig accepted")
	}
}

func TestPeerInfoAdvertisesGCMAndDataV2(t *testing.T) {
	pi := peerInfo()
	if !strings.Contains(pi, "IV_CIPHERS=AES-256-GCM") {
		t.Error("peer info does not advertise AES-256-GCM")
	}
	if !strings.Contains(pi, "IV_PROTO=2") {
		t.Error("peer info does not advertise P_DATA_V2 support")
	}
}
