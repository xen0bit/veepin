package openvpn

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/openvpn/keys"
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

func TestParsePushRecordsCipher(t *testing.T) {
	// parsePush records the negotiated cipher; whether it is supported is decided
	// later, when the data cipher is built.
	p, err := parsePush("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,cipher AES-256-CBC")
	if err != nil {
		t.Fatal(err)
	}
	if p.cipher != "AES-256-CBC" {
		t.Errorf("pushed cipher = %q, want AES-256-CBC", p.cipher)
	}
}

func TestBuildDataCipherRejectsUnsupported(t *testing.T) {
	ks2 := &keys.KeySource2{}
	if _, err := buildDataCipher("AES-128-CBC", &Config{}, ks2, keys.SessionID{}, keys.SessionID{}, 0); err == nil {
		t.Error("unsupported cipher accepted")
	}
}

func TestParsePushRejects(t *testing.T) {
	if _, err := parsePush("AUTH_FAILED"); err == nil {
		t.Error("AUTH_FAILED not surfaced as error")
	}
	if _, err := parsePush("PUSH_REPLY,peer-id 0"); err == nil {
		t.Error("missing ifconfig accepted")
	}
}

func TestPeerInfoAdvertisesGCMAndDataV2(t *testing.T) {
	pi := peerInfo(&Config{Cipher: cipherGCM})
	if !strings.Contains(pi, "IV_CIPHERS=AES-256-GCM") {
		t.Error("peer info does not advertise AES-256-GCM")
	}
	if !strings.Contains(pi, "IV_PROTO=2") {
		t.Error("peer info does not advertise P_DATA_V2 support")
	}
}

func TestPeerInfoAdvertisesConfiguredCipher(t *testing.T) {
	pi := peerInfo(&Config{Cipher: cipherCBC})
	if !strings.Contains(pi, "IV_CIPHERS=AES-256-CBC") {
		t.Error("peer info does not advertise the configured CBC cipher")
	}
}

// TestLivenessDeadlineComesFromWhatTheServerPromised. OpenVPN's ping is never
// echoed, so inbound silence is the only liveness signal there is and it means
// nothing unless the server said it would be sending something. Each case here
// is a different thing a server can say.
func TestLivenessDeadlineComesFromWhatTheServerPromised(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply string
		want  time.Duration
	}{{
		name:  "ping-restart is OpenVPN's own name for this question",
		reply: "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ping 10,ping-restart 60",
		want:  60 * time.Second,
	}, {
		name:  "ping alone gives the stock keepalive 10 60 ratio",
		reply: "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ping 10",
		want:  60 * time.Second,
	}, {
		name:  "ping-restart wins even when it is the shorter of the two",
		reply: "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ping 10,ping-restart 25",
		want:  25 * time.Second,
	}, {
		name:  "a server that promised nothing gets no deadline invented for it",
		reply: "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0",
		want:  0,
	}, {
		name:  "a nonsense interval is not a promise either",
		reply: "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ping 0,ping-restart abc",
		want:  0,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parsePush(tc.reply)
			if err != nil {
				t.Fatalf("parsePush: %v", err)
			}
			if got := livenessDeadline(p); got != tc.want {
				t.Errorf("livenessDeadline = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestASilentServerIsOnlyDeadIfItPromisedToSpeak is the claim that keeps this
// probe from tearing down healthy tunnels. A server run without `keepalive`
// sends nothing at all on an idle tunnel, so silence there is the normal state
// -- and a timeout on it would disconnect a working session every few minutes.
func TestASilentServerIsOnlyDeadIfItPromisedToSpeak(t *testing.T) {
	s := &session{deadline: 0}
	if err := s.Probe(context.Background()); err != nil {
		t.Errorf("Probe on a server that promised nothing returned %v, want nil: "+
			"there is no claim to check, so there is nothing to fail", err)
	}
	if got := s.LivenessConfig(); got != (client.LivenessConfig{}) {
		t.Errorf("LivenessConfig = %+v, want the zero value so the monitor takes "+
			"the package defaults rather than spinning against a no-op probe", got)
	}
}

// TestLivenessConfigDoesNotAddAMinuteToTheServersDeadline. Probe compares one
// clock against one deadline, so a failure is conclusive; the default four
// failures at fifteen seconds would silently stretch every ping-restart a
// server pushed by another minute.
func TestLivenessConfigDoesNotAddAMinuteToTheServersDeadline(t *testing.T) {
	s := &session{deadline: 60 * time.Second}
	cfg := s.LivenessConfig()
	if cfg.MaxFailures != 1 {
		t.Errorf("MaxFailures = %d, want 1: the deadline has already done the tolerating",
			cfg.MaxFailures)
	}
	if cfg.Interval <= 0 || cfg.Interval > s.deadline {
		t.Errorf("Interval = %v, want a positive value no larger than the %v deadline",
			cfg.Interval, s.deadline)
	}
}
