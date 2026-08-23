package openvpn

import (
	"context"
	"net"
	"net/netip"
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

// A dual-stack server pushes ifconfig-ipv6 beside ifconfig, and the client has
// to keep both. Until it did, dataplane.AddrPool6 had one consumer in the tree
// and OpenVPN carried half the internet for a client on a v6-only network.
func TestParsePushKeepsTheIPv6Assignment(t *testing.T) {
	p, err := parsePush("PUSH_REPLY,route-gateway 10.8.0.1,topology subnet," +
		"ifconfig 10.8.0.2 255.255.255.0,ifconfig-ipv6 fd00:8::2/64 fd00:8::1," +
		"route-ipv6-gateway fd00:8::1,peer-id 3")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.localIP.String(); got != "10.8.0.2" {
		t.Errorf("localIP = %s", got)
	}
	if got := p.localIP6.String(); got != "fd00:8::2" {
		t.Errorf("localIP6 = %s, want the local half of ifconfig-ipv6", got)
	}
	if p.prefix6 != 64 {
		t.Errorf("prefix6 = %d, want 64", p.prefix6)
	}
}

// The argument order of ifconfig-ipv6 is local-then-remote, the opposite way
// round from --ifconfig on the command line. Taking the second field would
// configure the *server's* address on the client's own interface, which looks
// like a routing problem and is not one.
func TestParsePushTakesTheLocalHalfOfIfconfigIPv6(t *testing.T) {
	p, err := parsePush("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0," +
		"ifconfig-ipv6 fd00:8::2/64 fd00:8::1")
	if err != nil {
		t.Fatal(err)
	}
	if p.localIP6.Equal(net.ParseIP("fd00:8::1")) {
		t.Fatal("the client took the server's address as its own")
	}
}

// An IPv4-only server pushes no ifconfig-ipv6, and the client must come up
// rather than inventing a v6 address or refusing.
func TestParsePushWithoutIPv6LeavesTheV6HalfEmpty(t *testing.T) {
	p, err := parsePush("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,peer-id 1")
	if err != nil {
		t.Fatal(err)
	}
	if p.localIP6 != nil || p.prefix6 != 0 {
		t.Fatalf("v6 half is %v/%d on an IPv4-only push", p.localIP6, p.prefix6)
	}
}

// A malformed ifconfig-ipv6 is an error rather than a silently IPv4-only
// tunnel: a server that meant to assign v6 and failed is a configuration
// problem the operator has to see, and a client that quietly dropped it would
// be the same silent-discard bug the WireGuard client had.
func TestParsePushRejectsAMalformedIfconfigIPv6(t *testing.T) {
	for _, bad := range []string{
		"ifconfig-ipv6 not-an-address/64 fd00:8::1",
		"ifconfig-ipv6 10.8.0.2/64 fd00:8::1",
		"ifconfig-ipv6 fd00:8::2/300 fd00:8::1",
		"ifconfig-ipv6 fd00:8::2/-1 fd00:8::1",
	} {
		if _, err := parsePush("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0," + bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// The derivation is what stands in for a second address pool, so it has to be
// injective over the whole v4 pool -- two clients on one v6 address is a
// routing bug that presents as packet loss.
func TestTheIPv6DerivationIsOneToOneOverThePool(t *testing.T) {
	_, network, err := net.ParseCIDR("10.8.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("fd00:8::/64")
	seen := map[netip.Addr]net.IP{}
	for i := range 256 {
		ip := net.IPv4(10, 8, 0, byte(i)).To4()
		got, err := derive6(prefix, network, ip)
		if err != nil {
			t.Fatalf("%s: %v", ip, err)
		}
		if prev, dup := seen[got]; dup {
			t.Fatalf("%s and %s both map to %s", prev, ip, got)
		}
		seen[got] = ip
	}
	if got, err := derive6(prefix, network, net.IPv4(10, 8, 0, 2).To4()); err != nil || got.String() != "fd00:8::2" {
		t.Fatalf("10.8.0.2 -> %s (%v), want fd00:8::2", got, err)
	}
}

// A prefix too small for the pool would wrap two clients onto one address, so
// it is refused at construction rather than discovered as packet loss.
func TestAPrefixTooSmallForThePoolIsRefused(t *testing.T) {
	_, network, err := net.ParseCIDR("10.8.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if err := prefix6Fits(netip.MustParsePrefix("fd00:8::/126"), network); err == nil {
		t.Fatal("a /126 was accepted for a /16 pool")
	}
	if err := prefix6Fits(netip.MustParsePrefix("fd00:8::/64"), network); err != nil {
		t.Fatalf("a /64 was refused for a /16 pool: %v", err)
	}
}
