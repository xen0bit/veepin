package gp

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func testESPConfig(t *testing.T) *ESPConfig {
	t.Helper()
	e, err := GenerateESP("aes-128-cbc", "sha1")
	if err != nil {
		t.Fatalf("GenerateESP: %v", err)
	}
	return e
}

func TestConfigRoundTrip(t *testing.T) {
	esp := testESPConfig(t)
	want := Config{
		AssignedIP:  net.ParseIP("10.50.0.7").To4(),
		Netmask:     net.IPMask(net.ParseIP("255.255.255.0").To4()),
		GatewayAddr: net.ParseIP("198.51.100.1").To4(),
		DNS:         []net.IP{net.ParseIP("10.50.0.1").To4()},
		Domain:      "example.com",
		MTU:         1400,
		Lifetime:    86400,
		Timeout:     3600,
		Include:     []Route{{IP: net.ParseIP("0.0.0.0").To4(), Mask: net.CIDRMask(0, 32)}},
		Exclude:     []Route{{IP: net.ParseIP("192.0.2.0").To4(), Mask: net.CIDRMask(24, 32)}},
		ESP:         esp,
	}

	got, err := ParseConfigXML(BuildConfigXML(want))
	if err != nil {
		t.Fatalf("ParseConfigXML: %v", err)
	}
	if !got.AssignedIP.Equal(want.AssignedIP) {
		t.Errorf("assigned %v, want %v", got.AssignedIP, want.AssignedIP)
	}
	if !bytes.Equal(got.Netmask, want.Netmask) {
		t.Errorf("netmask %v, want %v", got.Netmask, want.Netmask)
	}
	if !got.GatewayAddr.Equal(want.GatewayAddr) {
		t.Errorf("gw-address %v, want %v", got.GatewayAddr, want.GatewayAddr)
	}
	if got.MTU != 1400 || got.Lifetime != 86400 || got.Timeout != 3600 {
		t.Errorf("mtu/lifetime/timeout %d/%d/%d", got.MTU, got.Lifetime, got.Timeout)
	}
	if got.Domain != "example.com" {
		t.Errorf("domain %q", got.Domain)
	}
	if len(got.DNS) != 1 || !got.DNS[0].Equal(want.DNS[0]) {
		t.Errorf("dns %v", got.DNS)
	}
	if got.SSLTunnelURL != PathTunnel {
		t.Errorf("ssl-tunnel-url %q, want %q", got.SSLTunnelURL, PathTunnel)
	}
	if len(got.Include) != 1 || got.Include[0].String() != "0.0.0.0/0" {
		t.Errorf("include routes %v", got.Include)
	}
	if len(got.Exclude) != 1 || got.Exclude[0].String() != "192.0.2.0/24" {
		t.Errorf("exclude routes %v", got.Exclude)
	}
}

// TestESPKeysSurviveTheDocument is the load-bearing one: the keys are the
// protocol's whole security, and they travel as hex in this XML. A rendering or
// parsing slip would produce a tunnel that fails to decrypt rather than one that
// is insecure, but either way the round trip must be exact.
func TestESPKeysRoundTrip(t *testing.T) {
	want := testESPConfig(t)
	got, err := ParseConfigXML(BuildConfigXML(Config{
		AssignedIP: net.ParseIP("10.50.0.7").To4(),
		ESP:        want,
	}))
	if err != nil {
		t.Fatalf("ParseConfigXML: %v", err)
	}
	if got.ESP == nil {
		t.Fatal("the keying block did not survive the document")
	}
	e := got.ESP
	if e.C2SSPI != want.C2SSPI || e.S2CSPI != want.S2CSPI {
		t.Errorf("SPIs %#x/%#x, want %#x/%#x", e.C2SSPI, e.S2CSPI, want.C2SSPI, want.S2CSPI)
	}
	if e.EncAlgo != want.EncAlgo || e.HMACAlgo != want.HMACAlgo {
		t.Errorf("algorithms %s/%s", e.EncAlgo, e.HMACAlgo)
	}
	if e.UDPPort != DefaultESPPort {
		t.Errorf("udp-port %d, want %d", e.UDPPort, DefaultESPPort)
	}
	for _, k := range []struct {
		name     string
		got, exp []byte
	}{
		{"ekey-c2s", e.EKeyC2S, want.EKeyC2S},
		{"akey-c2s", e.AKeyC2S, want.AKeyC2S},
		{"ekey-s2c", e.EKeyS2C, want.EKeyS2C},
		{"akey-s2c", e.AKeyS2C, want.AKeyS2C},
	} {
		if !bytes.Equal(k.got, k.exp) {
			t.Errorf("%s round-tripped as %x, want %x", k.name, k.got, k.exp)
		}
	}
}

// TestSPIRendering pins the 0x-prefixed hex form the document uses; a plain
// decimal SPI would be misread by a real client.
func TestSPIRendering(t *testing.T) {
	doc := string(BuildConfigXML(Config{ESP: &ESPConfig{
		EncAlgo: "aes-128-cbc", HMACAlgo: "sha1",
		C2SSPI: 0xdeadbeef, S2CSPI: 0x00000001,
	}}))
	if !strings.Contains(doc, "<c2s-spi>0xdeadbeef</c2s-spi>") {
		t.Errorf("c2s-spi is not 0x-prefixed hex:\n%s", doc)
	}
	if !strings.Contains(doc, "<s2c-spi>0x00000001</s2c-spi>") {
		t.Errorf("s2c-spi is not zero-padded hex:\n%s", doc)
	}
}

func TestParseSPI(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
		bad  bool
	}{
		{"0xdeadbeef", 0xdeadbeef, false},
		{"0XDEADBEEF", 0xdeadbeef, false},
		{"deadbeef", 0xdeadbeef, false},
		{"", 0, false},
		{"0xdeadbeef00", 0, true},
		{"nonsense", 0, true},
	}
	for _, tc := range cases {
		got, err := parseSPI(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("parseSPI(%q) accepted a bad value", tc.in)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("parseSPI(%q) = %#x, %v; want %#x", tc.in, got, err, tc.want)
		}
	}
}

// TestBitsMismatchIsRejected covers a document that contradicts itself about a
// key's length. These are keys, so the answer is to refuse rather than guess.
func TestBitsMismatchIsRejected(t *testing.T) {
	doc := string(BuildConfigXML(Config{ESP: testESPConfig(t)}))
	bad := strings.Replace(doc, "<bits>128</bits>", "<bits>256</bits>", 1)
	if _, err := ParseConfigXML([]byte(bad)); err == nil {
		t.Error("a key whose stated length disagreed with its value was accepted")
	}
}

func TestParseConfigRejects(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"not xml", "<<<"},
		{"bad address", `<response><ip-address>not-an-ip</ip-address></response>`},
		{"bad netmask", `<response><netmask>::1</netmask></response>`},
		{"non-hex key", `<response><ipsec><enc-algo>aes-128-cbc</enc-algo>` +
			`<ekey-c2s><val>zzzz</val></ekey-c2s></ipsec></response>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConfigXML([]byte(tc.doc)); err == nil {
				t.Error("a malformed document was accepted")
			}
		})
	}
}

// TestConfigWithoutIPSec is the SSL-tunnel-only gateway: legitimate, and it must
// not read as an error or as an empty keying block that later fails to key.
func TestConfigWithoutIPSec(t *testing.T) {
	cfg, err := ParseConfigXML([]byte(`<response><ip-address>10.50.0.7</ip-address></response>`))
	if err != nil {
		t.Fatalf("ParseConfigXML: %v", err)
	}
	if cfg.ESP != nil {
		t.Error("a document with no <ipsec> yielded a keying block")
	}

	empty, err := ParseConfigXML([]byte(`<response><ip-address>10.50.0.7</ip-address><ipsec/></response>`))
	if err != nil {
		t.Fatalf("ParseConfigXML: %v", err)
	}
	if empty.ESP != nil {
		t.Error("an empty <ipsec> yielded a keying block")
	}
}

// TestUnknownElementsAreIgnored: PAN-OS adds fields between versions, and a
// client that rejected an unfamiliar tag would break on a gateway upgrade.
func TestUnknownElementsAreIgnored(t *testing.T) {
	doc := `<response><ip-address>10.50.0.7</ip-address>` +
		`<something-new><nested>1</nested></something-new>` +
		`<netmask>255.255.255.0</netmask></response>`
	cfg, err := ParseConfigXML([]byte(doc))
	if err != nil {
		t.Fatalf("ParseConfigXML: %v", err)
	}
	if !cfg.AssignedIP.Equal(net.ParseIP("10.50.0.7")) {
		t.Errorf("assigned %v", cfg.AssignedIP)
	}
}

// TestMalformedRoutesAreSkipped: one bad route should not cost a client its
// whole tunnel.
func TestMalformedRoutesAreSkipped(t *testing.T) {
	doc := `<response><access-routes><member>10.0.0.0/8</member>` +
		`<member>nonsense</member><member>192.168.0.0/16</member></access-routes></response>`
	cfg, err := ParseConfigXML([]byte(doc))
	if err != nil {
		t.Fatalf("ParseConfigXML: %v", err)
	}
	if len(cfg.Include) != 2 {
		t.Errorf("kept %d routes, want 2: %v", len(cfg.Include), cfg.Include)
	}
}

func TestRouteString(t *testing.T) {
	r := Route{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(8, 32)}
	if got := r.String(); got != "10.0.0.0/8" {
		t.Errorf("Route.String = %q", got)
	}
}
