package fortinet

import (
	"net"
	"strings"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	cfg := Config{
		AssignedIP: net.IPv4(10, 40, 0, 2),
		DNS:        []net.IP{net.IPv4(1, 1, 1, 1), net.IPv4(8, 8, 8, 8)},
		Domain:     "corp.example",
		Include:    []Route{{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 0, 0, 0)}},
		Exclude:    []Route{{IP: net.IPv4(192, 168, 1, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}},
	}
	xmlBytes := BuildConfigXML(cfg)

	got, err := ParseConfigXML(xmlBytes)
	if err != nil {
		t.Fatalf("ParseConfigXML: %v\n%s", err, xmlBytes)
	}
	if !got.AssignedIP.Equal(cfg.AssignedIP) {
		t.Errorf("assigned = %v, want %v", got.AssignedIP, cfg.AssignedIP)
	}
	if len(got.DNS) != 2 || !got.DNS[0].Equal(cfg.DNS[0]) || !got.DNS[1].Equal(cfg.DNS[1]) {
		t.Errorf("DNS = %v, want %v", got.DNS, cfg.DNS)
	}
	if got.Domain != "corp.example" {
		t.Errorf("domain = %q, want corp.example", got.Domain)
	}
	if len(got.Include) != 1 || !got.Include[0].IP.Equal(net.IPv4(10, 0, 0, 0)) {
		t.Errorf("include = %v", got.Include)
	}
	if len(got.Exclude) != 1 || !got.Exclude[0].IP.Equal(net.IPv4(192, 168, 1, 0)) {
		t.Errorf("exclude = %v", got.Exclude)
	}
}

// A full-tunnel config omits split-tunnel-info, which is how the client is told
// to route everything rather than a subset.
func TestFullTunnelOmitsSplit(t *testing.T) {
	xmlBytes := BuildConfigXML(Config{AssignedIP: net.IPv4(10, 40, 0, 2)})
	if strings.Contains(string(xmlBytes), "split-tunnel-info") {
		t.Errorf("a full-tunnel config should omit split-tunnel-info:\n%s", xmlBytes)
	}
	cfg, err := ParseConfigXML(xmlBytes)
	if err != nil || len(cfg.Include) != 0 {
		t.Errorf("parsed include = %v (%v), want none", cfg.Include, err)
	}
}

// The client must survive a config carrying tags it does not model, because
// FortiOS versions add fields freely.
func TestParseIgnoresUnknownTags(t *testing.T) {
	doc := `<?xml version="1.0"?><sslvpn-tunnel ver="9" some-new-attr="x">
	  <ipv4><assigned-addr ipv4="172.16.1.9"/><dns ip="9.9.9.9"/></ipv4>
	  <fips-mode>0</fips-mode><an-unknown-block><nested/></an-unknown-block>
	</sslvpn-tunnel>`
	cfg, err := ParseConfigXML([]byte(doc))
	if err != nil {
		t.Fatalf("rejected a config with unknown tags: %v", err)
	}
	if !cfg.AssignedIP.Equal(net.IPv4(172, 16, 1, 9)) {
		t.Errorf("assigned = %v, want 172.16.1.9", cfg.AssignedIP)
	}
}
