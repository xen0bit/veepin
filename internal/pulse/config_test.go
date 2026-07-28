package pulse

import (
	"encoding/binary"
	"net"
	"testing"
)

func sampleConfig() Config {
	_, inc, _ := net.ParseCIDR("10.0.0.0/8")
	_, exc, _ := net.ParseCIDR("192.168.5.0/24")
	return Config{
		Address:       net.IPv4(10, 70, 0, 12).To4(),
		Netmask:       net.IPv4(255, 255, 255, 0).To4(),
		DNS:           []net.IP{net.IPv4(10, 70, 0, 1).To4(), net.IPv4(8, 8, 8, 8).To4()},
		WINS:          []net.IP{net.IPv4(10, 70, 0, 2).To4()},
		MTU:           1400,
		Domain:        "corp.example",
		Gateway:       net.IPv4(10, 70, 0, 1).To4(),
		Routes:        []Route{{Net: inc}, {Net: exc, Exclude: true}},
		ESPPort:       4500,
		ESPEncryption: EncAES256CBC,
		ESPHMAC:       HMACSHA256,
		ESPLifeSecs:   1200,
		ESPLifeBytes:  0,
		ESPReplay:     1,
		ESPFallback:   15,
	}
}

func TestConfigRoundTrip(t *testing.T) {
	want := sampleConfig()
	got, err := ParseConfig(BuildConfig(want))
	if err != nil {
		t.Fatal(err)
	}

	if !got.Address.Equal(want.Address) || !got.Netmask.Equal(want.Netmask) {
		t.Errorf("address/netmask = %v/%v", got.Address, got.Netmask)
	}
	if len(got.DNS) != 2 || !got.DNS[0].Equal(want.DNS[0]) || !got.DNS[1].Equal(want.DNS[1]) {
		t.Errorf("dns = %v", got.DNS)
	}
	if len(got.WINS) != 1 || !got.WINS[0].Equal(want.WINS[0]) {
		t.Errorf("wins = %v", got.WINS)
	}
	if got.MTU != want.MTU || got.Domain != want.Domain {
		t.Errorf("mtu/domain = %d/%q", got.MTU, got.Domain)
	}
	if !got.Gateway.Equal(want.Gateway) {
		t.Errorf("gateway = %v", got.Gateway)
	}
	if got.ESPPort != want.ESPPort || got.ESPEncryption != want.ESPEncryption || got.ESPHMAC != want.ESPHMAC {
		t.Errorf("esp = port %d enc %#x hmac %#x", got.ESPPort, got.ESPEncryption, got.ESPHMAC)
	}
	if got.ESPLifeSecs != want.ESPLifeSecs || got.ESPReplay != want.ESPReplay || got.ESPFallback != want.ESPFallback {
		t.Errorf("esp lifetimes = %+v", got)
	}

	if len(got.Routes) != 2 {
		t.Fatalf("routes = %v", got.Routes)
	}
	if got.Routes[0].Net.String() != "10.0.0.0/8" || got.Routes[0].Exclude {
		t.Errorf("include route = %v (exclude=%v)", got.Routes[0].Net, got.Routes[0].Exclude)
	}
	if got.Routes[1].Net.String() != "192.168.5.0/24" || !got.Routes[1].Exclude {
		t.Errorf("exclude route = %v (exclude=%v)", got.Routes[1].Net, got.Routes[1].Exclude)
	}
}

// TestConfigMatchesTheCrossChecks pins the four length relationships
// openconnect verifies before it will look at a configuration packet at all.
// They are stated here in the same terms, so a change to the builder that broke
// one would fail here rather than in Docker.
func TestConfigMatchesTheCrossChecks(t *testing.T) {
	c := sampleConfig()
	p := BuildConfig(c)
	msg := EncodeMessage(VendorJuniper, TypeConfig, 1, p)
	total := len(msg)

	// Payload length at 0x28 of the message == total - 0x10.
	if got := binary.BigEndian.Uint32(msg[0x28:]); int(got) != total-0x10 {
		t.Errorf("payload length = %#x, want %#x", got, total-0x10)
	}
	// Offsets 0x10, 0x14, 0x18, 0x1c and 0x24 of the message must be zero.
	for _, off := range []int{0x10, 0x14, 0x18, 0x1c, 0x24} {
		if got := binary.BigEndian.Uint32(msg[off:]); got != 0 {
			t.Errorf("offset %#x = %#x, want zero", off, got)
		}
	}
	// The signature sits at 0x20 of the message.
	if got := binary.BigEndian.Uint32(msg[0x20:]); got != SigConfig {
		t.Errorf("signature = %#x, want %#x", got, SigConfig)
	}
	// The routing block: marker, then a length that is count*0x10+8.
	if got := binary.BigEndian.Uint16(msg[0x2c:]); got != 0x2e00 {
		t.Errorf("routing marker = %#04x", got)
	}
	routesLen := int(binary.BigEndian.Uint16(msg[0x2e:]))
	count := int(msg[0x30])
	if routesLen != count*routeEntryLen+8 {
		t.Errorf("routing length %d disagrees with %d routes", routesLen, count)
	}
	// The attribute block that follows must run exactly to the end.
	if got := binary.BigEndian.Uint32(msg[0x2c+routesLen:]); int(got)+routesLen+0x2c != total {
		t.Errorf("attribute block length %#x does not reach the end of a %#x-octet packet", got, total)
	}
}

func TestParseConfigRejectsGarbage(t *testing.T) {
	full := BuildConfig(sampleConfig())
	for i := range len(full) {
		if _, err := ParseConfig(full[:i]); err == nil {
			t.Errorf("prefix of %d octets was accepted", i)
		}
	}

	bad := append([]byte(nil), full...)
	binary.BigEndian.PutUint32(bad[cfgSigOffset:], 0xdeadbeef)
	if _, err := ParseConfig(bad); err == nil {
		t.Error("a packet with the wrong signature was accepted")
	}

	// A route count that disagrees with the block length is the check that
	// stops a peer-supplied count from driving the walk past the buffer.
	bad = append([]byte(nil), full...)
	bad[0x20] = 0xff
	if _, err := ParseConfig(bad); err == nil {
		t.Error("a route count disagreeing with the block length was accepted")
	}
}

// TestRouteRangeEncoding pins the unusual part of the routing block: a network
// is carried as an inclusive address range, not as a prefix.
func TestRouteRangeEncoding(t *testing.T) {
	_, n, _ := net.ParseCIDR("10.0.0.0/18")
	first, last, ok := rangeOf(n)
	if !ok {
		t.Fatal("a /18 has no range")
	}
	if first.String() != "10.0.0.0" || last.String() != "10.0.63.255" {
		t.Fatalf("range = %s..%s, want 10.0.0.0..10.0.63.255", first, last)
	}
	if back := netOf(first, last); back.String() != "10.0.0.0/18" {
		t.Errorf("range round-tripped as %s", back)
	}
}

// TestRouteRangeSkipsWhatItCannotSay: an IPv6 network has no representation in
// this block, so it is dropped rather than truncated into a wrong IPv4 one.
func TestRouteRangeSkipsWhatItCannotSay(t *testing.T) {
	_, v6, _ := net.ParseCIDR("2001:db8::/32")
	if _, _, ok := rangeOf(v6); ok {
		t.Error("an IPv6 network produced an IPv4 range")
	}
	if _, _, ok := rangeOf(nil); ok {
		t.Error("a nil network produced a range")
	}
}

// TestConfigOmitsESPWhenThereIsNone: a server serving only the IF-T/TLS data
// path must not advertise a port, or a client will wait for datagrams that
// never come.
func TestConfigOmitsESPWhenThereIsNone(t *testing.T) {
	c := sampleConfig()
	c.ESPPort = 0
	got, err := ParseConfig(BuildConfig(c))
	if err != nil {
		t.Fatal(err)
	}
	if got.ESPPort != 0 || got.ESPEncryption != 0 || got.ESPHMAC != 0 {
		t.Errorf("ESP attributes were sent for a config with no ESP: %+v", got)
	}
}

// TestSearchDomainLosesItsTerminator: a real server NUL-terminates the search
// domain, and the terminator is not part of the name.
func TestSearchDomainLosesItsTerminator(t *testing.T) {
	attr := []byte{0, 0, 0, 8, 'e', 'x', '.', 'c', 'o', 'm', 0, 0}
	binary.BigEndian.PutUint16(attr[0:2], AttrSearchDomain)

	var c Config
	if err := parseAttrs(attr, &c); err != nil {
		t.Fatal(err)
	}
	if c.Domain != "ex.com" {
		t.Errorf("domain = %q, want %q", c.Domain, "ex.com")
	}
}
