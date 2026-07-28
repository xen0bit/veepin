package ikev1

import (
	"bytes"
	"net"
	"testing"
)

func TestCfgPayloadRoundTrip(t *testing.T) {
	want := cfgPayload{
		typ:        cfgReply,
		identifier: 0xbeef,
		attrs: []attr{
			basicAttr(xauthStatus, xauthStatusOK),
			varAttr(cfgAttrIP4Address, []byte{10, 60, 0, 7}),
			varAttr(unityBanner, []byte("hello")),
		},
	}
	got, err := parseCfg(buildCfg(want))
	if err != nil {
		t.Fatal(err)
	}
	if got.typ != want.typ || got.identifier != want.identifier {
		t.Fatalf("header = {%d, %#x}, want {%d, %#x}", got.typ, got.identifier, want.typ, want.identifier)
	}
	if len(got.attrs) != len(want.attrs) {
		t.Fatalf("got %d attributes, want %d", len(got.attrs), len(want.attrs))
	}
	for i := range want.attrs {
		if got.attrs[i].typ != want.attrs[i].typ || !bytes.Equal(got.attrs[i].value, want.attrs[i].value) {
			t.Errorf("attribute %d = %+v, want %+v", i, got.attrs[i], want.attrs[i])
		}
	}
}

// TestParseCfgRejectsTruncated covers every prefix of a valid payload. Only two
// lengths may be accepted: the whole thing, and the bare header — an Attribute
// payload with no attributes is what a CFG_ACK legitimately looks like. Every
// length in between cuts an attribute in half and must be refused rather than
// read as a shorter value.
func TestParseCfgRejectsTruncated(t *testing.T) {
	full := buildCfg(cfgPayload{
		typ:        cfgRequest,
		identifier: 1,
		attrs:      []attr{varAttr(cfgAttrIP4Address, []byte{10, 0, 0, 1})},
	})
	for i := range len(full) {
		_, err := parseCfg(full[:i])
		if i == cfgHeaderLen {
			if err != nil {
				t.Errorf("a header with no attributes was rejected: %v", err)
			}
			continue
		}
		if err == nil {
			t.Errorf("prefix of %d octets was accepted", i)
		}
	}
	if _, err := parseCfg(full); err != nil {
		t.Fatalf("the whole payload was rejected: %v", err)
	}
}

func TestCfgReplyRoundTrip(t *testing.T) {
	_, splitA, _ := net.ParseCIDR("10.1.0.0/16")
	_, splitB, _ := net.ParseCIDR("192.168.5.0/24")
	want := ModeCfgReply{
		Address:      net.IPv4(10, 60, 0, 12).To4(),
		Netmask:      net.IP{255, 255, 255, 0},
		DNS:          []net.IP{net.IPv4(10, 60, 0, 1).To4(), net.IPv4(8, 8, 8, 8).To4()},
		NBNS:         []net.IP{net.IPv4(10, 60, 0, 2).To4()},
		Banner:       "authorised users only",
		Domain:       "corp.example",
		SplitInclude: []*net.IPNet{splitA, splitB},
	}
	got := parseCfgReply(cfgPayload{typ: cfgReply, attrs: cfgReplyAttrs(want)})

	if !got.Address.Equal(want.Address) {
		t.Errorf("address = %v, want %v", got.Address, want.Address)
	}
	if !net.IP(got.Netmask).Equal(net.IP(want.Netmask)) {
		t.Errorf("netmask = %v, want %v", got.Netmask, want.Netmask)
	}
	if len(got.DNS) != 2 || !got.DNS[0].Equal(want.DNS[0]) || !got.DNS[1].Equal(want.DNS[1]) {
		t.Errorf("dns = %v, want %v", got.DNS, want.DNS)
	}
	if len(got.NBNS) != 1 || !got.NBNS[0].Equal(want.NBNS[0]) {
		t.Errorf("nbns = %v", got.NBNS)
	}
	if got.Banner != want.Banner || got.Domain != want.Domain {
		t.Errorf("banner/domain = %q/%q", got.Banner, got.Domain)
	}
	if got.AppVersion != appVersion {
		t.Errorf("app version = %q, want %q", got.AppVersion, appVersion)
	}
	if len(got.SplitInclude) != 2 {
		t.Fatalf("split-include = %v, want two networks", got.SplitInclude)
	}
	for i, w := range want.SplitInclude {
		if got.SplitInclude[i].String() != w.String() {
			t.Errorf("split-include %d = %s, want %s", i, got.SplitInclude[i], w)
		}
	}
}

// TestSplitIncludeEntryIsFixedWidth pins the wire size: Cisco's attribute is a
// network, a mask, and ten octets of protocol/port selector veepin leaves zero.
// A client sizes its parse on that, so a short entry is a wire change.
func TestSplitIncludeEntryIsFixedWidth(t *testing.T) {
	_, n, _ := net.ParseCIDR("172.16.0.0/12")
	v := encodeSplitInclude(n)
	if len(v) != splitIncludeLen {
		t.Fatalf("entry is %d octets, want %d", len(v), splitIncludeLen)
	}
	if !bytes.Equal(v[0:4], []byte{172, 16, 0, 0}) || !bytes.Equal(v[4:8], []byte{255, 240, 0, 0}) {
		t.Errorf("entry = %x", v)
	}
	for i, b := range v[8:] {
		if b != 0 {
			t.Errorf("selector octet %d = %#x, want zero", i, b)
		}
	}
}

// TestEncodeSplitIncludeSkipsWhatItCannotSay: an IPv6 network has no
// representation in a Cisco Unity attribute, so it must be dropped rather than
// truncated into a wrong IPv4 one.
func TestEncodeSplitIncludeSkipsWhatItCannotSay(t *testing.T) {
	_, v6, _ := net.ParseCIDR("2001:db8::/32")
	if got := encodeSplitInclude(v6); got != nil {
		t.Errorf("an IPv6 network encoded as %x", got)
	}
	if got := encodeSplitInclude(nil); got != nil {
		t.Errorf("nil encoded as %x", got)
	}
}

func TestParseSplitIncludeRejectsShortEntries(t *testing.T) {
	for i := range 8 {
		if got := parseSplitInclude(make([]byte, i)); got != nil {
			t.Errorf("%d octets parsed as %s", i, got)
		}
	}
}

// TestCfgReplyOmitsWhatWasNotAssigned: an empty attribute reads as a zero value
// to some clients and as "absent" to others, so a reply says only what it means.
func TestCfgReplyOmitsWhatWasNotAssigned(t *testing.T) {
	attrs := cfgReplyAttrs(ModeCfgReply{Address: net.IPv4(10, 0, 0, 5).To4()})
	for _, a := range attrs {
		switch a.typ {
		case cfgAttrIP4Netmask, cfgAttrIP4DNS, cfgAttrIP4NBNS, unityBanner, unityDefDomain, unitySplitInclude:
			t.Errorf("attribute %d was sent for an assignment that carried none", a.typ)
		}
	}
}
