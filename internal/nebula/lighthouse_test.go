package nebula

import (
	"net/netip"
	"testing"

	"github.com/xen0bit/veepin/internal/vlog"
)

// TestOnlyALighthouseMayAnswerAHostQuery: a member that is not a lighthouse
// telling this host where some third host is could put itself on the path
// between them. If this fails, any mesh member can redirect any other's
// traffic.
func TestOnlyALighthouseMayAnswerAHostQuery(t *testing.T) {
	lh := netip.MustParseAddr("10.42.0.1")
	h := &Host{lighthouses: []netip.Addr{lh}, byAddr: map[netip.Addr]*peer{}, log: vlog.Discard()}
	if !h.isLighthouse(lh) {
		t.Fatal("the configured lighthouse is not recognised")
	}
	if h.isLighthouse(netip.MustParseAddr("10.42.0.66")) {
		t.Fatal("an ordinary member is treated as a lighthouse")
	}
}

// TestALighthouseAnswerDoesNotMoveALiveTunnel: a live tunnel's address is the
// one its authenticated traffic came from. If this fails, one answer moves a
// working tunnel somewhere else.
func TestALighthouseAnswerDoesNotMoveALiveTunnel(t *testing.T) {
	target := netip.MustParseAddr("10.42.0.7")
	real := netip.MustParseAddrPort("192.0.2.7:4242")
	other := netip.MustParseAddrPort("198.51.100.66:4242")
	h := &Host{byAddr: map[netip.Addr]*peer{}, log: vlog.Discard()}
	p := h.peerFor(target)
	p.underlay = []netip.AddrPort{real}
	p.tun = &tunnel{}

	h.learnAddresses(metaMessage{Type: metaHostQueryReply, VpnAddr: target, AddrPorts: []netip.AddrPort{other}})
	if p.underlay[0] != real {
		t.Fatalf("the live tunnel now sends to %v", p.underlay[0])
	}
}
