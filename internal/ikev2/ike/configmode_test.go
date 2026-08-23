package ike

import (
	"io"
	"log"
	"net"
	"testing"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// TestACFGRequestNamingOneFamilyIsAnsweredWithOnlyThatFamily is written from
// the peer's point of view, because that is the only point of view from which
// this was ever visible.
//
// veepin's own client asks for both families, so every veepin<->veepin test and
// every strongSwan cell (strongSwan also asks for both) saw a dual-stack reply
// and agreed with it. libreswan asks only for INTERNAL_IP4_ADDRESS, accepted
// the IPv6 address it had not requested, built its child traffic selectors from
// it, and failed the Child SA with TS_UNACCEPTABLE against selectors it had
// itself proposed.
//
// If this fails, an IPv4-only initiator is being handed an IPv6 lease again --
// and with it a leaked pool6 address per client.
func TestACFGRequestNamingOneFamilyIsAnsweredWithOnlyThatFamily(t *testing.T) {
	for _, tc := range []struct {
		name             string
		request          []payload.CFGAttrType
		wantV4, wantV6   bool
		wantAsked4, ask6 bool
	}{
		{
			name:       "IPv4 only, as libreswan asks",
			request:    []payload.CFGAttrType{payload.CFGInternalIP4Address, payload.CFGInternalIP4DNS},
			wantV4:     true,
			wantAsked4: true,
		},
		{
			name:    "IPv6 only",
			request: []payload.CFGAttrType{payload.CFGInternalIP6Address},
			wantV6:  true,
			ask6:    true,
		},
		{
			name:       "both, as veepin and strongSwan ask",
			request:    []payload.CFGAttrType{payload.CFGInternalIP4Address, payload.CFGInternalIP6Address},
			wantV4:     true,
			wantV6:     true,
			wantAsked4: true,
			ask6:       true,
		},
		{
			// A CP payload naming no address type at all is still a request to
			// be given an address; IPv4 is what every peer this runs against
			// means by that.
			name:       "neither, which still means IPv4",
			request:    []payload.CFGAttrType{payload.CFGApplicationVersion},
			wantV4:     true,
			wantAsked4: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Built directly rather than through NewServer: this exercises the
			// CFG_REPLY builder alone, and NewServer binds UDP 500.
			var asked AddressRequest
			srv := &Server{
				log: log.New(io.Discard, "", 0),
				cfg: Config{
					AssignAddr: func(want AddressRequest) (Assignment, error) {
						asked = want
						a := Assignment{}
						if want.IP4 {
							a.IP4 = net.IPv4(10, 0, 0, 2)
							a.Netmask = net.IPv4(255, 255, 255, 0)
						}
						if want.IP6 {
							a.IP6 = net.ParseIP("fd00::2")
							a.Prefix6 = 64
						}
						return a, nil
					},
				},
			}

			attrs := make([]payload.CFGAttr, 0, len(tc.request))
			for _, typ := range tc.request {
				attrs = append(attrs, payload.CFGAttr{Type: typ})
			}
			body := payload.MarshalCP(payload.CPPayload{Type: payload.CFGRequest, Attrs: attrs})

			reply := srv.buildCPReply(&IKESA{}, &payload.RawPayload{Body: body})
			if reply == nil {
				t.Fatal("buildCPReply returned nothing for a well-formed CFG_REQUEST")
			}
			if asked.IP4 != tc.wantAsked4 || asked.IP6 != tc.ask6 {
				t.Errorf("AssignAddr asked for %+v, want IP4=%v IP6=%v", asked, tc.wantAsked4, tc.ask6)
			}
			gotV4 := hasCFGAttr(reply.Attrs, payload.CFGInternalIP4Address)
			gotV6 := hasCFGAttr(reply.Attrs, payload.CFGInternalIP6Address)
			if gotV4 != tc.wantV4 {
				t.Errorf("CFG_REPLY carried INTERNAL_IP4_ADDRESS=%v, want %v", gotV4, tc.wantV4)
			}
			if gotV6 != tc.wantV6 {
				t.Errorf("CFG_REPLY carried INTERNAL_IP6_ADDRESS=%v, want %v", gotV6, tc.wantV6)
			}
		})
	}
}

func hasCFGAttr(attrs []payload.CFGAttr, typ payload.CFGAttrType) bool {
	for _, a := range attrs {
		if a.Type == typ {
			return true
		}
	}
	return false
}

// TestTheRespondersTSiNamesTheAddressItAssignedAndNotWhatWasProposed is written
// from the initiator's point of view, because from the responder's the echo
// looks fine.
//
// RFC 7296 section 2.19's worked example is unambiguous: the initiator proposes
// 0.0.0.0-255.255.255.255 because it does not yet know its address, and the
// responder answers with the address it just leased. veepin echoed the proposal
// instead. strongSwan tolerates that (its placeholder contains the lease, so its
// own narrowing still overlaps) and veepin's client never looked at TSi at all,
// so both halves agreed. libreswan's placeholder is its OUTER address, which
// overlaps nothing, and it answers TS_UNACCEPTABLE.
func TestTheRespondersTSiNamesTheAddressItAssignedAndNotWhatWasProposed(t *testing.T) {
	v4 := func(a, b net.IP) payload.TrafficSelector {
		return payload.TrafficSelector{
			Type: payload.TSIPv4AddrRange, IPProtocol: payload.IPProtoAny,
			StartPort: 0, EndPort: 65535, StartAddr: a, EndAddr: b,
		}
	}
	v6 := func(a, b net.IP) payload.TrafficSelector {
		return payload.TrafficSelector{
			Type: payload.TSIPv6AddrRange, IPProtocol: payload.IPProtoAny,
			StartPort: 0, EndPort: 65535, StartAddr: a, EndAddr: b,
		}
	}
	lease4 := net.IPv4(10, 10, 10, 4).To4()
	lease6 := net.ParseIP("fd00:10:10::4")
	allV4 := v4(net.IPv4zero.To4(), net.IP{255, 255, 255, 255})
	allV6 := v6(net.IPv6zero, net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))

	for _, tc := range []struct {
		name     string
		proposed []payload.TrafficSelector
		sa       *IKESA
		want     []payload.TrafficSelector
		changed  bool
	}{
		{
			name:     "libreswan proposes its own outer address, which overlaps nothing",
			proposed: []payload.TrafficSelector{v4(net.IPv4(172, 21, 0, 3).To4(), net.IPv4(172, 21, 0, 3).To4())},
			sa:       &IKESA{ClientIP: lease4},
			want:     []payload.TrafficSelector{v4(lease4, lease4)},
			changed:  true,
		},
		{
			name:     "strongSwan proposes everything, which is not an answer either",
			proposed: []payload.TrafficSelector{allV4},
			sa:       &IKESA{ClientIP: lease4},
			want:     []payload.TrafficSelector{v4(lease4, lease4)},
			changed:  true,
		},
		{
			name:     "dual-stack narrows both families",
			proposed: []payload.TrafficSelector{allV4, allV6},
			sa:       &IKESA{ClientIP: lease4, ClientIP6: lease6},
			want:     []payload.TrafficSelector{v4(lease4, lease4), v6(lease6, lease6)},
			changed:  true,
		},
		{
			// A family we leased nothing for keeps what was proposed: dropping
			// it would narrow a dual-stack request to half a tunnel.
			name:     "a family with no lease is left alone",
			proposed: []payload.TrafficSelector{allV4, allV6},
			sa:       &IKESA{ClientIP: lease4},
			want:     []payload.TrafficSelector{v4(lease4, lease4), allV6},
			changed:  true,
		},
		{
			// No config mode at all (a site-to-site style peer): the selectors
			// the initiator proposed are the negotiation, and rewriting them
			// would break it.
			name:     "no assignment leaves the proposal untouched",
			proposed: []payload.TrafficSelector{v4(net.IPv4(192, 0, 2, 0).To4(), net.IPv4(192, 0, 2, 255).To4())},
			sa:       &IKESA{},
			want:     []payload.TrafficSelector{v4(net.IPv4(192, 0, 2, 0).To4(), net.IPv4(192, 0, 2, 255).To4())},
			changed:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := narrowTSiToAssignment(payload.TSPayload{Selectors: tc.proposed}, tc.sa)
			if changed != tc.changed {
				t.Errorf("narrowed = %v, want %v", changed, tc.changed)
			}
			if len(got.Selectors) != len(tc.want) {
				t.Fatalf("got %d selectors, want %d: %+v", len(got.Selectors), len(tc.want), got.Selectors)
			}
			for i, sel := range got.Selectors {
				w := tc.want[i]
				if sel.Type != w.Type || !sel.StartAddr.Equal(w.StartAddr) || !sel.EndAddr.Equal(w.EndAddr) ||
					sel.IPProtocol != w.IPProtocol || sel.StartPort != w.StartPort || sel.EndPort != w.EndPort {
					t.Errorf("selector %d = %+v, want %+v", i, sel, w)
				}
			}
		})
	}
}
