package ike

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/aggfrag"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// The USE_AGGFRAG negotiation had no test at all, on either side, which is how
// veepin sent the notify with an empty body for as long as AGGFRAG existed in
// the tree. Two veepin ends agreed about it perfectly; strongSwan answers
// "invalid notify data length for USE_AGGFRAG (0)" and refuses the entire
// IKE_AUTH message, because notify_payload.c checks the length before it looks
// at anything else.
//
// These tests are written from the PEER's point of view rather than from the
// round trip's, which is the only thing that would have caught it: a round trip
// passes whatever both ends do, and what both ends did was wrong.

// startIPTFSServer is startTestServer with AGGFRAG permitted.
//
// The config is built before NewServer rather than being set on a running
// server, which is not fussiness: ListenAndServe's reader goroutine reads
// cfg.IPTFS on every IKE_AUTH, so writing it afterwards is a genuine race and
// the detector says so.
func startIPTFSServer(t *testing.T) (p500, p4500 int, srv *Server, childCh chan *ChildSA) {
	t.Helper()
	p500 = freeUDPPort(t)
	p4500 = freeUDPPort(t)
	childCh = make(chan *ChildSA, 4)

	srv, err := NewServer(Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		PSK:      []byte("test-psk"),
		LocalID:  FQDNIdentity("vpn.example"),
		PublicIP: net.ParseIP("127.0.0.1"),
		Logger:   log.New(io.Discard, "", 0),
		IPTFS:    true,
		AssignAddr: func(AddressRequest) (Assignment, error) {
			return Assignment{
				IP4:     net.IPv4(10, 8, 8, 8),
				Netmask: net.IPv4(255, 255, 255, 0),
			}, nil
		},
		OnChildSA: func(sa *IKESA, c *ChildSA) { childCh <- c },
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)
	return p500, p4500, srv, childCh
}

func iptfsClient(t *testing.T, p500, p4500 int) *Client {
	t.Helper()
	return NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("test-psk"),
		LocalID: FQDNIdentity("client.example"),
		IPTFS:   true,
		Logger:  log.New(io.Discard, "", 0),
	})
}

// TestUseAggFragNotifyCarriesOneOctetOfFlags is the assertion strongSwan makes
// and veepin did not. RFC 9347 section 6.1.4: "The notification payload
// contains 1 octet of requirement flags." An empty notify is not a notify with
// default flags — it is malformed, and it is refused before its meaning is
// considered.
func TestUseAggFragNotifyCarriesOneOctetOfFlags(t *testing.T) {
	c := NewClient(ClientConfig{
		PSK: []byte("x"), LocalID: FQDNIdentity("client.example"),
		IPTFS: true, Logger: log.New(io.Discard, "", 0),
	})
	b, _ := c.buildAuthInner(idPayloadBody(FQDNIdentity("client.example")), nil)

	n := findNotifyInBuilder(t, b, payload.UseAggFrag)
	if len(n.Data) != 1 {
		t.Fatalf("USE_AGGFRAG notify carries %d octets, want exactly 1 "+
			"(RFC 9347 §6.1.4; strongSwan refuses the whole IKE_AUTH otherwise)", len(n.Data))
	}
}

// TestUseAggFragRequiresNothingOfThePeer. The flags say what the SENDER
// requires, and veepin requires neither: it reassembles fragments, so
// forbidding them would cost the peer padding for nothing, and it does not
// implement sub-type 1, so asking for congestion control it could not act on
// would be worse than not asking.
func TestUseAggFragRequiresNothingOfThePeer(t *testing.T) {
	if aggfrag.OurFlags != 0 {
		t.Errorf("OurFlags = 0x%02x, want 0", byte(aggfrag.OurFlags))
	}
	if aggfrag.OurFlags.MustNotFragment() {
		t.Error("veepin forbids fragments it can reassemble")
	}
	if aggfrag.OurFlags.Unsupported() {
		t.Error("veepin requires of a peer something it does not implement itself")
	}
}

// TestAggFragIsNegotiatedEndToEnd walks both roles over a real socket: the
// client asks, the responder echoes, and both come out with AGGFRAG on.
func TestAggFragIsNegotiatedEndToEnd(t *testing.T) {
	p500, p4500, srv, childCh := startIPTFSServer(t)
	defer srv.Close()

	c := iptfsClient(t, p500, p4500)
	res, err := c.Connect()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	if !res.AggFrag {
		t.Error("the client did not come out with AGGFRAG enabled")
	}
	select {
	case child := <-childCh:
		if !child.AggFrag {
			t.Error("the responder did not come out with AGGFRAG enabled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never established a Child SA")
	}

	// And the tunnel it builds must be the AGGFRAG one, or the negotiation
	// agreed on a next-header nothing then sends.
	tun, err := res.BuildTunnel()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tun.(*aggfragTunnel); !ok {
		t.Errorf("BuildTunnel returned %T, want *aggfragTunnel", tun)
	}
}

// TestAResponderThatNeverAskedIsNotGivenAggFrag. The notify is an agreement
// only when both peers send it; echoing unconditionally would put next-header
// 144 on the wire against a client expecting plain inner IP, and every packet
// would be dropped as malformed.
func TestAResponderThatNeverAskedIsNotGivenAggFrag(t *testing.T) {
	p500, p4500, srv, childCh := startIPTFSServer(t)
	defer srv.Close()

	c := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("test-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
		// IPTFS deliberately unset.
	})
	res, err := c.Connect()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	if res.AggFrag {
		t.Error("the client enabled AGGFRAG without asking for it")
	}
	select {
	case child := <-childCh:
		if child.AggFrag {
			t.Error("the responder enabled AGGFRAG for a client that never asked")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never established a Child SA")
	}
}

// TestARequirementWeCannotMeetTurnsAggFragOffRatherThanFailing. RFC 9347 §5.1
// says a receiver that cannot support a requirement flag SHOULD NOT enable
// AGGFRAG — not that it should refuse the exchange. The Child SA is already
// established and carries plain inner IP perfectly well, so failing here would
// turn a negotiable option into a connection failure.
func TestARequirementWeCannotMeetTurnsAggFragOffRatherThanFailing(t *testing.T) {
	for name, flags := range map[string]aggfrag.Flags{
		"congestion control": aggfrag.FlagCongestionControl,
		"a reserved bit":     0x80,
	} {
		if !flags.Unsupported() {
			t.Errorf("%s: Unsupported() = false, want true", name)
		}
	}
	// Don't-Fragment is a requirement veepin CAN meet, so it must not be
	// mistaken for one it cannot: a peer that sets it still gets AGGFRAG.
	if aggfrag.FlagDontFragment.Unsupported() {
		t.Error("Don't Fragment reads as unsupported; veepin can honour it by not fragmenting")
	}
}

// TestAMalformedEchoDoesNotEnableAggFrag covers the direction veepin was
// broken in, from the other side: a peer that echoes an empty notify has sent
// something this cannot interpret, and guessing "no flags" would be exactly the
// assumption that let veepin send one.
func TestAMalformedEchoDoesNotEnableAggFrag(t *testing.T) {
	for _, data := range [][]byte{nil, {}, {0, 0}} {
		if _, err := aggfrag.ParseFlags(data); err == nil {
			t.Errorf("ParseFlags(%d octets) accepted a body that is not one octet", len(data))
		}
	}
}

// findNotifyInBuilder pulls one notify out of an assembled payload builder, by
// re-parsing the bytes it produced rather than by inspecting what went in. That
// is the point: the bug was in what reached the wire.
func findNotifyInBuilder(t *testing.T, b *payload.Builder, typ payload.NotifyType) payload.NotifyPayload {
	t.Helper()
	inners, err := parseInnerPayloads(b.FirstType(), b.Bytes())
	if err != nil {
		t.Fatalf("re-parsing the built payloads: %v", err)
	}
	n := findNotify(inners, typ)
	if n == nil {
		t.Fatalf("no notify of type %d in the IKE_AUTH inner payloads", typ)
	}
	return *n
}
