package nebula

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"

	"github.com/xen0bit/veepin/internal/replay"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// testTunnelPair builds two tunnels keyed to each other: a's send key is b's
// recv key and vice versa, which is what makes a sealRelayTo on one openable
// by the other.
//
// Built by hand rather than through a handshake because the relay hop is a
// property of the tunnel crypto and not of how the keys were agreed, and a
// full handshake here would obscure which half is under test.
func testTunnelPair(tb testing.TB) (*tunnel, *tunnel) {
	tb.Helper()
	c := cipherAESGCM

	var ab, ba [32]byte
	if _, err := rand.Read(ab[:]); err != nil {
		tb.Fatal(err)
	}
	if _, err := rand.Read(ba[:]); err != nil {
		tb.Fatal(err)
	}

	mk := func(send, recv [32]byte, remoteIndex uint32) *tunnel {
		s, err := c.aead(send[:])
		if err != nil {
			tb.Fatal(err)
		}
		r, err := c.aead(recv[:])
		if err != nil {
			tb.Fatal(err)
		}
		return &tunnel{cipher: c, send: s, recv: r, remoteIndex: remoteIndex, window: replay.New()}
	}
	return mk(ab, ba, 1), mk(ba, ab, 2)
}

// TestControlRoundTrip checks the NebulaControl codec against itself for every
// field, which is necessary and not sufficient -- the field numbers are what
// interoperability rests on and only the interop cell can check those.
func TestControlRoundTrip(t *testing.T) {
	want := controlMessage{
		Type:                controlCreateRelayRequest,
		InitiatorRelayIndex: 0xdeadbeef,
		ResponderRelayIndex: 0x01020304,
		RelayToAddr:         addr("10.42.0.9"),
		RelayFromAddr:       addr("10.42.0.3"),
	}
	got, err := parseControl(want.marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

// TestControlFieldNumbersMatchTheReference pins the wire tags. They are the
// only thing in this file that a peer can disagree with us about, and getting
// one wrong produces a message the reference silently skips as an unknown
// field -- so the relay is never set up and nothing says why.
func TestControlFieldNumbersMatchTheReference(t *testing.T) {
	m := controlMessage{
		Type:                controlCreateRelayResponse,
		InitiatorRelayIndex: 1,
		ResponderRelayIndex: 2,
		RelayToAddr:         addr("10.42.0.9"),
		RelayFromAddr:       addr("10.42.0.3"),
	}
	wire := m.marshal()

	// Field 1 varint = tag 0x08, field 2 varint = 0x10, field 3 varint = 0x18,
	// field 6 bytes = 0x32, field 7 bytes = 0x3a.
	for _, tag := range []byte{0x08, 0x10, 0x18, 0x32, 0x3a} {
		if !bytes.Contains(wire, []byte{tag}) {
			t.Errorf("tag %#x absent from the encoding; a field number moved", tag)
		}
	}
}

// TestControlRejectsMessagesMissingAnAddress: an entry built from an invalid
// address would be filed under the zero address and never found again, so the
// parse refuses rather than the table absorbing it.
func TestControlRejectsMessagesMissingAnAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    controlMessage
	}{
		{"no from", controlMessage{Type: controlCreateRelayRequest, RelayToAddr: addr("10.42.0.9")}},
		{"no to", controlMessage{Type: controlCreateRelayRequest, RelayFromAddr: addr("10.42.0.3")}},
		{"neither", controlMessage{Type: controlCreateRelayResponse}},
	} {
		if _, err := parseControl(tc.m.marshal()); err == nil {
			t.Errorf("%s: parsed without error", tc.name)
		}
	}
}

// TestControlRejectsUnknownTypes stops a None or a future type from being
// treated as a request.
func TestControlRejectsUnknownTypes(t *testing.T) {
	m := controlMessage{RelayToAddr: addr("10.42.0.9"), RelayFromAddr: addr("10.42.0.3")}
	if _, err := parseControl(m.marshal()); !errors.Is(err, errBadControlType) {
		t.Errorf("err = %v, want errBadControlType", err)
	}
}

// TestControlRejectsEveryTruncation is the house rule for a codec.
func TestControlRejectsEveryTruncation(t *testing.T) {
	whole := controlMessage{
		Type:                controlCreateRelayRequest,
		InitiatorRelayIndex: 0xdeadbeef,
		RelayToAddr:         addr("10.42.0.9"),
		RelayFromAddr:       addr("10.42.0.3"),
	}.marshal()

	for n := range len(whole) {
		if _, err := parseControl(whole[:n]); err == nil {
			t.Errorf("prefix of %d octets parsed as a whole message", n)
		}
	}
}

// TestMirrorIsTheOppositeDirection is the middle host's whole job, and the
// place the two addresses are easiest to transpose. A relay whose mirror
// lookup used the same key in both directions would forward every packet
// straight back to its sender -- which, over a working tunnel, looks like the
// far end never replying rather than like a loop.
func TestMirrorIsTheOppositeDirection(t *testing.T) {
	a, b := addr("10.42.0.3"), addr("10.42.0.9")
	rt := newRelayTable()

	fromA := &relay{localIndex: 1, neighbour: a, peerAddr: b, typ: relayForwarding, state: relayEstablished}
	fromB := &relay{localIndex: 2, neighbour: b, peerAddr: a, typ: relayForwarding, state: relayEstablished}
	rt.add(fromA)
	rt.add(fromB)

	got, ok := rt.mirror(fromA)
	if !ok {
		t.Fatal("no mirror for the A->B entry")
	}
	if got != fromB {
		t.Errorf("mirror of {from A, to B} = %+v, want the {from B, to A} entry", got)
	}
	// And symmetrically, which is what catches a lookup that happens to work
	// in one direction because both keys were transposed together.
	if got, ok := rt.mirror(fromB); !ok || got != fromA {
		t.Error("the mirror relation is not symmetric")
	}
}

// TestTerminalForIgnoresUnestablishedRelays: sending through a relay that has
// not answered yet addresses a remoteIndex of zero, which the far side has
// never issued, so every packet is dropped by a peer that looks healthy.
func TestTerminalForIgnoresUnestablishedRelays(t *testing.T) {
	rt := newRelayTable()
	rt.add(&relay{localIndex: 1, neighbour: addr("10.42.0.1"), peerAddr: addr("10.42.0.9"),
		typ: relayTerminal, state: relayRequested})

	if _, ok := rt.terminalFor(addr("10.42.0.9")); ok {
		t.Error("terminalFor returned a relay that has not been answered")
	}

	rt.add(&relay{localIndex: 2, neighbour: addr("10.42.0.2"), peerAddr: addr("10.42.0.9"),
		typ: relayTerminal, state: relayEstablished})
	if _, ok := rt.terminalFor(addr("10.42.0.9")); !ok {
		t.Error("terminalFor missed an established relay")
	}
}

// TestForwardingEntriesAreNotUsedAsTerminals. The middle host holds entries
// naming the same peers as the ends do; using one to send would wrap a packet
// for a host that expects to forward it.
func TestForwardingEntriesAreNotUsedAsTerminals(t *testing.T) {
	rt := newRelayTable()
	rt.add(&relay{localIndex: 1, neighbour: addr("10.42.0.3"), peerAddr: addr("10.42.0.9"),
		typ: relayForwarding, state: relayEstablished})

	if _, ok := rt.terminalFor(addr("10.42.0.9")); ok {
		t.Error("a forwarding entry was offered as a terminal one")
	}
}

// TestAddReplacesTheStaleIndex: a peer that reconnects renegotiates, and the
// old index must stop resolving or an arriving packet is authenticated against
// a tunnel that no longer carries it.
func TestAddReplacesTheStaleIndex(t *testing.T) {
	rt := newRelayTable()
	via, peer := addr("10.42.0.1"), addr("10.42.0.9")
	rt.add(&relay{localIndex: 11, neighbour: via, peerAddr: peer, typ: relayTerminal})
	rt.add(&relay{localIndex: 22, neighbour: via, peerAddr: peer, typ: relayTerminal})

	if _, ok := rt.byLocalIndex(11); ok {
		t.Error("the replaced entry's index still resolves")
	}
	if _, ok := rt.byLocalIndex(22); !ok {
		t.Error("the new entry's index does not resolve")
	}
}

// TestRelaySealIsAuthenticatedButNotEncrypted is the property the whole design
// turns on, and the one most likely to be "fixed" by someone who reads
// sealRelayTo and assumes a missing Seal. The payload has to stay readable:
// the relay must parse the inner header to forward, and it holds no key that
// would let it decrypt one.
func TestRelaySealIsAuthenticatedButNotEncrypted(t *testing.T) {
	a, b := testTunnelPair(t)

	payload := []byte("the inner nebula packet, header and all")
	sealed := a.sealRelayTo(0x11223344, payload)

	if !bytes.Contains(sealed, payload) {
		t.Fatal("the payload was encrypted; a relay could not read the inner header")
	}
	if got := sealed[headerLen : len(sealed)-tagSize]; !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}

	h, out, err := b.openRelay(sealed)
	if err != nil {
		t.Fatalf("openRelay: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Errorf("openRelay returned %q, want %q", out, payload)
	}
	if h.Subtype != subTypeRelay {
		t.Errorf("subtype = %d, want subTypeRelay", h.Subtype)
	}
	if h.RemoteIndex != 0x11223344 {
		t.Errorf("index = %#x, want the relay index rather than the tunnel's", h.RemoteIndex)
	}
}

// TestRelaySealAuthenticatesTheHeaderAndPayload: not encrypting is not the
// same as not protecting. A relay that accepted a tampered inner header would
// forward wherever an attacker pointed it.
func TestRelaySealAuthenticatesTheHeaderAndPayload(t *testing.T) {
	a, b := testTunnelPair(t)
	sealed := a.sealRelayTo(7, []byte("payload"))

	for _, tc := range []struct {
		name string
		at   int
	}{
		{"header", 2},
		{"relay index", 8},
		{"payload", headerLen + 1},
		{"tag", len(sealed) - 1},
	} {
		bad := append([]byte(nil), sealed...)
		bad[tc.at] ^= 0x01
		if _, _, err := b.openRelay(bad); err == nil {
			t.Errorf("a flipped bit in the %s was accepted", tc.name)
		}
	}
}

// TestRelayReplayIsRejected: the relay hop has its own counter and window, and
// without one a recorded relayed packet could be re-injected forever.
func TestRelayReplayIsRejected(t *testing.T) {
	a, b := testTunnelPair(t)
	sealed := a.sealRelayTo(7, []byte("payload"))

	if _, _, err := b.openRelay(sealed); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if _, _, err := b.openRelay(sealed); !errors.Is(err, errReplayed) {
		t.Errorf("replay err = %v, want errReplayed", err)
	}
}

// TestForgetDropsEntriesInBothPositions. A relay entry names two hosts and a
// departing host may be either of them: the neighbour whose tunnel
// authenticates the hop, or the far end the path leads to. Dropping only the
// first leaves the middle host offering a route to somewhere that is gone.
func TestForgetDropsEntriesInBothPositions(t *testing.T) {
	via, gone, other := addr("10.42.0.1"), addr("10.42.0.9"), addr("10.42.0.5")
	rt := newRelayTable()

	rt.add(&relay{localIndex: 1, neighbour: via, peerAddr: gone, typ: relayTerminal})     // far end leaves
	rt.add(&relay{localIndex: 2, neighbour: gone, peerAddr: other, typ: relayForwarding}) // neighbour leaves
	rt.add(&relay{localIndex: 3, neighbour: via, peerAddr: other, typ: relayTerminal})    // untouched

	rt.forget(gone)

	for _, idx := range []uint32{1, 2} {
		if _, ok := rt.byLocalIndex(idx); ok {
			t.Errorf("index %d survived forget", idx)
		}
	}
	if _, ok := rt.byLocalIndex(3); !ok {
		t.Error("forget removed an entry that named neither departing host")
	}
	if _, ok := rt.lookup(via, other); !ok {
		t.Error("forget removed the surviving entry's peer key")
	}
}
