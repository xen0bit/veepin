package l2tpv3

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// TestControlHeaderIsTwelveOctetsWithA32BitCCID pins the v3 control layout
// against the v2 one it is easy to carry over. v2 has a 16-bit tunnel ID and a
// 16-bit session ID where v3 has one 32-bit Control Connection ID, and v3
// control messages carry no session ID at all.
func TestControlHeaderIsTwelveOctetsWithA32BitCCID(t *testing.T) {
	pkt := AppendControl(nil, 0xdeadbeef, 7, 9, msgHello, nil)

	if got := binary.BigEndian.Uint16(pkt[0:]); got != flagsVerControl {
		t.Errorf("flags/ver = %#04x, want %#04x (T=1, L=1, S=1, Ver=3)", got, flagsVerControl)
	}
	if got := int(binary.BigEndian.Uint16(pkt[2:])); got != len(pkt) {
		t.Errorf("Length field = %d, want %d (the whole message)", got, len(pkt))
	}
	if got := binary.BigEndian.Uint32(pkt[4:]); got != 0xdeadbeef {
		t.Errorf("CCID = %#08x, want 0xdeadbeef; it is one 32-bit field at offset 4", got)
	}
	if got := binary.BigEndian.Uint16(pkt[8:]); got != 7 {
		t.Errorf("Ns = %d, want 7", got)
	}
	if got := binary.BigEndian.Uint16(pkt[10:]); got != 9 {
		t.Errorf("Nr = %d, want 9", got)
	}
	if controlHeaderLen != 12 {
		t.Errorf("controlHeaderLen = %d, want 12", controlHeaderLen)
	}
}

// TestAckIsAnExplicitMessageNotAnEmptyBody is the v2-to-v3 trap.
//
// v2 acknowledges with a Zero-Length Body: a bare header and no AVPs. v3 does
// not -- it sends a real message carrying Message-Type = 20. A peer sent a bare
// v3 header sees a malformed message, not an ack, and never clears its
// retransmit queue.
func TestAckIsAnExplicitMessageNotAnEmptyBody(t *testing.T) {
	pkt := AppendControl(nil, 1, 0, 1, msgAck, nil)

	if len(pkt) <= controlHeaderLen {
		t.Fatalf("ACK is %d octets, i.e. a bare header; v3 requires a Message-Type AVP", len(pkt))
	}
	m, err := ParseControl(pkt)
	if err != nil {
		t.Fatalf("ParseControl: %v", err)
	}
	if m.Type != msgAck {
		t.Errorf("Type = %d, want %d (ACK)", m.Type, msgAck)
	}
	if msgAck != 20 {
		t.Errorf("msgAck = %d, want 20", msgAck)
	}
}

// TestControlRoundTrip: every field survives encode/decode.
func TestControlRoundTrip(t *testing.T) {
	for _, mt := range []uint16{msgHello, msgAck, msgStopCCN} {
		pkt := AppendControl(nil, 0x01020304, 42, 43, mt, nil)
		m, err := ParseControl(pkt)
		if err != nil {
			t.Fatalf("type %d: ParseControl: %v", mt, err)
		}
		if m.CCID != 0x01020304 || m.Ns != 42 || m.Nr != 43 || m.Type != mt {
			t.Errorf("type %d: got %+v", mt, m)
		}
	}
}

// TestControlRejectsEveryTruncation: no prefix of a valid message reads out of
// bounds.
func TestControlRejectsEveryTruncation(t *testing.T) {
	valid := AppendControl(nil, 1, 0, 0, msgHello, nil)
	for i := range len(valid) {
		if _, err := ParseControl(valid[:i]); err == nil {
			t.Fatalf("prefix of %d octets parsed without error", i)
		}
	}
}

// TestControlRejectsAHiddenAVP: an AVP with the H bit set is obfuscated with a
// shared secret we never configure. Parsing its value as plaintext would feed
// ciphertext to the state machine.
func TestControlRejectsAHiddenAVP(t *testing.T) {
	pkt := AppendControl(nil, 1, 0, 0, msgHello, nil)
	// Set the H bit on the Message-Type AVP, which starts at the header's end.
	pkt[controlHeaderLen] |= 0x40

	if _, err := ParseControl(pkt); !errors.Is(err, ErrControlHidden) {
		t.Fatalf("hidden AVP accepted (err=%v)", err)
	}
}

// TestControlRequiresALeadingMessageTypeAVP: RFC 3931 section 5.4.1 makes it
// mandatory and first, and the whole dispatch depends on it.
func TestControlRequiresALeadingMessageTypeAVP(t *testing.T) {
	bare := make([]byte, controlHeaderLen)
	binary.BigEndian.PutUint16(bare[0:], flagsVerControl)
	binary.BigEndian.PutUint16(bare[2:], controlHeaderLen)

	if _, err := ParseControl(bare); !errors.Is(err, ErrControlNoType) {
		t.Fatalf("a message with no AVPs parsed (err=%v); v3 has no zero-length body", err)
	}
}

// TestIsControlDistinguishesByTheTBitAlone: both layouts put a 32-bit
// identifier at offset 4 -- CCID for control, Session ID for data -- so nothing
// else in the packet separates them.
func TestIsControlDistinguishesByTheTBitAlone(t *testing.T) {
	ctl := AppendControl(nil, 0x64, 0, 0, msgHello, nil)
	data := EncodeData(nil, 0x64, nil, false,
		ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("x")))

	if !IsControl(ctl) {
		t.Error("a control message was not recognised as one")
	}
	if IsControl(data) {
		t.Error("a data packet was taken for a control message")
	}
	// Both carry their identifier in the same place, which is why the T bit has
	// to be the test.
	if binary.BigEndian.Uint32(ctl[4:]) != binary.BigEndian.Uint32(data[4:]) {
		t.Error("this test's premise is wrong: the identifiers are not at the same offset")
	}
}

// controlPair wires two ControlConns together, each delivering straight into
// the other. Cross-wired CCIDs, as the protocol requires.
func controlPair(t *testing.T, helloInterval time.Duration) (a, b *ControlConn, deadA, deadB *bool) {
	t.Helper()
	var mu sync.Mutex
	da, db := false, false

	addrA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1701}
	addrB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1701}

	var ca, cb *ControlConn
	ca = NewControlConn(ControlConfig{
		LocalCCID: 100, RemoteCCID: 200, HelloInterval: helloInterval, PeerAddr: addrB,
	}, func(pkt []byte, _ *net.UDPAddr) { cb.HandleControl(pkt, addrA) },
		func() { mu.Lock(); da = true; mu.Unlock() })

	cb = NewControlConn(ControlConfig{
		LocalCCID: 200, RemoteCCID: 100, HelloInterval: helloInterval, PeerAddr: addrA,
	}, func(pkt []byte, _ *net.UDPAddr) { ca.HandleControl(pkt, addrB) },
		func() { mu.Lock(); db = true; mu.Unlock() })

	return ca, cb, &da, &db
}

// TestHelloIsAcknowledged: a keepalive gets an ACK back and clears the
// retransmit slot.
func TestHelloIsAcknowledged(t *testing.T) {
	a, b, _, _ := controlPair(t, -1) // no automatic HELLOs; drive it by hand
	_ = b

	a.sendHello()

	a.mu.Lock()
	inFlight := a.inFlight
	ns := a.ns
	a.mu.Unlock()

	if inFlight != nil {
		t.Error("the HELLO was not acknowledged; its retransmit slot is still occupied")
	}
	if ns != 1 {
		t.Errorf("Ns = %d after one HELLO, want 1", ns)
	}
}

// TestAckDoesNotConsumeASequenceNumber is the rule that desynchronises a peer
// permanently when broken. HELLO occupies a sequence number; ACK does not
// (RFC 3931 section 4.2).
func TestAckDoesNotConsumeASequenceNumber(t *testing.T) {
	a, b, _, _ := controlPair(t, -1)

	// b answers a's HELLO with an ACK. a's Ns must advance by exactly one -- for
	// the HELLO -- and b's must not advance at all, because all b sent was an ack.
	a.sendHello()

	a.mu.Lock()
	aNs := a.ns
	a.mu.Unlock()
	b.mu.Lock()
	bNs := b.ns
	bNr := b.nr
	b.mu.Unlock()

	if aNs != 1 {
		t.Errorf("sender Ns = %d, want 1", aNs)
	}
	if bNs != 0 {
		t.Errorf("acknowledger Ns = %d, want 0; an ACK must not consume a sequence number", bNs)
	}
	if bNr != 1 {
		t.Errorf("acknowledger Nr = %d, want 1 (it received one sequenced message)", bNr)
	}
}

// TestControlIgnoresAForeignCCID: a message whose Control Connection ID is not
// the one we chose must not touch our sequence state.
func TestControlIgnoresAForeignCCID(t *testing.T) {
	a, _, _, _ := controlPair(t, -1)

	a.mu.Lock()
	before := a.nr
	a.mu.Unlock()

	// Addressed to a CCID we never handed out.
	stray := AppendControl(nil, 999, 0, 0, msgHello, nil)
	a.HandleControl(stray, nil)

	a.mu.Lock()
	after := a.nr
	a.mu.Unlock()

	if after != before {
		t.Errorf("Nr moved from %d to %d on a message for a foreign CCID", before, after)
	}
}

// TestStopCCNClosesTheConnection: the peer saying goodbye is reported once.
func TestStopCCNClosesTheConnection(t *testing.T) {
	a, _, deadA, _ := controlPair(t, -1)

	bye := AppendControl(nil, 100, 0, 0, msgStopCCN, nil)
	a.HandleControl(bye, nil)

	if !*deadA {
		t.Error("StopCCN did not close the control connection")
	}
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if !closed {
		t.Error("the connection is not marked closed after StopCCN")
	}
}

// TestRetransmittedHelloIsAckedAgain: a peer that missed our ACK resends its
// HELLO with the same Ns, and must get another ACK rather than silence.
func TestRetransmittedHelloIsAckedAgain(t *testing.T) {
	var acks int
	var mu sync.Mutex
	c := NewControlConn(ControlConfig{
		LocalCCID: 100, RemoteCCID: 200, HelloInterval: -1,
		PeerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1701},
	}, func(pkt []byte, _ *net.UDPAddr) {
		if m, err := ParseControl(pkt); err == nil && m.Type == msgAck {
			mu.Lock()
			acks++
			mu.Unlock()
		}
	}, nil)

	hello := AppendControl(nil, 100, 0, 0, msgHello, nil)
	c.HandleControl(hello, nil)
	c.HandleControl(hello, nil) // the peer never saw our first ACK

	mu.Lock()
	got := acks
	mu.Unlock()
	if got != 2 {
		t.Errorf("sent %d ACKs for two copies of the same HELLO, want 2; "+
			"a peer that lost an ACK retransmits and must be answered again", got)
	}
}

// TestAckCarriesTheNextSequenceNumber pins RFC 3931 section 3.1's rule for a
// message that consumes no sequence number: its Ns is the next sequence number
// the sender will use, not the last one it used.
//
// It exists because a real peer breaks on it, and the temptation when that
// happens is to make veepin wrong in order to make the peer happy. go-l2tp
// v0.1.8 -- the only open-source L2TPv3 control implementation, and therefore
// the only possible interop peer -- wedges its receive queue on an ACK whose Ns
// is ahead of its Nr: transport.go's msgIsInSequence and msgIsStale between them
// classify such a message as neither, so dequeueRxMessage never returns it, and
// a second bug on the line above (`m := xport.rxQueue[0]` inside a loop over i)
// means nothing behind it is ever processed either. See
// TestPendingQl2tpdKeepalive in tests/interop for the capture.
//
// Lowering our Ns would clear that peer and would misstate the next sequence
// number to every conforming one. This test is what makes that a deliberate
// decision rather than an accident.
func TestAckCarriesTheNextSequenceNumber(t *testing.T) {
	var sent [][]byte
	c := NewControlConn(ControlConfig{
		LocalCCID: 100, RemoteCCID: 200, HelloInterval: time.Hour,
		PeerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1701},
	}, func(pkt []byte, _ *net.UDPAddr) { sent = append(sent, append([]byte(nil), pkt...)) }, nil)

	// A peer HELLO at the sequence number we expect. The reply is an ACK.
	hello := AppendControl(nil, 100, 0, 0, msgHello, nil)
	c.HandleControl(hello, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1701})

	if len(sent) != 1 {
		t.Fatalf("a HELLO produced %d replies, want exactly one ACK", len(sent))
	}
	ack, err := ParseControl(sent[0])
	if err != nil {
		t.Fatalf("parsing our own ACK: %v", err)
	}
	if ack.Type != msgAck {
		t.Fatalf("reply type = %d, want ACK (%d)", ack.Type, msgAck)
	}
	if ack.Nr != 1 {
		t.Errorf("ACK Nr = %d, want 1: it must acknowledge the HELLO at Ns 0", ack.Nr)
	}
	// The claim. Our own Ns has not advanced -- an ACK consumes no sequence
	// number -- so the ACK carries the number our NEXT message will use.
	if ack.Ns != 0 {
		t.Errorf("ACK Ns = %d, want 0, the next sequence number we will send", ack.Ns)
	}

	// And sending an actual message next uses that same number, which is what
	// makes "the next sequence number" true rather than merely stated.
	c.sendHello()
	if len(sent) != 2 {
		t.Fatalf("SendHello produced %d datagrams in total, want 2", len(sent))
	}
	h, err := ParseControl(sent[1])
	if err != nil {
		t.Fatalf("parsing our HELLO: %v", err)
	}
	if h.Ns != ack.Ns {
		t.Errorf("the HELLO after the ACK used Ns %d, but the ACK announced %d", h.Ns, ack.Ns)
	}
}
