package aggfrag

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// ipv4 builds a well-formed IPv4 packet of n octets whose Total Length is
// correct, since that field is what tells a decoder where the block ends.
func ipv4(n int, fill byte) []byte {
	if n < 20 {
		panic("ipv4 packet shorter than its header")
	}
	p := make([]byte, n)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(n))
	p[9] = 17
	for i := 20; i < n; i++ {
		p[i] = fill
	}
	return p
}

func ipv6(payloadLen int, fill byte) []byte {
	p := make([]byte, 40+payloadLen)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], uint16(payloadLen))
	for i := 40; i < len(p); i++ {
		p[i] = fill
	}
	return p
}

// TestPackedPayloadIsAlwaysTheRequestedSize: the output length must not depend
// on the traffic offered. That independence is the entire security claim of
// IP-TFS -- a payload that shrank when there was less to send would leak the
// thing the format exists to hide.
func TestPackedPayloadIsAlwaysTheRequestedSize(t *testing.T) {
	const size = 1400
	cases := map[string][][]byte{
		"nothing":       nil,
		"one small":     {ipv4(64, 1)},
		"several small": {ipv4(64, 1), ipv4(100, 2), ipv4(48, 3)},
		"one oversized": {ipv4(3000, 4)},
		"exact fit":     {ipv4(size-HeaderLen, 5)},
	}
	for name, pkts := range cases {
		t.Run(name, func(t *testing.T) {
			p := NewPacker()
			out, _ := p.Pack(pkts, size)
			if len(out) != size {
				t.Errorf("payload is %d octets, want %d", len(out), size)
			}
		})
	}
}

// TestBlockOffsetNamesTheContinuation is the guard against the field being left
// at zero.
//
// A sender that prepends the tail of a split packet but writes BlockOffset=0 is
// telling the receiver the payload starts on a block boundary when it does not.
// Its own reassembler, if it ignores the field too, still reads the stream back
// perfectly -- and only a real peer notices. So this asserts the encoded octets
// directly rather than trusting a round trip.
func TestBlockOffsetNamesTheContinuation(t *testing.T) {
	const size = 200
	big := ipv4(500, 7) // will not fit in one payload

	p := NewPacker()
	first, rest := p.Pack([][]byte{big}, size)
	if len(rest) != 0 {
		t.Fatalf("the oversized packet was not consumed: %d left", len(rest))
	}
	if got := binary.BigEndian.Uint16(first[2:]); got != 0 {
		t.Errorf("first payload BlockOffset = %d, want 0 (it starts on a block boundary)", got)
	}
	if !p.Pending() {
		t.Fatal("Pending() = false after splitting a packet")
	}

	second, _ := p.Pack(nil, size)
	wantOffset := size - HeaderLen // the whole payload is continuation
	if got := binary.BigEndian.Uint16(second[2:]); int(got) != wantOffset {
		t.Errorf("second payload BlockOffset = %d, want %d; a continuation that "+
			"does not say how long it is cannot be reassembled by any peer", got, wantOffset)
	}
}

// TestFragmentedPacketReassembles: a packet split across several payloads comes
// back byte-identical.
func TestFragmentedPacketReassembles(t *testing.T) {
	const size = 200
	orig := ipv4(500, 0xab)

	p := NewPacker()
	r := NewReassembler()

	var got [][]byte
	pkts := [][]byte{orig}
	for range 5 {
		payload, rest := p.Pack(pkts, size)
		pkts = rest
		out, err := r.Feed(payload)
		if err != nil {
			t.Fatalf("Feed: %v", err)
		}
		for _, pkt := range out {
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			got = append(got, cp)
		}
	}

	if len(got) != 1 {
		t.Fatalf("reassembled %d packets, want 1", len(got))
	}
	if !bytes.Equal(got[0], orig) {
		t.Errorf("reassembled packet differs:\ngot  %x\nwant %x", got[0], orig)
	}
}

// TestAggregationRoundTrip: several small packets in one payload come back in
// order and unchanged.
func TestAggregationRoundTrip(t *testing.T) {
	want := [][]byte{ipv4(64, 1), ipv6(20, 2), ipv4(100, 3)}

	p := NewPacker()
	payload, rest := p.Pack(want, 1400)
	if len(rest) != 0 {
		t.Fatalf("%d packets did not fit in a 1400-octet payload", len(rest))
	}

	got, err := NewReassembler().Feed(payload)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d packets, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("packet %d:\ngot  %x\nwant %x", i, got[i], want[i])
		}
	}
}

// TestBlockTypeIsTheInnerIPVersion pins the coincidence RFC 9347 chose
// deliberately: a block's type nibble IS the inner packet's IP version, which
// is why a block needs no length field of its own. It looks like an accident
// and a tidy-up would "fix" it.
func TestBlockTypeIsTheInnerIPVersion(t *testing.T) {
	if BlockTypeIPv4 != 4 {
		t.Errorf("BlockTypeIPv4 = %d, want 4 (the IPv4 version nibble)", BlockTypeIPv4)
	}
	if BlockTypeIPv6 != 6 {
		t.Errorf("BlockTypeIPv6 = %d, want 6 (the IPv6 version nibble)", BlockTypeIPv6)
	}

	v4, v6 := ipv4(64, 1), ipv6(24, 2)
	if v4[0]>>4 != BlockTypeIPv4 {
		t.Error("an IPv4 packet's first nibble is not BlockTypeIPv4")
	}
	if v6[0]>>4 != BlockTypeIPv6 {
		t.Error("an IPv6 packet's first nibble is not BlockTypeIPv6")
	}
}

// TestPadBlockEndsThePayload: padding is not returned as a packet, and stops
// parsing where it starts.
func TestPadBlockEndsThePayload(t *testing.T) {
	p := NewPacker()
	payload, _ := p.Pack([][]byte{ipv4(64, 9)}, 1400)

	got, err := NewReassembler().Feed(payload)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d packets, want 1 -- padding must not decode as a packet", len(got))
	}
}

// TestRejectEveryTruncation: every prefix of a valid payload is either rejected
// or parsed without reading out of bounds.
func TestRejectEveryTruncation(t *testing.T) {
	p := NewPacker()
	payload, _ := p.Pack([][]byte{ipv4(64, 1), ipv4(80, 2)}, 400)

	for i := range len(payload) {
		// Must not panic; an error is fine and so is a short read.
		_, _ = NewReassembler().Feed(payload[:i])
	}
}

// TestHeaderRejectsAnOutOfRangeBlockOffset: a BlockOffset past the end of the
// payload would index out of bounds if trusted.
func TestHeaderRejectsAnOutOfRangeBlockOffset(t *testing.T) {
	payload := make([]byte, 40)
	binary.BigEndian.PutUint16(payload[2:], 1000) // far past the 36 data octets

	if _, err := NewReassembler().Feed(payload); !errors.Is(err, ErrBlockOffset) {
		t.Fatalf("out-of-range BlockOffset accepted (err=%v)", err)
	}
}

// TestSubTypeIsAWholeOctet guards the header layout. The sub-type occupies the
// first octet, not its high nibble; both encodings are identical for sub-type 0
// so only a test can hold the difference in place.
func TestSubTypeIsAWholeOctet(t *testing.T) {
	hdr := AppendHeader(nil, 0x1234)
	if len(hdr) != HeaderLen {
		t.Fatalf("header is %d octets, want %d", len(hdr), HeaderLen)
	}
	if hdr[0] != SubTypeNonCongestionControlled {
		t.Errorf("sub-type octet = %#x, want %#x", hdr[0], SubTypeNonCongestionControlled)
	}
	if hdr[1] != 0 {
		t.Errorf("reserved octet = %#x, want 0", hdr[1])
	}
	if got := binary.BigEndian.Uint16(hdr[2:]); got != 0x1234 {
		t.Errorf("BlockOffset = %#x, want 0x1234", got)
	}
}

// TestCongestionControlledSubTypeIsRejected: sub-type 1 has a 24-octet header,
// so parsing it as sub-type 0 would misread every field. Until it is
// implemented it must be refused, not guessed at.
func TestCongestionControlledSubTypeIsRejected(t *testing.T) {
	payload := make([]byte, 40)
	payload[0] = SubTypeCongestionControlled

	if _, err := NewReassembler().Feed(payload); !errors.Is(err, ErrSubType) {
		t.Fatalf("a congestion-controlled payload was parsed as sub-type 0 (err=%v)", err)
	}
}

// TestLostContinuationDoesNotSpliceUnrelatedHalves: if the payload carrying a
// fragment's tail is lost, the pending head must be discarded rather than
// joined to whatever arrives next.
func TestLostContinuationDoesNotSpliceUnrelatedHalves(t *testing.T) {
	const size = 200
	p := NewPacker()
	r := NewReassembler()

	// Split a large packet; feed only the first payload.
	first, _ := p.Pack([][]byte{ipv4(500, 0xcd)}, size)
	if _, err := r.Feed(first); err != nil {
		t.Fatalf("Feed(first): %v", err)
	}

	// Now a fresh payload that starts on a block boundary: the tail was lost.
	fresh, _ := NewPacker().Pack([][]byte{ipv4(64, 0xee)}, size)
	got, err := r.Feed(fresh)
	if err != nil {
		t.Fatalf("Feed(fresh): %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d packets, want exactly the 1 that arrived whole", len(got))
	}
	if len(got[0]) != 64 {
		t.Errorf("packet is %d octets, want 64 -- a lost fragment was spliced in", len(got[0]))
	}
}

// TestPackReusesItsBuffer: a steady send loop must not allocate a fresh payload
// per tick.
func TestPackReusesItsBuffer(t *testing.T) {
	p := NewPacker()
	pkts := [][]byte{ipv4(64, 1), ipv4(100, 2)}
	p.Pack(pkts, 1400) // prime the buffer so its growth is not counted

	if got := testing.AllocsPerRun(100, func() {
		p.Pack(pkts, 1400)
	}); got > 1 {
		t.Errorf("Pack allocated %v times per payload, want at most 1 (the pad)", got)
	}
}

// TestPackDoesNotBorrowAPacketItReportedAsConsumed is an ownership claim, and
// the reason it is worth a test of its own is that violating it is invisible to
// every other test here: pack then unpack, with nothing touching the input in
// between, agrees with itself perfectly.
//
// A split packet is dropped from the returned remaining list, which tells the
// caller it is finished with the buffer. internal/ikev2/ike's constant-rate
// sender takes that at its word and recycles it onto a free list that Enqueue
// draws from, so the next inner packet is written over a tail Pack has not sent
// yet. On the wire that is a corrupted continuation and a packet the receiver
// drops -- once per fragmentation, which at a fixed payload size is most
// packets.
func TestPackDoesNotBorrowAPacketItReportedAsConsumed(t *testing.T) {
	const size = HeaderLen + 16
	p := NewPacker()

	pkt := bytes.Repeat([]byte{0xAA}, 24)
	_, remaining := p.Pack([][]byte{pkt}, size)
	if len(remaining) != 0 {
		t.Fatalf("got %d packets back, want 0: a split packet is reported as consumed", len(remaining))
	}
	if !p.Pending() {
		t.Fatal("Pending is false after a split, so nothing carried the 8-octet tail")
	}

	// The caller was told it was done with pkt, so it recycles it.
	for i := range pkt {
		pkt[i] = 0xBB
	}

	payload, _ := p.Pack(nil, size)
	hdr, err := ParseHeader(payload)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if hdr.BlockOffset != 8 {
		t.Fatalf("BlockOffset is %d, want 8", hdr.BlockOffset)
	}
	if got := payload[HeaderLen : HeaderLen+8]; !bytes.Equal(got, bytes.Repeat([]byte{0xAA}, 8)) {
		t.Errorf("continuation is %#x, want the original 0xAA tail -- the Packer "+
			"aliased a buffer it had told the caller it was finished with", got)
	}
}

// TestPackCarriesATailWithoutAllocating: the fix above must not cost an
// allocation per fragmented packet, which on a constant-rate tunnel would be
// one per payload -- the exact path TestPackReusesItsBuffer exists to protect.
func TestPackCarriesATailWithoutAllocating(t *testing.T) {
	const size = 1400
	p := NewPacker()
	// A packet that cannot fit in one payload, so every call both finishes a
	// tail and starts a new one.
	pkts := [][]byte{ipv4(1200, 3), ipv4(1200, 4)}
	for range 4 {
		p.Pack(pkts, size) // prime both buffers so their growth is not counted
	}

	if got := testing.AllocsPerRun(100, func() {
		p.Pack(pkts, size)
	}); got > 1 {
		t.Errorf("Pack allocated %v times per payload while fragmenting, want at "+
			"most 1 (the pad)", got)
	}
}
