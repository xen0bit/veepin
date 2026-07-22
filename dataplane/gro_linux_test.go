//go:build linux

package dataplane

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

// spiTunnel is a Tunnel whose datagrams are a 4-byte SPI (1) prefix on the
// inner packet, so SPIDemux routes to it and Decapsulate just strips the
// prefix — inbound GRO tests then control the exact inner bytes.
type spiTunnel struct{ peer *net.UDPAddr }

func (t *spiTunnel) InboundKey() uint32 { return 1 }
func (t *spiTunnel) Routes() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
}
func (t *spiTunnel) PeerAddr() *net.UDPAddr { return t.peer }
func (t *spiTunnel) Encapsulate(p []byte) ([]byte, error) {
	return append([]byte{0, 0, 0, 1}, p...), nil
}
func (t *spiTunnel) Decapsulate(p []byte) ([]byte, error) { return p[4:], nil }

func spiWrap(inner []byte) []byte { return append([]byte{0, 0, 0, 1}, inner...) }

// groPump builds a vnet pump around a fake GSO TUN and the SPI tunnel.
func groPump(t *testing.T) (*Pump, *fakeGSOTUN) {
	t.Helper()
	tun := newFakeGSOTUN() // no reads: these tests drive HandleInboundBatch directly
	pump := NewPump(tun, func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
	pump.AddTunnel(&spiTunnel{peer: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}})
	return pump, tun
}

// validSegments cuts a super-frame with segmentTSO4, whose output carries
// genuinely valid checksums — exactly what verified GRO input looks like.
func validSegments(t *testing.T, id uint16, seq uint32, flags byte, payload, gsoSize int) [][]byte {
	t.Helper()
	super := buildTCP4(t, id, seq, flags, patterned(payload))
	var segs [][]byte
	n, err := segmentTSO4(super, virtioNetHdr{gsoType: vnetGSOTCPv4, gsoSize: uint16(gsoSize), hdrLen: 40}, &segs)
	if err != nil {
		t.Fatalf("segmentTSO4: %v", err)
	}
	out := make([][]byte, n)
	for i := range n {
		out[i] = append([]byte(nil), segs[i]...)
	}
	return out
}

func patterned(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 13)
	}
	return b
}

// The core property, and TSO's mirror: segments cut from a super-frame
// coalesce back into one GSO TUN write carrying the same payload, correct
// lengths, a valid IP checksum, the CHECKSUM_PARTIAL pseudo-header sum, and
// GSO metadata the kernel can re-segment with.
func TestGROCoalescesBatch(t *testing.T) {
	const (
		baseID  = 0x3344
		baseSeq = 777_000
	)
	segs := validSegments(t, baseID, baseSeq, 0x18 /* PSH|ACK */, 2500, 1000)
	pump, tun := groPump(t)

	batch := make([][]byte, len(segs))
	for i, s := range segs {
		batch[i] = spiWrap(s)
	}
	pump.HandleInboundBatch(batch, nil)

	tun.mu.Lock()
	defer tun.mu.Unlock()
	if len(tun.vnetWr) != 0 {
		t.Fatalf("%d packets were written singly instead of coalescing", len(tun.vnetWr))
	}
	if len(tun.gsoWr) != 1 {
		t.Fatalf("got %d GSO writes, want 1", len(tun.gsoWr))
	}
	w := tun.gsoWr[0]
	if w.hdr.flags != vnetFlagNeedsCsum || w.hdr.gsoType != vnetGSOTCPv4 ||
		w.hdr.hdrLen != 40 || w.hdr.gsoSize != 1000 ||
		w.hdr.csumStart != 20 || w.hdr.csumOffset != 16 {
		t.Errorf("virtio-net header %+v is not TCPv4 GSO at 1000", w.hdr)
	}
	frame := w.pkt
	if len(frame) != 40+2500 {
		t.Fatalf("frame length %d, want %d", len(frame), 40+2500)
	}
	if got := binary.BigEndian.Uint16(frame[2:4]); got != uint16(len(frame)) {
		t.Errorf("IP total length %d, want %d", got, len(frame))
	}
	if got := binary.BigEndian.Uint16(frame[4:6]); got != baseID {
		t.Errorf("IP ID %#x, want first segment's %#x", got, baseID)
	}
	if got := binary.BigEndian.Uint32(frame[24:28]); got != baseSeq {
		t.Errorf("TCP seq %d, want %d", got, baseSeq)
	}
	if frame[33]&tcpFlagPSH == 0 {
		t.Error("PSH from the final segment was not folded into the frame")
	}
	if got := foldSum(onesComplementSum(0, frame[:20])); got != 0xffff {
		t.Errorf("IP header checksum does not verify: folded sum %#04x", got)
	}
	// CHECKSUM_PARTIAL contract: completing the checksum as the kernel would
	// (completePartialChecksum is unit-tested against a from-scratch
	// computation) must yield a checksum a receiver verifies.
	completePartialChecksum(frame, 20, 16)
	acc := onesComplementSum(0, frame[12:20])
	acc += protoTCP + uint32(len(frame)-20)
	acc = onesComplementSum(acc, frame[20:])
	if got := foldSum(acc); got != 0xffff {
		t.Errorf("completed TCP checksum does not verify: folded sum %#04x", got)
	}
	if !bytes.Equal(frame[40:], patterned(2500)) {
		t.Error("coalesced payload differs from the original")
	}
}

// Interleaved flows must coalesce independently, never across.
func TestGROKeepsFlowsApart(t *testing.T) {
	a := validSegments(t, 10, 1000, 0x10, 2000, 1000)
	b := validSegments(t, 20, 9000, 0x10, 2000, 1000)
	for _, s := range b {
		binary.BigEndian.PutUint16(s[20:22], 55555) // different source port
		// refresh the TCP checksum after the port change
		s[36], s[37] = 0, 0
		acc := onesComplementSum(0, s[12:20])
		acc += protoTCP + uint32(len(s)-20)
		acc = onesComplementSum(acc, s[20:])
		binary.BigEndian.PutUint16(s[36:38], ^foldSum(acc))
	}
	pump, tun := groPump(t)
	pump.HandleInboundBatch([][]byte{spiWrap(a[0]), spiWrap(b[0]), spiWrap(a[1]), spiWrap(b[1])}, nil)

	tun.mu.Lock()
	defer tun.mu.Unlock()
	if len(tun.gsoWr) != 2 {
		t.Fatalf("got %d GSO writes, want one per flow (2)", len(tun.gsoWr))
	}
	for i, w := range tun.gsoWr {
		if len(w.pkt) != 40+2000 {
			t.Errorf("flow %d frame length %d, want %d", i, len(w.pkt), 40+2000)
		}
	}
}

// A sequence gap must flush what is held and start over — coalescing never
// papers over reordering.
func TestGROFlushesOnSequenceGap(t *testing.T) {
	segs := validSegments(t, 5, 40_000, 0x10, 3000, 1000)
	pump, tun := groPump(t)
	// Deliver segment 0 then segment 2: not contiguous.
	pump.HandleInboundBatch([][]byte{spiWrap(segs[0]), spiWrap(segs[2])}, nil)

	tun.mu.Lock()
	defer tun.mu.Unlock()
	if len(tun.gsoWr) != 0 {
		t.Fatalf("non-contiguous segments were coalesced")
	}
	if len(tun.vnetWr) != 2 {
		t.Fatalf("got %d plain writes, want 2", len(tun.vnetWr))
	}
	if !bytes.Equal(tun.vnetWr[0], segs[0]) || !bytes.Equal(tun.vnetWr[1], segs[2]) {
		t.Error("pass-through packets were modified or reordered")
	}
}

// A segment with a bad TCP checksum must not merge — the coalesced frame is
// CHECKSUM_PARTIAL, so nothing downstream would catch it — and it must not
// overtake its own flow's held data on the way to the stack.
func TestGRORejectsBadChecksumInOrder(t *testing.T) {
	segs := validSegments(t, 5, 40_000, 0x10, 2000, 1000)
	segs[1][100] ^= 0xff // corrupt the second segment's payload
	pump, tun := groPump(t)
	pump.HandleInboundBatch([][]byte{spiWrap(segs[0]), spiWrap(segs[1])}, nil)

	tun.mu.Lock()
	defer tun.mu.Unlock()
	if len(tun.gsoWr) != 0 {
		t.Fatal("a corrupted segment was coalesced")
	}
	if len(tun.vnetWr) != 2 {
		t.Fatalf("got %d plain writes, want 2", len(tun.vnetWr))
	}
	// Order: the held first segment must flush before the corrupt one passes.
	if !bytes.Equal(tun.vnetWr[0], segs[0]) {
		t.Error("first write is not the flow's held segment: pass-through overtook it")
	}
	if !bytes.Equal(tun.vnetWr[1], segs[1]) {
		t.Error("the corrupted segment was not passed through unchanged")
	}
}

// A short segment closes its group (gso_size semantics); later contiguous
// data starts a new frame rather than growing a closed one.
func TestGROShortSegmentClosesGroup(t *testing.T) {
	segs := validSegments(t, 5, 40_000, 0x10, 2500, 1000) // 1000,1000,500
	next := validSegments(t, 8, 40_000+2500, 0x10, 1000, 1000)
	pump, tun := groPump(t)
	batch := [][]byte{spiWrap(segs[0]), spiWrap(segs[1]), spiWrap(segs[2]), spiWrap(next[0])}
	pump.HandleInboundBatch(batch, nil)

	tun.mu.Lock()
	defer tun.mu.Unlock()
	if len(tun.gsoWr) != 1 || len(tun.gsoWr[0].pkt) != 40+2500 {
		t.Fatalf("want one 2540-byte GSO frame from the closed group, got %d writes", len(tun.gsoWr))
	}
	if len(tun.vnetWr) != 1 || !bytes.Equal(tun.vnetWr[0], next[0]) {
		t.Fatalf("the post-close segment should flush as a single plain write")
	}
}

// discardGSOTUN swallows writes without recording them, so the alloc test
// measures the GRO path itself rather than a capturing fake.
type discardGSOTUN struct{}

func (discardGSOTUN) Read(buf []byte) (int, error)            { return 0, net.ErrClosed }
func (discardGSOTUN) Write(pkt []byte) (int, error)           { return len(pkt), nil }
func (discardGSOTUN) GSO() bool                               { return true }
func (discardGSOTUN) writeVnet(pkt []byte) (int, error)       { return len(pkt), nil }
func (discardGSOTUN) writeVnetGSO(h, pkt []byte) (int, error) { return len(pkt), nil }

// Steady-state coalescing allocates nothing, the data-path discipline.
func TestGROAllocs(t *testing.T) {
	segs := validSegments(t, 5, 40_000, 0x10, 3000, 1500)
	pump := NewPump(discardGSOTUN{}, func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
	pump.AddTunnel(&spiTunnel{peer: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}})
	batch := make([][]byte, len(segs))
	for i, s := range segs {
		batch[i] = spiWrap(s)
	}
	pump.HandleInboundBatch(batch, nil) // warm the group scratch
	if avg := testing.AllocsPerRun(100, func() {
		pump.HandleInboundBatch(batch, nil)
	}); avg != 0 {
		t.Errorf("HandleInboundBatch allocates %.1f per batch in steady state, want 0", avg)
	}
}
