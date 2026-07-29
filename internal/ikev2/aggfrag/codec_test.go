package aggfrag

import (
	"bytes"
	"testing"
)

func TestPackSinglePacket(t *testing.T) {
	ip4 := []byte{0x45, 0x00, 0x00, 0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	pkt, frag := Pack([][]byte{ip4}, 64, nil)
	if len(pkt) != 64 {
		t.Errorf("packet length = %d, want 64", len(pkt))
	}
	if len(frag) > 0 {
		t.Errorf("unexpected fragment: %d bytes", len(frag))
	}
	// Verify the first byte is an IP version nibble.
	if pkt[4]>>4 != 4 {
		t.Errorf("first block type = %x, want 4 (IPv4)", pkt[4]>>4)
	}
}

func TestPackMultiplePackets(t *testing.T) {
	ip4 := []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ip6 := []byte{0x60, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	pkt, frag := Pack([][]byte{ip4, ip6}, 128, nil)
	if len(pkt) != 128 {
		t.Errorf("packet length = %d, want 128", len(pkt))
	}
	if len(frag) > 0 {
		t.Errorf("unexpected fragment: %d bytes", len(frag))
	}
	_ = pkt
}

func TestPackFragment(t *testing.T) {
	ip4 := []byte{0x45, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ip4 = append(ip4, make([]byte, 0x100-20)...)

	mtu := 64
	pkt, frag := Pack([][]byte{ip4}, mtu, nil)
	if len(pkt) != mtu {
		t.Errorf("packet length = %d, want %d", len(pkt), mtu)
	}
	if len(frag) == 0 {
		t.Errorf("expected a fragment but got none")
	}
	if len(frag)+len(pkt)-4 >= len(ip4) {
		t.Logf("packed %d, fragmented %d (original %d)", len(pkt)-4, len(frag), len(ip4))
	}
}

func TestReassemble(t *testing.T) {
	ip4 := []byte{0x45, 0x00, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ip4 = append(ip4, make([]byte, 0x20-20)...)

	r := NewReassembler()

	// Pack and feed in one go.
	pkt, frag := Pack([][]byte{ip4}, 128, nil)
	if len(frag) > 0 {
		t.Fatalf("unexpected fragment: %d bytes", len(frag))
	}

	pkts, err := r.Feed(pkt)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}
	if !bytes.Equal(pkts[0], ip4) {
		t.Errorf("reassembled packet mismatch")
	}
}

func TestReassembleFragmented(t *testing.T) {
	ip4 := []byte{0x45, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ip4 = append(ip4, make([]byte, 0x100-20)...)

	r := NewReassembler()

	pkt1, frag := Pack([][]byte{ip4}, 64, nil)
	if len(frag) == 0 {
		t.Fatal("expected a fragment")
	}

	// First fragment
	pkts, err := r.Feed(pkt1)
	if err != nil {
		t.Fatalf("Feed 1: %v", err)
	}
	if len(pkts) != 0 {
		t.Logf("first fragment produced %d packets (may be zero)", len(pkts))
	}

	// Second fragment with the remainder
	pkt2, rest := Pack(nil, 200, frag)
	if len(rest) > 0 {
		t.Fatalf("unexpected rest after second pack: %d", len(rest))
	}

	pkts, err = r.Feed(pkt2)
	if err != nil {
		t.Fatalf("Feed 2: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet from second fragment, got %d", len(pkts))
	}
	if !bytes.Equal(pkts[0], ip4) {
		t.Errorf("reassembled packet mismatch")
	}
}

func TestPadBlockIsDropped(t *testing.T) {
	ip4 := []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	// Pack into a large MTU so most of it is pad.
	pkt, frag := Pack([][]byte{ip4}, 128, nil)
	if len(frag) > 0 {
		t.Fatalf("unexpected fragment")
	}

	r := NewReassembler()
	pkts, err := r.Feed(pkt)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d (pad should be dropped)", len(pkts))
	}
}

func TestRejectEveryTruncation(t *testing.T) {
	ip4 := []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	pkt, _ := Pack([][]byte{ip4}, 64, nil)

	r := NewReassembler()
	for i := 0; i < 4; i++ {
		_, err := r.Feed(pkt[:i])
		if err == nil {
			t.Fatalf("expected error for prefix length %d", i)
		}
	}
}
