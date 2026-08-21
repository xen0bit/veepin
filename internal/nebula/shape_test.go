package nebula

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/dataplane"
)

// shapePacket is host_test.go's ipv4Packet with the addresses fixed, so the
// tests below read as being about sizes rather than about routing.
func shapePacket(t *testing.T, payload string) []byte {
	t.Helper()
	return ipv4Packet(netip.MustParseAddr("10.42.0.1"), netip.MustParseAddr("10.42.0.2"), payload)
}

// TestPadInnerLeavesTotalLengthAlone is the property every shaped protocol here
// relies on and the one that is easy to break while "tidying up": the filler is
// outside the packet as far as the IP header is concerned, so a receiver --
// ours or a stock nebula's, which just writes the plaintext to its TUN --
// recovers the original packet byte for byte.
//
// Rewriting Total Length to cover the filler would make the padding part of the
// packet, and whatever transport was inside it would receive garbage.
func TestPadInnerLeavesTotalLengthAlone(t *testing.T) {
	orig := shapePacket(t, "the real payload")
	padded := padInner(orig, 1300)

	if len(padded) != 1300 {
		t.Fatalf("padded length = %d, want 1300", len(padded))
	}
	if got := binary.BigEndian.Uint16(padded[2:4]); int(got) != len(orig) {
		t.Errorf("Total Length = %d after padding, want %d; the filler has been made part "+
			"of the packet and the inner transport will see garbage", got, len(orig))
	}
	if !bytes.Equal(padded[:len(orig)], orig) {
		t.Error("padding altered the packet it was supposed to leave alone")
	}
	for i, b := range padded[len(orig):] {
		if b != 0 {
			t.Fatalf("filler octet %d = %#x, want zero", i, b)
		}
	}
}

// TestPadInnerNeverShrinks: a target below the packet's own size is a shaper
// asking for something impossible, and the answer is the packet unchanged
// rather than a truncated one.
func TestPadInnerNeverShrinks(t *testing.T) {
	orig := shapePacket(t, strings.Repeat("x", 400))
	for _, target := range []int{0, 1, len(orig) - 1, len(orig)} {
		if got := padInner(orig, target); len(got) != len(orig) {
			t.Errorf("padInner(target=%d) returned %d octets, want %d", target, len(got), len(orig))
		}
	}
}

// TestShapedPacketSurvivesTheAEADRoundTrip is the claim specific to nebula, and
// the reason the padding goes inside the sealed payload rather than after the
// tag: the 16-octet header is additional data, so trailing octets appended to
// the datagram are not covered by the authentication and a conforming peer
// rejects the whole thing rather than trimming it.
//
// Inside the plaintext, the peer decrypts successfully and the filler arrives
// as trailing octets on the inner packet, where IP's Total Length delimits it.
func TestShapedPacketSurvivesTheAEADRoundTrip(t *testing.T) {
	// benchTunnel's send and recv keys are the same, so what it encrypts it can
	// also decrypt -- enough to exercise the AEAD without a handshake.
	tun := benchTunnel(t, cipherAESGCM)
	orig := shapePacket(t, "shaped")
	padded := padInner(orig, 1300)

	wire := tun.encrypt(typeMessage, subTypeNone, padded)
	_, got, err := tun.decrypt(wire)
	if err != nil {
		t.Fatalf("decrypting a shaped packet: %v", err)
	}
	if len(got) != len(padded) {
		t.Fatalf("decrypted %d octets, want %d", len(got), len(padded))
	}
	if !bytes.Equal(got[:len(orig)], orig) {
		t.Error("the inner packet did not survive the padded round trip")
	}
	// And the receiver's own delimiter still finds the real packet.
	if total := int(binary.BigEndian.Uint16(got[2:4])); total != len(orig) {
		t.Errorf("Total Length after the round trip = %d, want %d", total, len(orig))
	}
}

// TestShaperProducesPacketsAtTheMTU: the point of shaping is that the inner
// handshake's size pattern stops being visible, so the first packets of a flow
// have to come out at the interface MTU rather than at their own size.
func TestShaperProducesPacketsAtTheMTU(t *testing.T) {
	const mtu = 1300
	sh := dataplane.NewShaper(dataplane.ShapeConfig{Bytes: 16384})

	small := shapePacket(t, "tls client hello, notionally")
	target := sh.Target(small, mtu)
	if target <= len(small) {
		t.Fatalf("shaper asked for %d octets on a %d-octet packet; nothing would be padded", target, len(small))
	}
	if got := len(padInner(small, target)); got != mtu {
		t.Errorf("shaped packet is %d octets, want the full %d-octet MTU", got, mtu)
	}
}
