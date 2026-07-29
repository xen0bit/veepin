package ike

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/aggfrag"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
)

// aggfragPair builds two tunnels sharing key material, one the mirror of the
// other, so what one encapsulates the other can open.
func aggfragPair(t *testing.T) (out, in *aggfragTunnel) {
	t.Helper()
	// AES-GCM keys carry a 4-octet salt after the key itself (RFC 4106), so the
	// ESP transform wants 36 octets for a 256-bit cipher, not 32.
	kOut := bytes.Repeat([]byte{0xa1}, 36)
	kIn := bytes.Repeat([]byte{0xb2}, 36)

	mk := func(spiOut, spiIn uint32, enc, dec []byte) *aggfragTunnel {
		e := &espTunnel{
			espSA: &esp.SA{
				SPIOut: spiOut, SPIIn: spiIn,
				Out: esp.Transform{EncrID: 20, EncrKeyLn: 256, EncKey: enc},
				In:  esp.Transform{EncrID: 20, EncrKeyLn: 256, EncKey: dec},
			},
			inSPI:  spiIn,
			routes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}
		e.peer.Store(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500})
		return newAggfragTunnel(e)
	}
	return mk(1, 2, kOut, kIn), mk(2, 1, kIn, kOut)
}

func testIPv4(n int, fill byte) []byte {
	p := make([]byte, n)
	p[0] = 0x45
	p[2], p[3] = byte(n>>8), byte(n)
	p[9] = 17
	for i := 20; i < n; i++ {
		p[i] = fill
	}
	return p
}

// TestAggfragTunnelUsesNextHeader144 pins the wire marker. An AGGFRAG SA that
// still emitted 4 or 41 would be read by the peer as a plain inner IP packet,
// and the AGGFRAG header would be parsed as an IP header.
func TestAggfragTunnelUsesNextHeader144(t *testing.T) {
	out, in := aggfragPair(t)

	pkt := testIPv4(64, 0x11)
	espPkt, err := out.Encapsulate(pkt)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	_, nextHeader, err := in.espSA.Decapsulate(espPkt)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if nextHeader != aggfrag.ESPNextHeader {
		t.Errorf("ESP next header = %d, want %d", nextHeader, aggfrag.ESPNextHeader)
	}
}

// TestAggfragTunnelRoundTrip: a packet survives the AGGFRAG data path intact.
func TestAggfragTunnelRoundTrip(t *testing.T) {
	out, in := aggfragPair(t)

	want := testIPv4(200, 0x5a)
	espPkt, err := out.Encapsulate(want)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	got, err := in.DecapsulateMulti(espPkt, nil)
	if err != nil {
		t.Fatalf("DecapsulateMulti: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d inner packets, want 1", len(got))
	}
	if !bytes.Equal(got[0], want) {
		t.Errorf("inner packet differs:\ngot  %x\nwant %x", got[0], want)
	}
}

// TestAggfragTunnelAcceptsPlainInnerPackets: the next-header says per packet
// what a payload is, so a peer that sends an ordinary tunnel-mode packet on an
// AGGFRAG SA is still understood.
func TestAggfragTunnelAcceptsPlainInnerPackets(t *testing.T) {
	out, in := aggfragPair(t)

	want := testIPv4(100, 0x33)
	espPkt, err := out.espTunnel.Encapsulate(want) // the plain path
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	got, err := in.DecapsulateMulti(espPkt, nil)
	if err != nil {
		t.Fatalf("DecapsulateMulti: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Errorf("plain inner packet not delivered on an AGGFRAG SA: %x", got)
	}
}

// TestOnlyAnAggfragTunnelIsAMultiTunnel guards the type split. If espTunnel
// itself implemented DecapsulateMulti, every IKEv2 tunnel in the tree would
// take the pump's aggregating path -- including the fifteen protocols-worth
// that never negotiated AGGFRAG.
func TestOnlyAnAggfragTunnelIsAMultiTunnel(t *testing.T) {
	plain := &espTunnel{}
	if _, ok := any(plain).(dataplane.MultiTunnel); ok {
		t.Error("a plain espTunnel satisfies dataplane.MultiTunnel; " +
			"the aggregating path must be opt-in per SA")
	}
	if _, ok := any(newAggfragTunnel(plain)).(dataplane.MultiTunnel); !ok {
		t.Error("an aggfragTunnel does not satisfy dataplane.MultiTunnel")
	}
}

// TestAggfragPaddedEncapUsesAPadBlock: with shaping on, the padding goes inside
// the AGGFRAG payload as a pad block rather than as ESP TFC padding around it,
// because a pad block is what an AGGFRAG receiver already discards.
func TestAggfragPaddedEncapUsesAPadBlock(t *testing.T) {
	out, in := aggfragPair(t)

	want := testIPv4(64, 0x77)
	espPkt, err := out.EncapsulatePadded(want, 800)
	if err != nil {
		t.Fatalf("EncapsulatePadded: %v", err)
	}
	inner, nextHeader, err := in.espSA.Decapsulate(espPkt)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if nextHeader != aggfrag.ESPNextHeader {
		t.Fatalf("next header = %d, want %d", nextHeader, aggfrag.ESPNextHeader)
	}
	if len(inner) < 800 {
		t.Errorf("padded payload is %d octets, want at least 800", len(inner))
	}

	// A fresh packet: the one above is spent, and replaying it would (rightly)
	// be refused by the anti-replay window.
	espPkt2, err := out.EncapsulatePadded(want, 800)
	if err != nil {
		t.Fatalf("EncapsulatePadded: %v", err)
	}
	got, err := in.DecapsulateMulti(espPkt2, nil)
	if err != nil {
		t.Fatalf("DecapsulateMulti: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Errorf("the padded packet did not survive: %x", got)
	}
}
