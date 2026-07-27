package ike

import (
	"bytes"
	"testing"

	"github.com/xen0bit/veepin/internal/ikev2/esp"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// gcmESPTransform builds an AES-GCM-16 ESP transform keyed with a repeated byte.
func gcmESPTransform(t *testing.T, key byte) esp.Transform {
	t.Helper()
	c, err := transform.Cipher(payload.ENCR_AES_GCM_16, 256)
	if err != nil {
		t.Fatal(err)
	}
	return esp.Transform{
		EncrID:    payload.ENCR_AES_GCM_16,
		EncrKeyLn: 256,
		EncKey:    bytes.Repeat([]byte{key}, c.KeyLen()),
	}
}

// TestESPTunnelNextHeaderByFamily proves the dual-stack data path tags each inner
// packet with the ESP next-header its version implies — IPv4 (4) or IPv6 (41) —
// so one Child SA carries both families and the receiver learns which it opened.
func TestESPTunnelNextHeaderByFamily(t *testing.T) {
	kOut := gcmESPTransform(t, 0x11)
	kIn := gcmESPTransform(t, 0x22)
	sender := &esp.SA{SPIOut: 0xaaaa, SPIIn: 0xbbbb, Out: kOut, In: kIn}
	receiver := &esp.SA{SPIOut: 0xbbbb, SPIIn: 0xaaaa, Out: kIn, In: kOut}

	tun := &espTunnel{espSA: sender, inSPI: 0xbbbb}

	// A minimal IPv4 packet (version nibble 4) and IPv6 packet (nibble 6).
	v4 := make([]byte, 20)
	v4[0] = 0x45
	v6 := make([]byte, 40)
	v6[0] = 0x60

	for _, tc := range []struct {
		name   string
		pkt    []byte
		wantNH uint8
	}{
		{"IPv4 -> next-header 4", v4, 4},
		{"IPv6 -> next-header 41", v6, 41},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := tun.Encapsulate(tc.pkt)
			if err != nil {
				t.Fatalf("Encapsulate: %v", err)
			}
			inner, nh, err := receiver.Decapsulate(wire)
			if err != nil {
				t.Fatalf("Decapsulate: %v", err)
			}
			if nh != tc.wantNH {
				t.Errorf("next-header = %d, want %d", nh, tc.wantNH)
			}
			if !bytes.Equal(inner, tc.pkt) {
				t.Errorf("inner packet did not round-trip")
			}
		})
	}
}

// espIP builds a minimal IP packet of total length n whose header declares that
// length, since the trim on the receive side believes the header.
func espIP(t *testing.T, version, n int) []byte {
	t.Helper()
	p := make([]byte, n)
	switch version {
	case 4:
		p[0] = 0x45
		p[2], p[3] = byte(n>>8), byte(n)
	case 6:
		p[0] = 0x60
		p[4], p[5] = byte((n-40)>>8), byte(n-40)
	default:
		t.Fatalf("espIP: version %d", version)
	}
	for i := 20; i < n; i++ {
		p[i] = byte(i) // distinguishable payload, so a bad trim is visible
	}
	return p
}

// TestESPTunnelPaddingRoundTrip is the end-to-end shape of the defence: a small
// packet leaves padded to the size of a full one, and comes back byte-identical
// because the trim delimits it by its own IP header.
func TestESPTunnelPaddingRoundTrip(t *testing.T) {
	kOut := gcmESPTransform(t, 0x11)
	kIn := gcmESPTransform(t, 0x22)
	sender := &esp.SA{SPIOut: 0xaaaa, SPIIn: 0xbbbb, Out: kOut, In: kIn}
	receiver := &esp.SA{SPIOut: 0xbbbb, SPIIn: 0xaaaa, Out: kIn, In: kOut}

	out := &espTunnel{espSA: sender, inSPI: 0xbbbb}
	in := &espTunnel{espSA: receiver, inSPI: 0xaaaa}

	for _, tc := range []struct {
		name    string
		version int
		size    int
	}{
		{"IPv4 tiny", 4, 40},
		{"IPv4 small", 4, 137},
		{"IPv6 tiny", 6, 48},
		{"IPv6 small", 6, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := espIP(t, tc.version, tc.size)
			padded, err := out.EncapsulatePadded(pkt, 1400)
			if err != nil {
				t.Fatalf("EncapsulatePadded: %v", err)
			}
			full, err := out.Encapsulate(espIP(t, tc.version, 1400))
			if err != nil {
				t.Fatalf("Encapsulate: %v", err)
			}
			if len(padded) != len(full) {
				t.Errorf("padded = %d bytes, a genuine full packet = %d; sizes must match", len(padded), len(full))
			}
			got, err := in.Decapsulate(padded)
			if err != nil {
				t.Fatalf("Decapsulate: %v", err)
			}
			if !bytes.Equal(got, pkt) {
				t.Errorf("recovered %d bytes, want the original %d", len(got), len(pkt))
			}
		})
	}
}

// An unpadded packet must survive the new trim untouched: the receive path
// changed for every peer, not just for padding ones.
func TestESPTunnelUnpaddedStillRoundTrips(t *testing.T) {
	kOut := gcmESPTransform(t, 0x11)
	kIn := gcmESPTransform(t, 0x22)
	out := &espTunnel{espSA: &esp.SA{SPIOut: 1, SPIIn: 2, Out: kOut, In: kIn}, inSPI: 2}
	in := &espTunnel{espSA: &esp.SA{SPIOut: 2, SPIIn: 1, Out: kIn, In: kOut}, inSPI: 1}

	for _, tc := range []struct{ version, size int }{{4, 20}, {4, 1400}, {6, 40}, {6, 1400}} {
		pkt := espIP(t, tc.version, tc.size)
		wire, err := out.Encapsulate(pkt)
		if err != nil {
			t.Fatalf("Encapsulate: %v", err)
		}
		got, err := in.Decapsulate(wire)
		if err != nil {
			t.Fatalf("Decapsulate: %v", err)
		}
		if !bytes.Equal(got, pkt) {
			t.Errorf("v%d/%d did not round-trip", tc.version, tc.size)
		}
	}
}

// A dummy packet (RFC 4303 next-header 59) is pure filler and must be dropped
// rather than routed as if it were an IP packet.
func TestESPTunnelDropsDummyPacket(t *testing.T) {
	kOut := gcmESPTransform(t, 0x11)
	kIn := gcmESPTransform(t, 0x22)
	sender := &esp.SA{SPIOut: 1, SPIIn: 2, Out: kOut, In: kIn}
	in := &espTunnel{espSA: &esp.SA{SPIOut: 2, SPIIn: 1, Out: kIn, In: kOut}, inSPI: 1}

	dummy, err := sender.Encapsulate(make([]byte, 512), 59)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.Decapsulate(dummy); err == nil {
		t.Fatal("a next-header 59 dummy packet must be dropped, not delivered")
	}
}
