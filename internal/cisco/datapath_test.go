package cisco

import (
	"fmt"
	"net"
	"testing"

	"github.com/xen0bit/veepin/internal/ikev1"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
)

func ciscoPayload(n int) []byte {
	p := make([]byte, n)
	p[0] = 0x45 // reads as IPv4, which the next-header choice depends on
	p[2] = byte(n >> 8)
	p[3] = byte(n)
	for i := 4; i < n; i++ {
		p[i] = byte(i)
	}
	return p
}

var ciscoSizes = []int{64, 576, 1400}

// benchTunnel is a keyed tunnel-mode SA with the transform Quick Mode settles
// on: AES-256-CBC with HMAC-SHA2-256-128.
func benchTunnel() *Tunnel {
	r := ikev1.Result{
		EncrID: 12, EncrKeyLn: 256, IntegID: 12,
		OutSPI: 0x11111111, InSPI: 0x22222222,
		OutEncKey: make([]byte, 32), OutIntegKey: make([]byte, 32),
		InEncKey: make([]byte, 32), InIntegKey: make([]byte, 32),
	}
	return NewTunnel(newESPSA(r), r.InSPI, defaultRoutes(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500})
}

// loopTunnel is a tunnel whose outbound SA is also its inbound one, so a packet
// it encapsulates is one it can open — what the parse benchmarks need.
func loopTunnel() *Tunnel {
	key := make([]byte, 32)
	tr := esp.Transform{EncrID: 12, EncrKeyLn: 256, IntegID: 12, EncKey: key, IntegKey: key}
	sa := &esp.SA{SPIOut: 0x33333333, SPIIn: 0x33333333, Out: tr, In: tr}
	return NewTunnel(sa, sa.SPIIn, defaultRoutes(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500})
}

// BenchmarkEncapsulate measures protecting one inner IP packet as tunnel-mode
// ESP: the whole per-packet cost of the Cisco IPsec data path, since the
// protocol adds no framing of its own on top of RFC 4303.
func BenchmarkEncapsulate(b *testing.B) {
	t := benchTunnel()
	for _, size := range ciscoSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			pkt := ciscoPayload(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := t.Encapsulate(pkt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecapsulate(b *testing.B) {
	t := loopTunnel()
	for _, size := range ciscoSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			pkt, err := t.Encapsulate(ciscoPayload(size))
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t.sa.ResetReplayWindow()
				if _, err := t.Decapsulate(pkt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestDataPathAllocations pins what this package costs per packet.
//
// The framing here is nothing but RFC 4303, so the crypto allocations belong to
// internal/ikev2/esp and are measured there. What is this package's to guarantee
// is that the layer *on top* of the SA is free: the Tunnel adapter must add no
// allocation to either direction, and isIKE — which runs on every datagram
// arriving on the shared NAT-T port — must add none to the inbound hot path.
//
// The assertion is therefore relative rather than absolute. It catches the
// regressions that can happen here (a Decapsulate that starts copying instead of
// returning a subslice, a demux that starts allocating) without restating the
// AES-CBC crypter's cost, which this package does not choose.
func TestDataPathAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are perturbed by the race detector")
	}
	tun := loopTunnel()
	pkt := ciscoPayload(1400)

	// Warm the prepared crypters and the scratch pool before measuring: the SA
	// builds those once, and counting that setup would say nothing about the
	// steady state.
	espPkt, err := tun.Encapsulate(pkt)
	if err != nil {
		t.Fatal(err)
	}
	tun.sa.ResetReplayWindow()
	if _, err := tun.Decapsulate(espPkt); err != nil {
		t.Fatal(err)
	}

	bare := testing.AllocsPerRun(200, func() {
		if _, err := tun.sa.Encapsulate(pkt, 4); err != nil {
			t.Fatal(err)
		}
	})
	wrapped := testing.AllocsPerRun(200, func() {
		if _, err := tun.Encapsulate(pkt); err != nil {
			t.Fatal(err)
		}
	})
	if wrapped > bare {
		t.Errorf("Tunnel.Encapsulate allocates %.0f times against the SA's %.0f", wrapped, bare)
	}

	espPkt, err = tun.Encapsulate(pkt)
	if err != nil {
		t.Fatal(err)
	}
	bare = testing.AllocsPerRun(200, func() {
		tun.sa.ResetReplayWindow()
		if _, _, derr := tun.sa.Decapsulate(espPkt); derr != nil {
			t.Fatal(derr)
		}
	})
	wrapped = testing.AllocsPerRun(200, func() {
		tun.sa.ResetReplayWindow()
		if _, derr := tun.Decapsulate(espPkt); derr != nil {
			t.Fatal(derr)
		}
	})
	if wrapped > bare {
		t.Errorf("Tunnel.Decapsulate allocates %.0f times against the SA's %.0f", wrapped, bare)
	}

	marked := markIKE(make([]byte, 128))
	if n := testing.AllocsPerRun(200, func() { _, _ = isIKE(marked) }); n > 0 {
		t.Errorf("isIKE allocates %.0f times, want 0", n)
	}
	if n := testing.AllocsPerRun(200, func() { _, _ = isIKE(espPkt) }); n > 0 {
		t.Errorf("isIKE allocates %.0f times on an ESP packet, want 0", n)
	}
}

// TestIKEDemux pins the one rule that keeps IKE and ESP apart on the shared
// NAT-T port: four leading zero octets mean IKE. It is safe only because RFC
// 4303 reserves SPI zero, so no ESP packet can begin that way.
func TestIKEDemux(t *testing.T) {
	msg := []byte("an IKE message")
	marked := markIKE(msg)
	if len(marked) != len(msg)+nonESPMarkerLen {
		t.Fatalf("marked message is %d octets, want %d", len(marked), len(msg)+nonESPMarkerLen)
	}
	got, ok := isIKE(marked)
	if !ok || string(got) != string(msg) {
		t.Fatalf("isIKE = (%q, %v)", got, ok)
	}
	if _, ok := isIKE(loopTunnelPacket(t)); ok {
		t.Error("an ESP packet was taken for IKE")
	}
	for i := range nonESPMarkerLen {
		if _, ok := isIKE(marked[:i]); ok {
			t.Errorf("a %d-octet datagram was taken for IKE", i)
		}
	}
}

func loopTunnelPacket(t *testing.T) []byte {
	t.Helper()
	pkt, err := loopTunnel().Encapsulate(ciscoPayload(64))
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}
