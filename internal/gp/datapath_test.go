package gp

import (
	"fmt"
	"testing"
)

func gpPayload(n int) []byte {
	p := make([]byte, n)
	p[0] = 0x45 // so it reads as IPv4 where that matters
	for i := 1; i < n; i++ {
		p[i] = byte(i)
	}
	return p
}

var gpSizes = []int{64, 576, 1400}

// BenchmarkEncodeFrame measures wrapping a layer-3 packet in GlobalProtect's
// 16-octet framing. The carrier is TLS, so this prepend is the veepin-specific
// per-packet cost on the SSL tunnel — the ESP path's cost is measured in
// internal/ikev2/esp instead.
func BenchmarkEncodeFrame(b *testing.B) {
	for _, size := range gpSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			pkt := gpPayload(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = EncodeFrame(EtherTypeIPv4, pkt)
			}
		})
	}
}

func BenchmarkParseFrame(b *testing.B) {
	for _, size := range gpSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			frame := EncodeFrame(EtherTypeIPv4, gpPayload(size))
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := ParseFrame(frame); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestFramingAllocations pins the framing costs: EncodeFrame allocates once (the
// framed packet), ParseFrame not at all, because it returns a subslice of its
// input rather than a copy. A regression here means the parser started copying,
// which on the inbound path is one allocation per packet.
func TestFramingAllocations(t *testing.T) {
	pkt := gpPayload(1400)
	if n := testing.AllocsPerRun(100, func() { _ = EncodeFrame(EtherTypeIPv4, pkt) }); n > 1 {
		t.Errorf("EncodeFrame allocates %.0f times, want 1", n)
	}
	frame := EncodeFrame(EtherTypeIPv4, pkt)
	if n := testing.AllocsPerRun(100, func() {
		if _, _, err := ParseFrame(frame); err != nil {
			t.Fatal(err)
		}
	}); n > 0 {
		t.Errorf("ParseFrame allocates %.0f times, want 0", n)
	}
}
