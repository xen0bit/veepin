package pulse

import (
	"fmt"
	"testing"
)

func pulsePayload(n int) []byte {
	p := make([]byte, n)
	p[0] = 0x45
	p[2] = byte(n >> 8)
	p[3] = byte(n)
	for i := 4; i < n; i++ {
		p[i] = byte(i)
	}
	return p
}

var pulseSizes = []int{64, 576, 1400}

// BenchmarkEncodeData measures wrapping a layer-3 packet in the 16-octet
// IF-T/TLS header. The carrier is TLS, so this prepend is the veepin-specific
// per-packet cost on that data path; the ESP path's cost is measured in
// internal/ikev2/esp instead.
func BenchmarkEncodeData(b *testing.B) {
	for _, size := range pulseSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			pkt := pulsePayload(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = EncodeData(1, pkt)
			}
		})
	}
}

func BenchmarkParseMessage(b *testing.B) {
	for _, size := range pulseSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			msg := EncodeData(1, pulsePayload(size))
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, _, err := ParseMessage(msg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestFramingAllocations pins the framing costs: EncodeData allocates once (the
// framed message), ParseMessage not at all, because it returns a subslice of its
// input rather than a copy. A regression here means the parser started copying,
// which on the inbound path is one allocation per packet.
func TestFramingAllocations(t *testing.T) {
	pkt := pulsePayload(1400)
	if n := testing.AllocsPerRun(200, func() { _ = EncodeData(1, pkt) }); n > 1 {
		t.Errorf("EncodeData allocates %.0f times, want 1", n)
	}
	msg := EncodeData(1, pkt)
	if n := testing.AllocsPerRun(200, func() {
		if _, _, err := ParseMessage(msg); err != nil {
			t.Fatal(err)
		}
	}); n > 0 {
		t.Errorf("ParseMessage allocates %.0f times, want 0", n)
	}
}
