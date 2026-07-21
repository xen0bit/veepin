package fortinet

import (
	"fmt"
	"testing"
)

func fnPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

var fnSizes = []int{64, 576, 1400}

// BenchmarkEncodeFrame measures wrapping a PPP frame in FortiOS's 6-octet framing.
// The carrier is TLS or DTLS, so this header prepend is the veepin-specific
// per-packet cost on the TLS tunnel.
func BenchmarkEncodeFrame(b *testing.B) {
	for _, size := range fnSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			ppp := fnPayload(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = EncodeFrame(ppp)
			}
		})
	}
}

func BenchmarkParseFrame(b *testing.B) {
	frame := EncodeFrame(fnPayload(1400))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := ParseFrame(frame); err != nil {
			b.Fatal(err)
		}
	}
}

// TestFramingAllocations pins the framing costs: EncodeFrame allocates once (the
// framed packet), ParseFrame not at all (it returns subslices of its input).
func TestFramingAllocations(t *testing.T) {
	ppp := fnPayload(1400)
	if n := testing.AllocsPerRun(100, func() { _ = EncodeFrame(ppp) }); n > 1 {
		t.Errorf("EncodeFrame allocates %.0f times, want 1", n)
	}
	frame := EncodeFrame(ppp)
	if n := testing.AllocsPerRun(100, func() {
		if _, _, err := ParseFrame(frame); err != nil {
			t.Fatal(err)
		}
	}); n > 0 {
		t.Errorf("ParseFrame allocates %.0f times, want 0", n)
	}
}
