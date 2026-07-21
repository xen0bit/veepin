package l2tp

import (
	"fmt"
	"testing"
)

func l2tpPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

var l2tpSizes = []int{64, 576, 1400}

// BenchmarkMarshalData measures wrapping a PPP frame in an L2TP data message. The
// message then rides inside an ESP transport SA (internal/ikev2/esp, separately
// benchmarked), so this 6-octet header prepend is the L2TP-specific per-packet cost.
func BenchmarkMarshalData(b *testing.B) {
	for _, size := range l2tpSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			ppp := l2tpPayload(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = marshalData(0x1234, 0x5678, ppp)
			}
		})
	}
}

// TestFramingAllocations pins marshalData to a single allocation (the data message).
func TestFramingAllocations(t *testing.T) {
	ppp := l2tpPayload(1400)
	if n := testing.AllocsPerRun(100, func() { _ = marshalData(0x1234, 0x5678, ppp) }); n > 1 {
		t.Errorf("marshalData allocates %.0f times, want 1", n)
	}
}
