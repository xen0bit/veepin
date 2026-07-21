package anyconnect

import (
	"fmt"
	"testing"
)

func acPayload(n int) []byte {
	p := make([]byte, n)
	p[0] = 0x45 // looks like an IPv4 packet
	for i := 1; i < n; i++ {
		p[i] = byte(i)
	}
	return p
}

var acSizes = []int{64, 576, 1400}

// BenchmarkCSTPMarshal measures framing an IP packet as a CSTP data packet. The
// crypto on this channel is TLS (crypto/tls), so the veepin-specific per-packet
// cost is this 8-octet header prepend.
func BenchmarkCSTPMarshal(b *testing.B) {
	for _, size := range acSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			payload := acPayload(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = marshal(typeData, payload)
			}
		})
	}
}

func BenchmarkCSTPParseHeader(b *testing.B) {
	hdr := marshal(typeData, acPayload(1400))[:headerLen]
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := parseHeader(hdr); err != nil {
			b.Fatal(err)
		}
	}
}

// TestFramingAllocations pins the CSTP framing costs: marshal allocates once (the
// framed packet), header parsing not at all.
func TestFramingAllocations(t *testing.T) {
	payload := acPayload(1400)
	if n := testing.AllocsPerRun(100, func() { _ = marshal(typeData, payload) }); n > 1 {
		t.Errorf("marshal allocates %.0f times, want 1", n)
	}
	hdr := marshal(typeData, payload)[:headerLen]
	if n := testing.AllocsPerRun(100, func() {
		if _, _, err := parseHeader(hdr); err != nil {
			t.Fatal(err)
		}
	}); n > 0 {
		t.Errorf("parseHeader allocates %.0f times, want 0", n)
	}
}
