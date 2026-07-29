package l2tpv3

import (
	"testing"
)

var benchSizes = []int{64, 576, 1400}

// benchFrame is a stand-in Ethernet frame of n octets carrying IPv4.
func benchFrame(n int) []byte {
	f := make([]byte, n)
	copy(f, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	f[12], f[13] = 0x08, 0x00 // EtherType IPv4
	for i := 14; i < n; i++ {
		f[i] = byte(i)
	}
	return f
}

// TestDataPathAllocations pins the per-packet allocation counts this data path
// was written for: encoding into a reused buffer allocates nothing, and
// decoding allocates nothing because it returns subslices of its input.
//
// If this fails, something on the hot path started copying -- most likely
// EncodeData reallocating because the caller stopped reusing its buffer, or
// DecodeData being changed to return a struct pointer instead of subslices.
func TestDataPathAllocations(t *testing.T) {
	frame := benchFrame(1400)
	cookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	buf := make([]byte, 0, 65535)
	if got := testing.AllocsPerRun(100, func() {
		buf = EncodeData(buf, 0x1234, cookie, true, frame)
	}); got != 0 {
		t.Errorf("EncodeData into a reused buffer allocated %v times per packet, want 0", got)
	}

	pkt := EncodeData(nil, 0x1234, cookie, true, frame)
	if got := testing.AllocsPerRun(100, func() {
		if _, _, err := DecodeData(pkt, cookie, true); err != nil {
			t.Fatal(err)
		}
	}); got != 0 {
		t.Errorf("DecodeData allocated %v times per packet, want 0", got)
	}
}

// TestDropPathAllocations pins the rejection path. A peer flooding malformed
// packets must cost nothing to reject, which is why the errors are pre-built
// sentinels rather than fmt.Errorf calls.
func TestDropPathAllocations(t *testing.T) {
	frame := benchFrame(1400)
	cookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	wrong := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	pkt := EncodeData(nil, 0x1234, cookie, true, frame)

	if got := testing.AllocsPerRun(100, func() {
		_, _, _ = DecodeData(pkt, wrong, true)
	}); got != 0 {
		t.Errorf("rejecting a bad cookie allocated %v times, want 0", got)
	}

	short := pkt[:4]
	if got := testing.AllocsPerRun(100, func() {
		_, _, _ = DecodeData(short, cookie, true)
	}); got != 0 {
		t.Errorf("rejecting a truncated packet allocated %v times, want 0", got)
	}
}

func BenchmarkEncodeData(b *testing.B) {
	cookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _, n := range benchSizes {
		b.Run(sizeName(n), func(b *testing.B) {
			frame := benchFrame(n)
			buf := make([]byte, 0, 65535)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				buf = EncodeData(buf, 0x1234, cookie, true, frame)
			}
		})
	}
}

func BenchmarkDecodeData(b *testing.B) {
	cookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _, n := range benchSizes {
		b.Run(sizeName(n), func(b *testing.B) {
			pkt := EncodeData(nil, 0x1234, cookie, true, benchFrame(n))
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, _, err := DecodeData(pkt, cookie, true); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSessionIDDemux(b *testing.B) {
	pkt := EncodeData(nil, 0x1234, nil, false, benchFrame(1400))
	b.ReportAllocs()
	for range b.N {
		if _, ok := SessionIDDemux(pkt); !ok {
			b.Fatal("demux failed")
		}
	}
}

func sizeName(n int) string {
	switch n {
	case 64:
		return "64"
	case 576:
		return "576"
	default:
		return "1400"
	}
}
