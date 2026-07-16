package transport

import (
	"testing"

	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

func sizeName(n int) string {
	switch n {
	case 64:
		return "64B"
	case 576:
		return "576B"
	case 1400:
		return "1400B"
	default:
		return "n"
	}
}

// BenchmarkSeal measures the outbound transport path: pad, header, and the
// ChaCha20-Poly1305 seal, per packet. This is the per-packet cost of traffic
// leaving the TUN toward the peer, and the number that must stay high for the
// data path to be worth having in Go — it is why the AEAD comes from x/crypto's
// assembly rather than a hand-rolled cipher.
func BenchmarkSeal(b *testing.B) {
	for _, size := range []int{64, 576, 1400} {
		b.Run(sizeName(size), func(b *testing.B) {
			s, _ := pair(b)
			inner := ipv4(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := s.Seal(inner); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOpen measures the inbound transport path: decrypt in place, the
// anti-replay check, and the length trim. The replay window would reject a
// re-sent counter, so each iteration decrypts a freshly sealed packet from a
// pre-built batch with distinct counters.
func BenchmarkOpen(b *testing.B) {
	for _, size := range []int{64, 576, 1400} {
		b.Run(sizeName(size), func(b *testing.B) {
			a, recv := pair(b)
			inner := ipv4(size)

			const batch = 1024
			pkts := make([][]byte, batch)
			for i := range pkts {
				m, err := a.Seal(inner)
				if err != nil {
					b.Fatal(err)
				}
				pkts[i] = m
			}
			// A scratch copy per iteration, since Open decrypts in place.
			scratch := make([]byte, wire.TransportHeaderLen+size+64+wire.TagSize)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				if i%batch == 0 && i != 0 {
					// Exhausted the batch's distinct counters; rebuild the
					// receiver so the replay window starts fresh.
					b.StopTimer()
					_, recv = pair(b)
					b.StartTimer()
				}
				src := pkts[i%batch]
				buf := scratch[:len(src)]
				copy(buf, src)
				if _, err := recv.Open(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
