package data

import (
	"testing"

	"github.com/xen0bit/veepin/internal/openvpn/keys"
)

func benchCiphers(b *testing.B) (client, server *Cipher) {
	b.Helper()
	var kA, kB [keys.GCMKeyLen]byte
	var ivA, ivB [keys.ImplicitIVLen]byte
	for i := range kA {
		kA[i] = byte(i + 1)
		kB[i] = byte(i + 100)
	}
	for i := range ivA {
		ivA[i] = byte(i + 8)
		ivB[i] = byte(i + 200)
	}
	c, _ := New(keys.DataKeys{EncryptKey: kA, DecryptKey: kB, EncryptIV: ivA, DecryptIV: ivB}, 0, 0)
	s, _ := New(keys.DataKeys{EncryptKey: kB, DecryptKey: kA, EncryptIV: ivB, DecryptIV: ivA}, 0, 0)
	return c, s
}

func ipv4(size int) []byte {
	if size < 20 {
		size = 20
	}
	p := make([]byte, size)
	p[0] = 0x45
	p[2] = byte(size >> 8)
	p[3] = byte(size)
	return p
}

func sizeName(n int) string {
	switch n {
	case 64:
		return "64B"
	case 576:
		return "576B"
	case 1400:
		return "1400B"
	}
	return "n"
}

func BenchmarkSeal(b *testing.B) {
	for _, size := range []int{64, 576, 1400} {
		b.Run(sizeName(size), func(b *testing.B) {
			c, _ := benchCiphers(b)
			inner := ipv4(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := c.Seal(inner); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	for _, size := range []int{64, 576, 1400} {
		b.Run(sizeName(size), func(b *testing.B) {
			c, s := benchCiphers(b)
			inner := ipv4(size)

			const batch = 1024
			pkts := make([][]byte, batch)
			for i := range pkts {
				m, err := c.Seal(inner)
				if err != nil {
					b.Fatal(err)
				}
				pkts[i] = m
			}
			scratch := make([]byte, size+Overhead)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				if i%batch == 0 && i != 0 {
					b.StopTimer()
					_, s = benchCiphers(b)
					b.StartTimer()
				}
				src := pkts[i%batch]
				buf := scratch[:len(src)]
				copy(buf, src)
				if _, err := s.Open(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
