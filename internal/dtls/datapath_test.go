package dtls

import (
	"crypto/rand"
	"fmt"
	"testing"
)

// benchAEAD builds an aeadState with a random AES-128-GCM key and salt — the
// record-layer cipher an established DTLS connection uses.
func benchAEAD(tb testing.TB) *aeadState {
	tb.Helper()
	key := make([]byte, 16)
	salt := make([]byte, 4)
	if _, err := rand.Read(key); err != nil {
		tb.Fatal(err)
	}
	if _, err := rand.Read(salt); err != nil {
		tb.Fatal(err)
	}
	a, err := newAEAD(key, salt)
	if err != nil {
		tb.Fatal(err)
	}
	return a
}

func dtlsPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

var dtlsSizes = []int{64, 576, 1400}

// TestRecordAllocations pins the record-layer allocation counts: seal produces
// one buffer (the returned record payload), open decrypts in place and allocates
// nothing. It guards against reintroducing the nonce/additional-data heap escapes
// or the separate sealed buffer and copy that seal used to make.
func TestRecordAllocations(t *testing.T) {
	a := benchAEAD(t)
	payload := dtlsPayload(1400)

	if n := testing.AllocsPerRun(100, func() {
		_ = a.seal(recordApplicationData, version1_2, 1, 7, payload)
	}); n > 1 {
		t.Errorf("seal allocates %.0f times per record, want 1", n)
	}

	const batch = 4096
	sealed := make([][]byte, batch)
	for i := range sealed {
		sealed[i] = a.seal(recordApplicationData, version1_2, 1, uint64(i), payload)
	}
	scratch := make([]byte, len(sealed[0]))
	i := 0
	if n := testing.AllocsPerRun(batch-1, func() {
		buf := scratch[:len(sealed[i])]
		copy(buf, sealed[i])
		if _, err := a.open(recordApplicationData, version1_2, 1, uint64(i), buf); err != nil {
			t.Fatal(err)
		}
		i++
	}); n > 0 {
		t.Errorf("open allocates %.0f times per record, want 0", n)
	}
}

func BenchmarkRecordSeal(b *testing.B) {
	for _, size := range dtlsSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			a := benchAEAD(b)
			payload := dtlsPayload(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = a.seal(recordApplicationData, version1_2, 1, uint64(i), payload)
			}
		})
	}
}

func BenchmarkRecordOpen(b *testing.B) {
	for _, size := range dtlsSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			a := benchAEAD(b)
			payload := dtlsPayload(size)

			const batch = 4096
			sealed := make([][]byte, batch)
			for i := range sealed {
				sealed[i] = a.seal(recordApplicationData, version1_2, 1, uint64(i), payload)
			}
			scratch := make([]byte, len(sealed[0]))

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				j := i % batch
				buf := scratch[:len(sealed[j])]
				copy(buf, sealed[j])
				if _, err := a.open(recordApplicationData, version1_2, 1, uint64(j), buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
