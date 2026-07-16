package esp

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// benchSAPair builds a pair of ESP SAs sharing keys so that one can encapsulate
// and the other decapsulate. encrID/keyBits/integID select the ESP suite;
// integID is 0 for AEAD.
func benchSAPair(b *testing.B, encrID uint16, keyBits int, integID uint16) (send, recv *SA) {
	b.Helper()
	c, err := transform.Cipher(encrID, keyBits)
	if err != nil {
		b.Fatal(err)
	}
	encA := randKey(c.KeyLen())
	encB := randKey(c.KeyLen())

	var integKeyA, integKeyB []byte
	if integID != 0 {
		ig, err := transform.Integrity(integID)
		if err != nil {
			b.Fatal(err)
		}
		integKeyA = randKey(ig.KeyLen)
		integKeyB = randKey(ig.KeyLen)
	}

	mk := func(encKey, integKey []byte) Transform {
		return Transform{
			EncrID:    encrID,
			EncrKeyLn: uint16(keyBits),
			IntegID:   integID,
			EncKey:    encKey,
			IntegKey:  integKey,
		}
	}
	send = &SA{
		SPIOut: 0xbbbb, SPIIn: 0xaaaa,
		Out: mk(encA, integKeyA),
		In:  mk(encB, integKeyB),
	}
	recv = &SA{
		SPIOut: 0xaaaa, SPIIn: 0xbbbb,
		Out: mk(encB, integKeyB),
		In:  mk(encA, integKeyA),
	}
	return send, recv
}

func randKey(n int) []byte {
	k := make([]byte, n)
	_, _ = rand.Read(k)
	return k
}

// packet sizes representative of real traffic: a TCP ACK, a typical MTU-sized
// data packet, and a jumbo-ish payload.
var benchSizes = []int{64, 576, 1400}

func BenchmarkESPEncapsulate(b *testing.B) {
	suites := []struct {
		name    string
		encr    uint16
		keyBits int
		integ   uint16
	}{
		{"AES128-GCM", payload.ENCR_AES_GCM_16, 128, 0},
		{"AES256-GCM", payload.ENCR_AES_GCM_16, 256, 0},
		{"AES256-CBC-SHA256", payload.ENCR_AES_CBC, 256, payload.AUTH_HMAC_SHA2_256_128},
	}
	for _, s := range suites {
		for _, size := range benchSizes {
			b.Run(fmt.Sprintf("%s/%dB", s.name, size), func(b *testing.B) {
				send, _ := benchSAPair(b, s.encr, s.keyBits, s.integ)
				pkt := make([]byte, size)
				rand.Read(pkt)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := send.Encapsulate(pkt, 4); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkESPDecapsulate(b *testing.B) {
	suites := []struct {
		name    string
		encr    uint16
		keyBits int
		integ   uint16
	}{
		{"AES128-GCM", payload.ENCR_AES_GCM_16, 128, 0},
		{"AES256-GCM", payload.ENCR_AES_GCM_16, 256, 0},
		{"AES256-CBC-SHA256", payload.ENCR_AES_CBC, 256, payload.AUTH_HMAC_SHA2_256_128},
	}
	for _, s := range suites {
		for _, size := range benchSizes {
			b.Run(fmt.Sprintf("%s/%dB", s.name, size), func(b *testing.B) {
				send, recv := benchSAPair(b, s.encr, s.keyBits, s.integ)
				pkt := make([]byte, size)
				rand.Read(pkt)
				// Anti-replay would reject repeated sequence numbers, so we
				// decapsulate distinct packets by re-encapsulating each round.
				// To isolate decap cost we disable replay checking via a fresh
				// receiver each N is too costly; instead we pre-build a batch.
				const batch = 256
				encs := make([][]byte, batch)
				for i := range encs {
					e, err := send.Encapsulate(pkt, 4)
					if err != nil {
						b.Fatal(err)
					}
					encs[i] = e
				}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// Reset the receiver's replay window periodically so valid
					// packets are not rejected as replays during the benchmark.
					if i%batch == 0 {
						recv.ResetReplayWindow()
					}
					if _, _, err := recv.Decapsulate(encs[i%batch]); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkESPRoundTrip measures a full encapsulate+decapsulate cycle, i.e. the
// cost of moving one packet through both ends of the tunnel.
func BenchmarkESPRoundTrip(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("AES256-GCM/%dB", size), func(b *testing.B) {
			send, recv := benchSAPair(b, payload.ENCR_AES_GCM_16, 256, 0)
			pkt := make([]byte, size)
			rand.Read(pkt)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				enc, err := send.Encapsulate(pkt, 4)
				if err != nil {
					b.Fatal(err)
				}
				if i%256 == 0 {
					recv.ResetReplayWindow()
				}
				if _, _, err := recv.Decapsulate(enc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkESPDecapParallel measures aggregate decap throughput across cores,
// with an independent SA per goroutine (mirroring one SA pair per client). This
// reflects how a multi-client server scales on multiple cores.
func BenchmarkESPDecapParallel(b *testing.B) {
	const size = 1400
	inner := make([]byte, size)
	rand.Read(inner)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		send, recv := benchSAPair(b, payload.ENCR_AES_GCM_16, 256, 0)
		// Pre-build a batch of distinct packets for this goroutine.
		const batch = 256
		pkts := make([][]byte, batch)
		for i := range pkts {
			e, err := send.Encapsulate(inner, 4)
			if err != nil {
				b.Fatal(err)
			}
			pkts[i] = e
		}
		i := 0
		for pb.Next() {
			if i%batch == 0 {
				recv.ResetReplayWindow()
			}
			if _, _, err := recv.Decapsulate(pkts[i%batch]); err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}
