package nebula

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/xen0bit/veepin/internal/replay"
)

// benchTunnel builds a tunnel whose send and receive keys are the same, so a
// packet it encrypts it can also decrypt — enough to exercise the data-path
// crypto without a handshake.
func benchTunnel(tb testing.TB, c noiseCipher) *tunnel {
	tb.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		tb.Fatal(err)
	}
	send, err := c.aead(key)
	if err != nil {
		tb.Fatal(err)
	}
	recv, err := c.aead(key)
	if err != nil {
		tb.Fatal(err)
	}
	return &tunnel{
		cipher:      c,
		send:        send,
		recv:        recv,
		remoteIndex: 0x01020304,
		window:      replay.New(),
	}
}

// benchPayload is a stand-in inner IP packet of n bytes.
func benchPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

var benchSizes = []int{64, 576, 1400}

// TestDataPathAllocations pins the per-packet allocation counts the data path was
// tuned to: encrypt allocates once (the returned packet), decrypt not at all (it
// decrypts in place with a per-tunnel nonce scratch). It guards against a change
// that reintroduces the nonce heap-escape or drops the in-place Open.
func TestDataPathAllocations(t *testing.T) {
	for _, c := range []struct {
		name   string
		cipher noiseCipher
	}{{"aesgcm", cipherAESGCM}, {"chachapoly", cipherChaChaPoly}} {
		t.Run(c.name, func(t *testing.T) {
			enc := benchTunnel(t, c.cipher)
			payload := benchPayload(1400)

			if n := testing.AllocsPerRun(100, func() {
				_ = enc.encrypt(typeMessage, subTypeNone, payload)
			}); n > 1 {
				t.Errorf("encrypt allocates %.0f times per packet, want 1", n)
			}

			// Pre-seal a batch with distinct, increasing counters so each decrypt is
			// a fresh packet the replay window accepts.
			const batch = 4096
			batchPkts := make([][]byte, batch)
			for i := range batchPkts {
				batchPkts[i] = enc.encrypt(typeMessage, subTypeNone, payload)
			}
			dec := benchTunnel(t, c.cipher)
			dec.recv = enc.send
			scratch := make([]byte, len(batchPkts[0]))
			i := 0
			if n := testing.AllocsPerRun(batch-1, func() {
				buf := scratch[:len(batchPkts[i])]
				copy(buf, batchPkts[i])
				i++
				if _, _, err := dec.decrypt(buf); err != nil {
					t.Fatalf("decrypt: %v", err)
				}
			}); n > 0 {
				t.Errorf("decrypt allocates %.0f times per packet, want 0", n)
			}
		})
	}
}

func BenchmarkNebulaEncrypt(b *testing.B) {
	for _, c := range []struct {
		name   string
		cipher noiseCipher
	}{{"aesgcm", cipherAESGCM}, {"chachapoly", cipherChaChaPoly}} {
		for _, size := range benchSizes {
			b.Run(fmt.Sprintf("%s/%d", c.name, size), func(b *testing.B) {
				t := benchTunnel(b, c.cipher)
				payload := benchPayload(size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = t.encrypt(typeMessage, subTypeNone, payload)
				}
			})
		}
	}
}

func BenchmarkNebulaDecrypt(b *testing.B) {
	for _, c := range []struct {
		name   string
		cipher noiseCipher
	}{{"aesgcm", cipherAESGCM}, {"chachapoly", cipherChaChaPoly}} {
		for _, size := range benchSizes {
			b.Run(fmt.Sprintf("%s/%d", c.name, size), func(b *testing.B) {
				enc := benchTunnel(b, c.cipher)
				payload := benchPayload(size)

				// Pre-seal a batch with the distinct, increasing counters the replay
				// window accepts, so each decrypt sees a fresh packet.
				batch := make([][]byte, 4096)
				for i := range batch {
					batch[i] = enc.encrypt(typeMessage, subTypeNone, payload)
				}

				dec := benchTunnel(b, c.cipher)
				dec.recv = enc.send // decrypt what enc sealed
				scratch := make([]byte, len(batch[0]))

				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					pkt := batch[i%len(batch)]
					buf := scratch[:len(pkt)]
					copy(buf, pkt)
					if _, _, err := dec.decrypt(buf); err != nil {
						// Cycling past the batch replays counters; reset the window so
						// the measured work stays the successful decrypt path.
						dec.window = replay.New()
					}
				}
			})
		}
	}
}
