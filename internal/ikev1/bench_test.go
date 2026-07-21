package ikev1

import (
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// benchBytes returns n random bytes for benchmark inputs.
func benchBytes(b *testing.B, n int) []byte {
	b.Helper()
	p := make([]byte, n)
	if _, err := rand.Read(p); err != nil {
		b.Fatal(err)
	}
	return p
}

// benchPhase1 builds a phase1 key schedule with the negotiated defaults
// (HMAC-SHA2-256 PRF, a 256-octet MODP-2048 shared secret, AES-256 phase-1 key).
func benchPhase1(b *testing.B) *phase1 {
	b.Helper()
	prf, err := newPRF(hashSHA2256)
	if err != nil {
		b.Fatal(err)
	}
	ctor, err := hashCtor(hashSHA2256)
	if err != nil {
		b.Fatal(err)
	}
	var ckyI, ckyR [8]byte
	copy(ckyI[:], benchBytes(b, 8))
	copy(ckyR[:], benchBytes(b, 8))
	return derivePhase1(prf, ctor, benchBytes(b, 20), benchBytes(b, 16), benchBytes(b, 16),
		benchBytes(b, 256), ckyI, ckyR, 32)
}

// BenchmarkDerivePhase1 measures the Main Mode key schedule: SKEYID and the
// SKEYID_d/a/e family plus the phase-1 encryption key (RFC 2409 section 5). Four
// PRF invocations plus the key expansion, run once per handshake.
func BenchmarkDerivePhase1(b *testing.B) {
	prf, err := newPRF(hashSHA2256)
	if err != nil {
		b.Fatal(err)
	}
	ctor, err := hashCtor(hashSHA2256)
	if err != nil {
		b.Fatal(err)
	}
	psk := benchBytes(b, 20)
	ni, nr := benchBytes(b, 16), benchBytes(b, 16)
	dh := benchBytes(b, 256)
	var ckyI, ckyR [8]byte
	copy(ckyI[:], benchBytes(b, 8))
	copy(ckyR[:], benchBytes(b, 8))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = derivePhase1(prf, ctor, psk, ni, nr, dh, ckyI, ckyR, 32)
	}
}

// BenchmarkQuickModeKeymat measures Phase 2 ESP key derivation (RFC 2409 section
// 5.5): the KEYMAT expansion that yields one direction's AES-256 + HMAC-SHA2-256
// key material (64 octets).
func BenchmarkQuickModeKeymat(b *testing.B) {
	p := benchPhase1(b)
	spi := benchBytes(b, 4)
	ni, nr := benchBytes(b, 16), benchBytes(b, 16)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.keymat(3 /* ESP */, spi, ni, nr, 64)
	}
}

// BenchmarkHashI measures the initiator's authenticating hash HASH_I (RFC 2409
// section 5), a single PRF over the DH publics, cookies, SA and ID bodies.
func BenchmarkHashI(b *testing.B) {
	p := benchPhase1(b)
	gxi, gxr := benchBytes(b, 256), benchBytes(b, 256)
	var ckyI, ckyR [8]byte
	copy(ckyI[:], benchBytes(b, 8))
	copy(ckyR[:], benchBytes(b, 8))
	saBody, idBody := benchBytes(b, 48), benchBytes(b, 16)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.hashI(gxi, gxr, ckyI, ckyR, saBody, idBody)
	}
}

// BenchmarkPhase1CBC measures the AES-256-CBC encrypt/decrypt of a phase-1
// message body (the encrypted ID + HASH payloads), the per-message crypto of the
// Main Mode exchange.
func BenchmarkPhase1CBC(b *testing.B) {
	key := benchBytes(b, 32)
	iv := benchBytes(b, aesBlockSize)
	plaintext := benchBytes(b, 64)

	b.Run("encrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := cbcEncrypt(key, iv, plaintext); err != nil {
				b.Fatal(err)
			}
		}
	})

	ct, err := cbcEncrypt(key, iv, plaintext)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("decrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := cbcDecrypt(key, iv, ct); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkFullHandshakePSK measures a complete Main Mode + Quick Mode PSK
// exchange, initiator against responder in-process over channels. It is
// dominated by the two MODP-2048 exponentiations (~3.9 ms each; see the root
// README), which is the point: it shows the end-to-end per-connection cost and
// where it goes, mirroring the IKEv2 full-handshake benchmark.
func BenchmarkFullHandshakePSK(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		initCap := newCapture()
		respCap := newCapture()
		toResp := make(chan []byte, 32)
		toInit := make(chan []byte, 32)

		initiator := NewSession(Config{
			Role: Initiator, PSK: []byte("shared-secret"),
			LocalIP: net.IPv4(10, 0, 0, 2), PeerIP: net.IPv4(10, 0, 0, 1),
			LocalPort: 12345, PeerPort: ikePort,
			Send:    func(p []byte, _ bool) error { toResp <- p; return nil },
			Handler: initCap,
		})
		responder := NewSession(Config{
			Role: Responder, PSK: []byte("shared-secret"),
			LocalIP: net.IPv4(10, 0, 0, 1), PeerIP: net.IPv4(10, 0, 0, 2),
			LocalPort: ikePort, PeerPort: 12345,
			Send:    func(p []byte, _ bool) error { toInit <- p; return nil },
			Handler: respCap,
		})

		done := make(chan struct{})
		go pumpIKE(done, toResp, responder)
		go pumpIKE(done, toInit, initiator)

		initiator.Start()
		waitBench(b, initCap)
		waitBench(b, respCap)
		close(done)
	}
}

// waitBench blocks until a session establishes, failing the benchmark on error
// or timeout.
func waitBench(b *testing.B, c *capture) {
	b.Helper()
	select {
	case <-c.res:
	case err := <-c.fail:
		b.Fatalf("handshake failed: %v", err)
	case <-time.After(5 * time.Second):
		b.Fatal("handshake timed out")
	}
}
