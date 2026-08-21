package nebula

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"
)

// The vectors below were produced by github.com/flynn/noise v1.1.0 — the same
// library nebula uses — configured exactly as nebula configures it, with
// deterministic keys:
//
//	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
//	noise.NewHandshakeState(noise.Config{
//	    CipherSuite: cs, Pattern: noise.HandshakeIX,
//	    StaticKeypair: ..., PresharedKey: []byte{}, PresharedKeyPlacement: 0,
//	})
//
// veepin cannot depend on that library, so the vectors are pinned here instead.
// This is the test that would have caught the psk0 misreading described in
// noise.go: an implementation built against Noise_IXpsk0 seeds its handshake
// hash from a different protocol name and diverges from the very first message.
const (
	katInitStaticPriv = "1111111111111111111111111111111111111111111111111111111111111111"
	katInitStaticPub  = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
	katRespStaticPriv = "2222222222222222222222222222222222222222222222222222222222222222"
	katRespStaticPub  = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"

	katInitEphemeral = "3333333333333333333333333333333333333333333333333333333333333333"
	katRespEphemeral = "4444444444444444444444444444444444444444444444444444444444444444"

	katMsg1 = "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14" +
		"7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13" +
		"7061796c6f61642d6f6e65"
	katMsg2 = "ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b" +
		"57908fe2f35731026652fe0a000b8cd6b153fa7e240f329ff233e6331fc49b1e" +
		"a8fd1214816df64dd73c5d2390ab1b2f" +
		"34dff6413fd1d84e3909be3ee6b717ee0c5c55e7f621150026dbb1"

	katPayload1 = "payload-one"
	katPayload2 = "payload-two"

	// The transport keys are pinned by what they produce: each side's first
	// record over a known plaintext with an empty AD.
	katInitSendCT = "b3c8bf09c8769561e41b70500e5965d256d60ec1a42e"
	katInitRecvCT = "f88e86e2093b480b79303f83cf3887c86ce51bea821a"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding hex: %v", err)
	}
	return b
}

func mustX25519(t *testing.T, hexKey string) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(mustDecodeHex(t, hexKey))
	if err != nil {
		t.Fatalf("building X25519 key: %v", err)
	}
	return k
}

// The ephemeral keys are handed in whole rather than as an entropy source. That
// used to be a fixedReader feeding ecdh.GenerateKey, which stopped working at a
// go.mod floor of 1.26: cryptocustomrand makes crypto APIs ignore the reader, so
// the "fixed" ephemeral key was silently random and these vectors failed. The
// vectors themselves are unchanged -- only the seam moved.

func TestNoiseIXKnownAnswer(t *testing.T) {
	ini := newNoiseHandshake(cipherAESGCM, true, mustX25519(t, katInitStaticPriv))
	res := newNoiseHandshake(cipherAESGCM, false, mustX25519(t, katRespStaticPriv))

	initEph := mustX25519(t, katInitEphemeral)
	respEph := mustX25519(t, katRespEphemeral)

	msg1, err := ini.WriteMessage1([]byte(katPayload1), initEph)
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	if want := mustDecodeHex(t, katMsg1); !bytes.Equal(msg1, want) {
		t.Fatalf("message 1 diverges from the reference\n got: %x\nwant: %x", msg1, want)
	}

	gotPayload1, err := res.ReadMessage1(msg1)
	if err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}
	if string(gotPayload1) != katPayload1 {
		t.Errorf("payload 1 = %q, want %q", gotPayload1, katPayload1)
	}
	if want := mustDecodeHex(t, katInitStaticPub); !bytes.Equal(res.PeerStatic(), want) {
		t.Errorf("responder read initiator static %x, want %x", res.PeerStatic(), want)
	}

	msg2, err := res.WriteMessage2([]byte(katPayload2), respEph)
	if err != nil {
		t.Fatalf("WriteMessage2: %v", err)
	}
	if want := mustDecodeHex(t, katMsg2); !bytes.Equal(msg2, want) {
		t.Fatalf("message 2 diverges from the reference\n got: %x\nwant: %x", msg2, want)
	}

	gotPayload2, err := ini.ReadMessage2(msg2)
	if err != nil {
		t.Fatalf("ReadMessage2: %v", err)
	}
	if string(gotPayload2) != katPayload2 {
		t.Errorf("payload 2 = %q, want %q", gotPayload2, katPayload2)
	}
	if want := mustDecodeHex(t, katRespStaticPub); !bytes.Equal(ini.PeerStatic(), want) {
		t.Errorf("initiator read responder static %x, want %x", ini.PeerStatic(), want)
	}

	// Transport keys are checked through the records they produce.
	iSend, iRecv := ini.Split()
	rSend, rRecv := res.Split()
	if iSend != rRecv || iRecv != rSend {
		t.Fatal("the two sides derived mismatched transport keys")
	}

	if got := sealWith(t, iSend, 0, []byte("i-to-r")); !bytes.Equal(got, mustDecodeHex(t, katInitSendCT)) {
		t.Errorf("initiator send key diverges\n got: %x\nwant: %s", got, katInitSendCT)
	}
	if got := sealWith(t, iRecv, 0, []byte("r-to-i")); !bytes.Equal(got, mustDecodeHex(t, katInitRecvCT)) {
		t.Errorf("initiator receive key diverges\n got: %x\nwant: %s", got, katInitRecvCT)
	}
}

func sealWith(t *testing.T, key [keySize]byte, n uint64, pt []byte) []byte {
	t.Helper()
	aead, err := cipherAESGCM.aead(key[:])
	if err != nil {
		t.Fatalf("building AEAD: %v", err)
	}
	return aead.Seal(nil, cipherAESGCM.nonce(n), pt, nil)
}

// The IX pattern sends the initiator's static key unencrypted in the first
// message; a responder relies on that to find the peer's certificate before
// doing any asymmetric work. If this ever stops being true, the host map lookup
// in the handshake path breaks.
func TestNoiseIXFirstMessageExposesInitiatorStatic(t *testing.T) {
	ini := newNoiseHandshake(cipherAESGCM, true, mustX25519(t, katInitStaticPriv))
	msg1, err := ini.WriteMessage1(nil, mustX25519(t, katInitEphemeral))
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	want := mustDecodeHex(t, katInitStaticPub)
	if !bytes.Equal(msg1[keySize:2*keySize], want) {
		t.Errorf("static key is not in the clear at the expected offset")
	}
}

func TestNoiseRoundTripBothCiphers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cipher noiseCipher
	}{
		{"AESGCM", cipherAESGCM},
		{"ChaChaPoly", cipherChaChaPoly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ini := newNoiseHandshake(tc.cipher, true, mustX25519(t, katInitStaticPriv))
			res := newNoiseHandshake(tc.cipher, false, mustX25519(t, katRespStaticPriv))

			msg1, err := ini.WriteMessage1([]byte("one"), mustX25519(t, katInitEphemeral))
			if err != nil {
				t.Fatalf("WriteMessage1: %v", err)
			}
			if _, err := res.ReadMessage1(msg1); err != nil {
				t.Fatalf("ReadMessage1: %v", err)
			}
			msg2, err := res.WriteMessage2([]byte("two"), mustX25519(t, katRespEphemeral))
			if err != nil {
				t.Fatalf("WriteMessage2: %v", err)
			}
			if _, err := ini.ReadMessage2(msg2); err != nil {
				t.Fatalf("ReadMessage2: %v", err)
			}

			iSend, iRecv := ini.Split()
			rSend, rRecv := res.Split()
			if iSend != rRecv || iRecv != rSend {
				t.Fatal("mismatched transport keys")
			}
		})
	}
}

func TestNoiseRejectsTamperedMessage2(t *testing.T) {
	ini := newNoiseHandshake(cipherAESGCM, true, mustX25519(t, katInitStaticPriv))
	res := newNoiseHandshake(cipherAESGCM, false, mustX25519(t, katRespStaticPriv))

	msg1, err := ini.WriteMessage1(nil, mustX25519(t, katInitEphemeral))
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	if _, err := res.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}
	msg2, err := res.WriteMessage2([]byte("two"), mustX25519(t, katRespEphemeral))
	if err != nil {
		t.Fatalf("WriteMessage2: %v", err)
	}

	// Flipping a bit in the encrypted static key must fail authentication
	// rather than yield a different peer identity.
	tampered := append([]byte(nil), msg2...)
	tampered[keySize] ^= 0x01
	if _, err := ini.ReadMessage2(tampered); err == nil {
		t.Fatal("accepted a handshake message with a corrupted static key")
	}
}

func TestNoiseRejectsShortMessages(t *testing.T) {
	res := newNoiseHandshake(cipherAESGCM, false, mustX25519(t, katRespStaticPriv))
	if _, err := res.ReadMessage1(make([]byte, keySize)); err == nil {
		t.Error("accepted a truncated first message")
	}

	ini := newNoiseHandshake(cipherAESGCM, true, mustX25519(t, katInitStaticPriv))
	if _, err := ini.WriteMessage1(nil, mustX25519(t, katInitEphemeral)); err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	if _, err := ini.ReadMessage2(make([]byte, keySize)); err == nil {
		t.Error("accepted a truncated second message")
	}
}

// TestNilEphemeralGeneratesAFreshKey: production passes nil, and the seam that
// lets a test pin the ephemeral key must not become a way to accidentally reuse
// one. Two handshakes built the same way have to disagree about their first 32
// octets, which is the ephemeral public key in the clear.
func TestNilEphemeralGeneratesAFreshKey(t *testing.T) {
	first, err := newNoiseHandshake(cipherAESGCM, true, mustX25519(t, katInitStaticPriv)).
		WriteMessage1(nil, nil)
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	second, err := newNoiseHandshake(cipherAESGCM, true, mustX25519(t, katInitStaticPriv)).
		WriteMessage1(nil, nil)
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	if bytes.Equal(first[:keySize], second[:keySize]) {
		t.Fatal("two handshakes shared an ephemeral public key; nil must mean generate")
	}
}

// TestPinnedEphemeralIsTheKeyThatGoesOnTheWire is the regression guard for the
// bug this seam was reshaped to prevent. When crypto APIs ignored the caller's
// io.Reader (Go 1.26 cryptocustomrand), a "fixed" ephemeral key was silently
// random and only the known-answer vectors noticed. Asserting the pinned key
// reaches the wire directly means a future change cannot quietly drop it.
func TestPinnedEphemeralIsTheKeyThatGoesOnTheWire(t *testing.T) {
	eph := mustX25519(t, katInitEphemeral)
	msg, err := newNoiseHandshake(cipherAESGCM, true, mustX25519(t, katInitStaticPriv)).
		WriteMessage1(nil, eph)
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	if got, want := msg[:keySize], eph.PublicKey().Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("ephemeral on the wire = %x, want the pinned key %x", got, want)
	}
}
