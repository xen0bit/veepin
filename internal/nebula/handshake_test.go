package nebula

import (
	"bytes"
	"crypto/ecdh"
	"net/netip"
	"testing"
	"time"
)

// The fixtures were signed with a ten-year CA; pinning a time inside that
// window keeps these tests from becoming a time bomb.
var fixtureTime = time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)

func loadIdentity(t *testing.T, certFile, keyFile string) *Identity {
	t.Helper()
	c := loadFixtureCert(t, certFile)
	raw, err := UnmarshalX25519PrivateKeyPEM(readFixture(t, keyFile))
	if err != nil {
		t.Fatalf("reading %s: %v", keyFile, err)
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatalf("building key from %s: %v", keyFile, err)
	}
	id, err := NewIdentity(c, key)
	if err != nil {
		t.Fatalf("building identity: %v", err)
	}
	return id
}

func testConfig(t *testing.T, certFile, keyFile string) *handshakeConfig {
	t.Helper()
	pool, err := NewCAPoolFromPEM(readFixture(t, "ca.crt"))
	if err != nil {
		t.Fatalf("building CA pool: %v", err)
	}
	return &handshakeConfig{
		cipher:   cipherAESGCM,
		identity: loadIdentity(t, certFile, keyFile),
		pool:     pool,
		now:      func() time.Time { return fixtureTime },
	}
}

// runHandshake drives a complete exchange between two configs.
func runHandshake(t *testing.T, initCfg, respCfg *handshakeConfig) (initTun, respTun *tunnel) {
	t.Helper()

	pending, msg1, err := initCfg.initiate()
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	msg2, respTun, err := respCfg.respond(msg1)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	initTun, err = pending.complete(msg2)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	return initTun, respTun
}

func TestHandshakeEstablishesTunnel(t *testing.T) {
	initCfg := testConfig(t, "host-a.crt", "host-a.key")
	respCfg := testConfig(t, "host-b.crt", "host-b.key")

	initTun, respTun := runHandshake(t, initCfg, respCfg)

	// Each side must learn the address the *certificate* vouches for, not one
	// the peer asserted. That is the whole point of the identity model.
	if got, want := initTun.PeerAddr(), netip.MustParseAddr("10.42.0.2"); got != want {
		t.Errorf("initiator sees peer address %v, want %v", got, want)
	}
	if got, want := respTun.PeerAddr(), netip.MustParseAddr("10.42.0.1"); got != want {
		t.Errorf("responder sees peer address %v, want %v", got, want)
	}
	if initTun.peerCert.Name != "host-b" {
		t.Errorf("initiator peer name = %q, want host-b", initTun.peerCert.Name)
	}
	if respTun.peerCert.Name != "host-a" {
		t.Errorf("responder peer name = %q, want host-a", respTun.peerCert.Name)
	}

	// The indexes must be crossed over: what one side calls local, the other
	// addresses as remote.
	if initTun.localIndex != respTun.remoteIndex || respTun.localIndex != initTun.remoteIndex {
		t.Errorf("tunnel indexes do not correspond: init(local=%d remote=%d) resp(local=%d remote=%d)",
			initTun.localIndex, initTun.remoteIndex, respTun.localIndex, respTun.remoteIndex)
	}
}

func TestDataPathRoundTrip(t *testing.T) {
	initTun, respTun := runHandshake(t,
		testConfig(t, "host-a.crt", "host-a.key"),
		testConfig(t, "host-b.crt", "host-b.key"))

	for i, payload := range [][]byte{
		[]byte("first"),
		[]byte("second"),
		bytes.Repeat([]byte{0xab}, 1300), // a full-size inner packet
		{},
	} {
		pkt := initTun.encrypt(typeMessage, subTypeNone, payload)

		h, got, err := respTun.decrypt(pkt)
		if err != nil {
			t.Fatalf("packet %d: decrypt: %v", i, err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("packet %d: payload = %x, want %x", i, got, payload)
		}
		if h.Type != typeMessage {
			t.Errorf("packet %d: type = %v, want message", i, h.Type)
		}
		if h.RemoteIndex != respTun.localIndex {
			t.Errorf("packet %d: remote index = %d, want %d", i, h.RemoteIndex, respTun.localIndex)
		}
	}

	// And the reverse direction, which uses the other key.
	pkt := respTun.encrypt(typeMessage, subTypeNone, []byte("reply"))
	got, err := func() ([]byte, error) {
		_, p, err := initTun.decrypt(pkt)
		return p, err
	}()
	if err != nil {
		t.Fatalf("reverse decrypt: %v", err)
	}
	if string(got) != "reply" {
		t.Errorf("reverse payload = %q, want reply", got)
	}
}

// Data traffic must start after the counters the handshake consumed, or the
// replay window will treat the first real packets as duplicates.
func TestDataCountersStartAfterHandshake(t *testing.T) {
	initTun, _ := runHandshake(t,
		testConfig(t, "host-a.crt", "host-a.key"),
		testConfig(t, "host-b.crt", "host-b.key"))

	pkt := initTun.encrypt(typeMessage, subTypeNone, []byte("x"))
	h, err := parseHeader(pkt)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if h.MessageCounter != handshakeMessageCount+1 {
		t.Errorf("first data counter = %d, want %d", h.MessageCounter, handshakeMessageCount+1)
	}
}

// The header is passed to the AEAD as additional data, so altering any of it
// must fail authentication rather than take effect.
func TestHeaderIsAuthenticated(t *testing.T) {
	initTun, respTun := runHandshake(t,
		testConfig(t, "host-a.crt", "host-a.key"),
		testConfig(t, "host-b.crt", "host-b.key"))

	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"type", func(p []byte) { p[0] = headerVersion<<4 | byte(typeLightHouse) }},
		{"subtype", func(p []byte) { p[1] ^= 0xff }},
		{"remote index", func(p []byte) { p[4] ^= 0xff }},
		{"counter", func(p []byte) { p[15] ^= 0xff }},
		{"ciphertext", func(p []byte) { p[headerLen] ^= 0xff }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := initTun.encrypt(typeMessage, subTypeNone, []byte("payload"))
			tc.mutate(pkt)
			if _, _, err := respTun.decrypt(pkt); err == nil {
				t.Errorf("accepted a packet with an altered %s", tc.name)
			}
		})
	}
}

func TestReplayRejected(t *testing.T) {
	initTun, respTun := runHandshake(t,
		testConfig(t, "host-a.crt", "host-a.key"),
		testConfig(t, "host-b.crt", "host-b.key"))

	pkt := initTun.encrypt(typeMessage, subTypeNone, []byte("once"))
	if _, _, err := respTun.decrypt(pkt); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if _, _, err := respTun.decrypt(pkt); err == nil {
		t.Fatal("accepted a replayed packet")
	}
}

// UDP reorders, so packets arriving out of order within the window must still
// be accepted -- a strictly increasing counter check would drop real traffic.
func TestOutOfOrderWithinWindowAccepted(t *testing.T) {
	initTun, respTun := runHandshake(t,
		testConfig(t, "host-a.crt", "host-a.key"),
		testConfig(t, "host-b.crt", "host-b.key"))

	var pkts [][]byte
	for range 8 {
		pkts = append(pkts, initTun.encrypt(typeMessage, subTypeNone, []byte("x")))
	}

	// Deliver the last one first, then the rest in order.
	if _, _, err := respTun.decrypt(pkts[7]); err != nil {
		t.Fatalf("delivering the newest packet first: %v", err)
	}
	for i := range 7 {
		if _, _, err := respTun.decrypt(pkts[i]); err != nil {
			t.Errorf("packet %d arriving late was rejected: %v", i, err)
		}
	}
}

func TestHandshakeRejectsUntrustedCA(t *testing.T) {
	initCfg := testConfig(t, "host-a.crt", "host-a.key")
	respCfg := testConfig(t, "host-b.crt", "host-b.key")

	// A responder that trusts nothing must not accept a well-formed peer.
	respCfg.pool = NewCAPool()

	_, msg1, err := initCfg.initiate()
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if _, _, err := respCfg.respond(msg1); err == nil {
		t.Fatal("responder accepted a peer signed by an untrusted CA")
	}
}

func TestHandshakeRejectsExpiredPeer(t *testing.T) {
	initCfg := testConfig(t, "host-a.crt", "host-a.key")
	respCfg := testConfig(t, "host-b.crt", "host-b.key")
	// Judge the peer far outside its validity window.
	respCfg.now = func() time.Time { return time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC) }

	_, msg1, err := initCfg.initiate()
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if _, _, err := respCfg.respond(msg1); err == nil {
		t.Fatal("responder accepted an expired certificate")
	}
}

// A peer must not be able to send a certificate that still carries its public
// key: the key Noise authenticated is the one the signature has to cover, and
// accepting a supplied key would decouple the two.
func TestHandshakeRejectsCertificateCarryingPublicKey(t *testing.T) {
	cfg := testConfig(t, "host-b.crt", "host-b.key")
	peer := loadFixtureCert(t, "host-a.crt")

	if _, err := cfg.verifyPeer(peer.Marshal(), peer.PublicKey); err == nil {
		t.Fatal("accepted a handshake certificate that carried its public key")
	}
}

// Substituting someone else's certificate while keying with your own static key
// is the attack the elide-and-restore step exists to stop.
func TestHandshakeRejectsSubstitutedCertificate(t *testing.T) {
	cfg := testConfig(t, "host-b.crt", "host-b.key")

	victim := loadFixtureCert(t, "host-a.crt")
	attackerKey := loadIdentity(t, "host-b.crt", "host-b.key").Key.PublicKey().Bytes()

	// The victim's certificate, but keyed by the attacker's static key.
	if _, err := cfg.verifyPeer(victim.MarshalForHandshakes(), attackerKey); err == nil {
		t.Fatal("accepted a certificate that does not match the authenticated static key")
	}
}

func TestNewIdentityRejectsMismatchedKey(t *testing.T) {
	certA := loadFixtureCert(t, "host-a.crt")
	rawB, err := UnmarshalX25519PrivateKeyPEM(readFixture(t, "host-b.key"))
	if err != nil {
		t.Fatalf("reading host-b key: %v", err)
	}
	keyB, err := ecdh.X25519().NewPrivateKey(rawB)
	if err != nil {
		t.Fatalf("building key: %v", err)
	}
	if _, err := NewIdentity(certA, keyB); err == nil {
		t.Fatal("paired a certificate with the wrong private key")
	}
}

func TestHandshakePayloadRoundTrip(t *testing.T) {
	want := handshakePayload{
		Cert:           []byte("certificate-bytes"),
		InitiatorIndex: 0xdeadbeef,
		ResponderIndex: 0x01020304,
		Time:           1_700_000_000_000_000_000,
		CertVersion:    certVersion1,
	}
	got, err := parseHandshakePayload(want.marshal())
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if !bytes.Equal(got.Cert, want.Cert) || got.InitiatorIndex != want.InitiatorIndex ||
		got.ResponderIndex != want.ResponderIndex || got.Time != want.Time ||
		got.CertVersion != want.CertVersion {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	want := header{
		Version:        headerVersion,
		Type:           typeLightHouse,
		Subtype:        subTypeTestReply,
		RemoteIndex:    0xcafebabe,
		MessageCounter: 0x0102030405060708,
	}
	got, err := parseHeader(want.encode(nil))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}

	if _, err := parseHeader(make([]byte, headerLen-1)); err == nil {
		t.Error("accepted a datagram shorter than the header")
	}
}

// The replay window itself is tested in internal/replay, which nebula and toy
// now share -- they had byte-for-byte the same implementation. The behaviour it
// guarantees is exercised end-to-end here by TestReplayRejected and
// TestOutOfOrderWithinWindowAccepted, which is the level that matters for this
// package.
