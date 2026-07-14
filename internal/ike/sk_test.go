package ike

import (
	"bytes"
	"testing"

	"github.com/example/ikev2-go/internal/crypto"
	"github.com/example/ikev2-go/internal/payload"
)

// buildTestSuite returns a resolved suite for the given ENCR id.
func buildTestSuite(t testing.TB, encrID uint16) Suite {
	t.Helper()
	encr := payload.Transform{Type: payload.TransformENCR, ID: encrID, KeyLen: 256}
	prf := payload.Transform{Type: payload.TransformPRF, ID: payload.PRF_HMAC_SHA2_256}
	dh := payload.Transform{Type: payload.TransformDH, ID: payload.DH_CURVE25519}
	var integ payload.Transform
	if !isAEAD(encrID) {
		integ = payload.Transform{Type: payload.TransformINTEG, ID: payload.AUTH_HMAC_SHA2_256_128}
	}
	s, err := buildSuite(encr, prf, integ, dh)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func randomKeys(suite Suite) crypto.SAKeys {
	encLen := suite.encKeyLen()
	integLen := suite.integKeyLen()
	mk := func(n, seed int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(seed + i)
		}
		return b
	}
	return crypto.SAKeys{
		SKd:  mk(suite.PRF.Size, 1),
		SKai: mk(integLen, 2),
		SKar: mk(integLen, 3),
		SKei: mk(encLen, 4),
		SKer: mk(encLen, 5),
		SKpi: mk(suite.PRF.Size, 6),
		SKpr: mk(suite.PRF.Size, 7),
	}
}

// roundTripSK seals an inner chain as the responder would and reopens it,
// verifying the framing, AAD and padding all line up.
func roundTripSK(t *testing.T, encrID uint16) {
	suite := buildTestSuite(t, encrID)
	keys := randomKeys(suite)

	// Build an inner payload chain: IDr + AUTH.
	b := payload.NewBuilder()
	b.Add(payload.TypeIDr, false, payload.MarshalID(payload.IDPayload{
		Type: payload.IDFQDN, Data: []byte("responder.example"),
	}))
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: bytes.Repeat([]byte{0x5a}, 32),
	}))
	firstInner := b.FirstType()
	innerChain := b.Bytes()

	hdr := payload.Header{
		InitiatorSPI: 0x1111222233334444,
		ResponderSPI: 0x5555666677778888,
		ExchangeType: payload.IKE_AUTH,
		Flags:        payload.FlagResponse,
		MessageID:    1,
	}
	// Seal as responder (dirResponderToInitiator).
	pkt, err := buildEncryptedMessage(hdr, suite, keys, dirResponderToInitiator, firstInner, innerChain)
	if err != nil {
		t.Fatal(err)
	}

	// Parse and decrypt as the initiator would (inbound = responder->initiator).
	msg, err := payload.ParseMessage(pkt)
	if err != nil {
		t.Fatalf("parse sealed message: %v", err)
	}
	sk := msg.Find(payload.TypeSK)
	if sk == nil {
		t.Fatal("no SK payload in sealed message")
	}
	gotFirst, inner, err := decryptSK(pkt, msg.Header, *sk, suite, keys, dirResponderToInitiator)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if gotFirst != firstInner {
		t.Fatalf("first inner type = %s want %s", gotFirst, firstInner)
	}
	inners, err := parseInnerPayloads(gotFirst, inner)
	if err != nil {
		t.Fatalf("parse inner: %v", err)
	}
	if len(inners) != 2 || inners[0].Type != payload.TypeIDr || inners[1].Type != payload.TypeAUTH {
		t.Fatalf("inner payloads wrong: %+v", inners)
	}
	id, _ := payload.ParseID(inners[0].Body)
	if string(id.Data) != "responder.example" {
		t.Fatalf("IDr data wrong: %q", id.Data)
	}
}

func TestSKRoundTripGCM(t *testing.T) { roundTripSK(t, payload.ENCR_AES_GCM_16) }
func TestSKRoundTripCBC(t *testing.T) { roundTripSK(t, payload.ENCR_AES_CBC) }

// TestSKTamperRejected flips a ciphertext byte and confirms decryption fails.
func TestSKTamperRejected(t *testing.T) {
	suite := buildTestSuite(t, payload.ENCR_AES_GCM_16)
	keys := randomKeys(suite)
	b := payload.NewBuilder()
	b.Add(payload.TypeNonce, false, bytes.Repeat([]byte{1}, 20))
	pkt, err := buildEncryptedMessage(payload.Header{
		ExchangeType: payload.INFORMATIONAL, Flags: payload.FlagResponse, MessageID: 2,
	}, suite, keys, dirResponderToInitiator, b.FirstType(), b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	pkt[len(pkt)-1] ^= 0xff // corrupt the ICV (does not change any length field)
	msg, err := payload.ParseMessage(pkt)
	if err != nil {
		// Corruption broke framing; that is itself a valid rejection.
		return
	}
	sk := msg.Find(payload.TypeSK)
	if sk == nil {
		return
	}
	if _, _, err := decryptSK(pkt, msg.Header, *sk, suite, keys, dirResponderToInitiator); err == nil {
		t.Fatal("tampered SK payload was accepted")
	}
}
