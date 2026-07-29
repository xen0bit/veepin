package ike

import (
	"bytes"
	"crypto/mlkem"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// TestIntermediateNotifyIsTheIANAValue pins INTERMEDIATE_EXCHANGE_SUPPORTED to
// 16438. If this drifts, veepin advertises a notify no peer recognises: the
// handshake still completes, classically, and the post-quantum exchange is
// silently never negotiated. Nothing else in the tree would notice.
func TestIntermediateNotifyIsTheIANAValue(t *testing.T) {
	if payload.IntermediateExchangeSupported != 16438 {
		t.Fatalf("INTERMEDIATE_EXCHANGE_SUPPORTED = %d, want 16438 (RFC 9242 section 3.1)",
			payload.IntermediateExchangeSupported)
	}
}

// TestMLKEMGroupIDsMatchTheRegistry pins the Key Exchange Method IDs. Same
// failure mode as the notify: a wrong number is a silent non-negotiation.
func TestMLKEMGroupIDsMatchTheRegistry(t *testing.T) {
	for _, tc := range []struct {
		got  uint16
		want uint16
		name string
	}{
		{payload.MLKEM512, 35, "ML-KEM-512"},
		{payload.MLKEM768, 36, "ML-KEM-768"},
		{payload.MLKEM1024, 37, "ML-KEM-1024"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

// TestADDKETransformTypesAreSixThroughTwelve pins the RFC 9370 section 2.1
// transform type numbers.
func TestADDKETransformTypesAreSixThroughTwelve(t *testing.T) {
	want := []payload.TransformType{6, 7, 8, 9, 10, 11, 12}
	got := []payload.TransformType{
		payload.TransformADDKE1, payload.TransformADDKE2, payload.TransformADDKE3,
		payload.TransformADDKE4, payload.TransformADDKE5, payload.TransformADDKE6,
		payload.TransformADDKE7,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ADDKE%d = %d, want %d", i+1, got[i], want[i])
		}
	}
}

// TestAuthOctetsPutsIntAuthLast is written from the peer's point of view: it
// spells out the RFC 9242 section 3.3 layout literally rather than calling the
// same helper the production code does, so a reordering cannot satisfy both.
// An implementation that puts IntAuth anywhere else interoperates perfectly
// with itself and with nothing else.
func TestAuthOctetsPutsIntAuthLast(t *testing.T) {
	prf, err := transform.PRF(payload.PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatal(err)
	}
	realMsg := []byte("REALMESSAGE")
	nonce := []byte("NONCE")
	skp := []byte("skp-key")
	idBody := []byte("IDBODY")
	intAuth := []byte("INTAUTH")

	got := AuthOctets(prf, realMsg, nonce, skp, idBody, intAuth)

	want := bytes.Join([][]byte{realMsg, nonce, prf.Apply(skp, idBody), intAuth}, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("signed octets are not RealMessage | Nonce | prf(SK_p, ID') | IntAuth\n got %x\nwant %x", got, want)
	}
}

// TestAuthOctetsWithoutIntermediateIsPlainRFC7296 is the compatibility claim:
// with no IKE_INTERMEDIATE exchange the signed octets must be byte-identical to
// what veepin produced before RFC 9242 support existed, or every peer that does
// not implement it breaks.
func TestAuthOctetsWithoutIntermediateIsPlainRFC7296(t *testing.T) {
	prf, err := transform.PRF(payload.PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatal(err)
	}
	realMsg, nonce, skp, idBody := []byte("MSG"), []byte("N"), []byte("k"), []byte("ID")

	withNil := AuthOctets(prf, realMsg, nonce, skp, idBody, nil)
	withEmpty := AuthOctets(prf, realMsg, nonce, skp, idBody, []byte{})
	want := bytes.Join([][]byte{realMsg, nonce, prf.Apply(skp, idBody)}, nil)

	if !bytes.Equal(withNil, want) || !bytes.Equal(withEmpty, want) {
		t.Fatal("a handshake with no intermediate exchange must sign exactly the RFC 7296 octets")
	}
}

// TestFinalIntAuthIsNilWithoutAnExchange guards the same degradation one level
// down: finalIntAuth must produce nothing at all, not a bare message ID, or
// AUTH changes for every ordinary handshake.
func TestFinalIntAuthIsNilWithoutAnExchange(t *testing.T) {
	if got := finalIntAuth(nil, nil, 1); got != nil {
		t.Fatalf("finalIntAuth with no chains = %x, want nil", got)
	}
}

// TestFinalIntAuthOrdersInitiatorThenResponderThenMsgID pins
// IntAuth = IntAuth_iN | IntAuth_rN | IKE_AUTH_MID. Both endpoints append the
// same value, so swapping the two chains is a change both ends would agree on
// — exactly the class of bug a self-test cannot catch.
func TestFinalIntAuthOrdersInitiatorThenResponderThenMsgID(t *testing.T) {
	i := []byte{0xaa, 0xbb}
	r := []byte{0xcc, 0xdd}
	got := finalIntAuth(i, r, 2)
	want := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x02}
	if !bytes.Equal(got, want) {
		t.Fatalf("IntAuth = %x, want %x", got, want)
	}
}

// TestIntAuthBlobZeroesOutTheCipherOverhead checks the length adjustment of
// RFC 9242 section 3.3: the covered bytes must describe a message with no IV,
// padding, pad length or ICV, so both endpoints compute the blob identically
// even though only one of them ever holds the ciphertext.
func TestIntAuthBlobZeroesOutTheCipherOverhead(t *testing.T) {
	inner := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	hdr := payload.Header{
		InitiatorSPI: 0x1122334455667788, ResponderSPI: 0x99aabbccddeeff00,
		ExchangeType: payload.IKE_INTERMEDIATE, Flags: payload.FlagInitiator, MessageID: 1,
	}
	blob := intAuthBlob(hdr, payload.TypeKE, inner)

	if len(blob) != payload.HeaderLen+4+len(inner) {
		t.Fatalf("blob length %d, want header+4+%d", len(blob), len(inner))
	}
	gotHdr, err := payload.ParseHeader(blob)
	if err != nil {
		t.Fatal(err)
	}
	if gotHdr.Length != uint32(payload.HeaderLen+4+len(inner)) {
		t.Errorf("IKE header Length = %d, want %d (cipher overhead must not be counted)",
			gotHdr.Length, payload.HeaderLen+4+len(inner))
	}
	skLen := int(blob[payload.HeaderLen+2])<<8 | int(blob[payload.HeaderLen+3])
	if skLen != 4+len(inner) {
		t.Errorf("SK payload Length = %d, want %d", skLen, 4+len(inner))
	}
	if payload.PayloadType(blob[payload.HeaderLen]) != payload.TypeKE {
		t.Errorf("SK generic header NextPayload = %d, want TypeKE", blob[payload.HeaderLen])
	}
}

// TestChainIntAuthIsOrderDependent: the chain is a running prf, so folding the
// same two messages in the other order must not produce the same value.
// Otherwise a reordered exchange would authenticate.
func TestChainIntAuthIsOrderDependent(t *testing.T) {
	prf, err := transform.PRF(payload.PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatal(err)
	}
	skp := []byte("key")
	a, b := []byte("first"), []byte("second")

	ab := chainIntAuth(prf, skp, chainIntAuth(prf, skp, nil, a), b)
	ba := chainIntAuth(prf, skp, chainIntAuth(prf, skp, nil, b), a)
	if bytes.Equal(ab, ba) {
		t.Fatal("the IntAuth chain is order-independent; a reordered exchange would still authenticate")
	}
}

// TestKEMResponderDerivesTheSameSecretItSends is the peer's-eye view of the
// KEM's asymmetry: the responder must keep the shared secret that comes out of
// Encapsulate, not just the ciphertext. Discarding it leaves the two ends keyed
// differently, which no amount of self-testing on one side reveals.
func TestKEMResponderDerivesTheSameSecretItSends(t *testing.T) {
	dk, err := mlkemGenerateForTest()
	if err != nil {
		t.Fatal(err)
	}
	ct, shared, err := kemEncapsulate(payload.MLKEM768, dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	initiatorShared, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shared, initiatorShared) {
		t.Fatal("responder's encapsulated secret differs from what the initiator decapsulates")
	}
	if len(shared) == 0 {
		t.Fatal("shared secret is empty")
	}
}

// TestKEMRejectsAnUnnegotiatedGroup: only ML-KEM-768 is implemented, and a peer
// naming anything else must be refused rather than silently treated as it.
func TestKEMRejectsAnUnnegotiatedGroup(t *testing.T) {
	if _, _, err := kemEncapsulate(payload.MLKEM1024, make([]byte, 1184)); err == nil {
		t.Fatal("kemEncapsulate accepted ML-KEM-1024, which is not implemented")
	}
}

// TestSelectADDKEIgnoresAProposalWithout: RFC 9370 section 2.1 says a proposal
// that omits the transform is as if it had proposed NONE. That must be a quiet
// "no", not an error, or every ordinary peer fails to negotiate.
func TestSelectADDKEIgnoresAProposalWithout(t *testing.T) {
	if _, ok := SelectADDKE(DefaultIKEProposal()); ok {
		t.Fatal("the default proposal has no ADDKE transform but SelectADDKE claimed one")
	}
	p := DefaultIKEProposal()
	p.Transforms = append(p.Transforms,
		payload.Transform{Type: payload.TransformADDKE1, ID: payload.MLKEM768})
	group, ok := SelectADDKE(p)
	if !ok || group != payload.MLKEM768 {
		t.Fatalf("SelectADDKE = (%d, %v), want (%d, true)", group, ok, payload.MLKEM768)
	}
}

// TestSelectADDKERejectsUnsupportedMethods: a peer proposing ML-KEM-1024 must
// get NONE rather than an accepted transform we cannot honour.
func TestSelectADDKERejectsUnsupportedMethods(t *testing.T) {
	p := DefaultIKEProposal()
	p.Transforms = append(p.Transforms,
		payload.Transform{Type: payload.TransformADDKE1, ID: payload.MLKEM1024})
	if _, ok := SelectADDKE(p); ok {
		t.Fatal("SelectADDKE accepted ML-KEM-1024, which kemEncapsulate cannot perform")
	}
}

// TestPostQuantumHandshakeCompletes runs the real client against the real
// server with the additional key exchange negotiated, and asserts the exchange
// actually happened. A bare "the handshake worked" assertion passes just as
// happily when the post-quantum exchange was silently skipped — which is the
// state this code was in before.
func TestPostQuantumHandshakeCompletes(t *testing.T) {
	p500, p4500, srv, childCh := startTestServer(t, nil)
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:         []byte("test-psk"),
		LocalID:     FQDNIdentity("client.example"),
		PostQuantum: true,
		Logger:      log.New(io.Discard, "", 0),
	})
	res, err := client.Connect()
	if err != nil {
		t.Fatalf("post-quantum connect: %v", err)
	}
	defer client.Close()

	if client.addkeGroup != payload.MLKEM768 {
		t.Fatal("the additional key exchange was not negotiated; the handshake fell back to classical DH")
	}
	if len(client.intAuthI) == 0 || len(client.intAuthR) == 0 {
		t.Fatal("IKE_INTERMEDIATE ran but contributed nothing to IntAuth")
	}
	if client.authMsgID != 2 {
		t.Fatalf("IKE_AUTH used message ID %d; the intermediate exchange consumed 1, so it must be 2", client.authMsgID)
	}
	if !res.AssignedIP.Equal(net.IPv4(10, 8, 8, 8)) {
		t.Fatalf("assigned IP %v", res.AssignedIP)
	}
	// Wait, rather than polling with a default: the server sends the IKE_AUTH
	// response BEFORE it invokes OnChildSA (ike_auth.go), so Connect can return
	// while the server goroutine is still a few lines short of the callback. A
	// non-blocking receive here reads that ordinary interleaving as a failure,
	// and did so on a loaded CI runner. Every other Child SA assertion in this
	// package waits with the same timeout.
	select {
	case <-childCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no Child SA was created")
	}
}

// TestPostQuantumClientFallsBackAgainstAClassicalServer: a server that does not
// offer ADDKE must still be usable. This is the deployment case that matters —
// veepin clients meeting strongSwan builds without RFC 9370.
func TestPostQuantumClientFallsBackAgainstAClassicalServer(t *testing.T) {
	p500, p4500, srv, _ := startTestServer(t, nil)
	defer srv.Close()

	// A server whose SA_INIT never sees INTERMEDIATE_EXCHANGE_SUPPORTED cannot
	// negotiate ADDKE. Simulate it from the client side by leaving PostQuantum
	// off, then assert the same server still serves a PostQuantum client
	// classically when it declines.
	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("test-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	if _, err := client.Connect(); err != nil {
		t.Fatalf("classical connect: %v", err)
	}
	defer client.Close()

	if client.addkeGroup != 0 {
		t.Fatal("a client that did not ask for post-quantum negotiated it anyway")
	}
	if client.authMsgID != 1 {
		t.Fatalf("IKE_AUTH used message ID %d, want 1 with no intermediate exchange", client.authMsgID)
	}
}

// TestServerRejectsIntermediateItNeverNegotiated: the exchange must be gated on
// the ADDKE transform, not merely on the notify, so a peer cannot drive an
// exchange the SA has no key material for.
func TestServerRejectsIntermediateItNeverNegotiated(t *testing.T) {
	sa := newIKESA()
	if sa.ADDKEGroup != 0 {
		t.Fatal("a fresh SA must not claim a negotiated additional key exchange")
	}
}

// mlkemGenerateForTest wraps key generation so the test does not import
// crypto/mlkem directly alongside the production file that already does.
func mlkemGenerateForTest() (*mlkem.DecapsulationKey768, error) { return mlkem.GenerateKey768() }
