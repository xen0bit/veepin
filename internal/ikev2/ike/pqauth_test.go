package ike

// pq-ikev2's two halves, tested where they can actually fail.
//
// The key-exchange half is a refusal, so the tests that matter are the negative
// ones: a classical initiator must be turned away rather than served. The
// authentication half is new cryptography on an existing wire format, and its
// dangerous failure is the mutually-consistent kind AGENTS.md names -- two
// veepin ends agreeing on a construction no third party would accept. The DER
// identifiers and the Identity hash are therefore pinned against the values
// crypto/x509 and the draft specify, not against what this package happens to
// emit.

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/vlog"
)

// mldsaKey is an ML-DSA signer for the AUTH tests.
func mldsaKey(t *testing.T, p mldsa.Parameters) crypto.Signer {
	t.Helper()
	k, err := mldsa.GenerateKey(p)
	if err != nil {
		t.Fatalf("generating %v: %v", p, err)
	}
	return k
}

// TestMLDSAAlgorithmIdentifiersHaveAbsentParameters is the byte-level guard.
//
// The RSA entries in knownSigAlgs are fifteen octets because they carry an
// explicit NULL parameters field. ML-DSA's parameters are ABSENT, making it
// thirteen. Copying the RSA shape produces an identifier no peer recognises,
// and because lookupSigAlg compares with bytes.Equal the failure is a clean
// "unrecognized signature AlgorithmIdentifier" rather than a bad signature --
// easy to misdiagnose as an interop problem in the peer.
//
// The expected bytes are derived here from crypto/x509's own certificates
// rather than copied from the draft, so this fails if the standard library and
// this table ever disagree about the encoding.
func TestMLDSAAlgorithmIdentifiersHaveAbsentParameters(t *testing.T) {
	cases := []struct {
		params mldsa.Parameters
		algID  []byte
		oid    string
	}{
		{mldsa.MLDSA44(), algMLDSA44, "2.16.840.1.101.3.4.3.17"},
		{mldsa.MLDSA65(), algMLDSA65, "2.16.840.1.101.3.4.3.18"},
		{mldsa.MLDSA87(), algMLDSA87, "2.16.840.1.101.3.4.3.19"},
	}
	for _, tc := range cases {
		if len(tc.algID) != 13 {
			t.Errorf("%v: AlgorithmIdentifier is %d octets, want 13 (parameters ABSENT, "+
				"not an explicit NULL like the RSA entries)", tc.params, len(tc.algID))
		}
		var got struct{ OID asn1.ObjectIdentifier }
		if _, err := asn1.Unmarshal(tc.algID, &got); err != nil {
			t.Errorf("%v: AlgorithmIdentifier does not parse: %v", tc.params, err)
			continue
		}
		if got.OID.String() != tc.oid {
			t.Errorf("%v: OID = %s, want %s", tc.params, got.OID, tc.oid)
		}

		// And the same bytes crypto/x509 would put in a certificate.
		key := mldsaKey(t, tc.params)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "pq"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatalf("%v: minting: %v", tc.params, err)
		}
		var outer asn1.RawValue
		if _, err := asn1.Unmarshal(der, &outer); err != nil {
			t.Fatal(err)
		}
		rest := outer.Bytes
		var tbs, alg asn1.RawValue
		rest, _ = asn1.Unmarshal(rest, &tbs)
		if _, err := asn1.Unmarshal(rest, &alg); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(alg.FullBytes, tc.algID) {
			t.Errorf("%v: our AlgorithmIdentifier %x differs from crypto/x509's %x",
				tc.params, tc.algID, alg.FullBytes)
		}
	}
}

// TestSigHashListAdvertisesTheIdentityHash is the one wire change with teeth.
// ML-DSA hashes the message itself, so a peer that never sees the Identity hash
// (RFC 9593, value 5) in SIGNATURE_HASH_ALGORITHMS will not select ML-DSA at
// all -- and the failure is a silent fallback to a classical scheme, which is
// exactly the downgrade pq-ikev2 exists to prevent.
func TestSigHashListAdvertisesTheIdentityHash(t *testing.T) {
	found := false
	for _, h := range sigHashList {
		if h == payload.HashIdentity {
			found = true
		}
	}
	if !found {
		t.Fatalf("sigHashList = %v, which omits the Identity hash (%d). "+
			"No conforming peer will choose ML-DSA.", sigHashList, payload.HashIdentity)
	}
	if payload.HashIdentity != 5 {
		t.Errorf("HashIdentity = %d, want 5 (RFC 9593)", payload.HashIdentity)
	}
}

// TestMLDSADigitalSignatureRoundTrip covers every parameter set through the
// real sign and verify paths, and asserts the negative: a signature over
// different octets must not verify. Without the negative half this would pass
// against an implementation that ignored the message entirely.
func TestMLDSADigitalSignatureRoundTrip(t *testing.T) {
	ca := newTestCA(t)
	octets := []byte("IKE_SA_INIT | Nr | prf(SKpi, IDi) | IntAuth")

	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			cred := ca.issue(t, "peer.example", mldsaKey(t, params))
			// A peer that accepts the Identity hash, as the draft requires.
			method, data, err := signAuthDigital(cred, octets, []uint16{payload.HashIdentity})
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if method != payload.AuthDigitalSig {
				t.Fatalf("method = %d, want %d (RFC 7427 Digital Signature)", method, payload.AuthDigitalSig)
			}
			if err := verifyAuthDigital(cred.signer.Public(), octets, data); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if err := verifyAuthDigital(cred.signer.Public(), append(octets, '!'), data); err == nil {
				t.Fatal("a signature verified over octets it was not made over")
			}
		})
	}
}

// TestMLDSASignaturesAreNotPreHashed is the mutually-consistent-bug guard for
// this feature.
//
// ML-DSA takes the MESSAGE. Pre-hashing it and signing the digest produces a
// signature that two veepin ends would agree on perfectly and that no other
// implementation would accept -- the same failure class as the Pulse ESP key
// direction. Asserting that the signature verifies against the raw octets
// through crypto/mldsa directly, rather than through our own verify path,
// is what makes this independent of the bug it is looking for.
func TestMLDSASignaturesAreNotPreHashed(t *testing.T) {
	ca := newTestCA(t)
	octets := []byte("the signed octets, verbatim")
	key := mldsaKey(t, mldsa.MLDSA65())
	cred := ca.issue(t, "peer.example", key)

	_, data, err := signAuthDigital(cred, octets, []uint16{payload.HashIdentity})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Strip the 1-octet length and the AlgorithmIdentifier to get the signature.
	algLen := int(data[0])
	sig := data[1+algLen:]

	pub, ok := key.Public().(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T", key.Public())
	}
	if err := mldsa.Verify(pub, octets, sig, &mldsa.Options{}); err != nil {
		t.Fatalf("crypto/mldsa rejects our signature over the raw octets: %v.\n"+
			"That means signAuthDigital pre-hashed them. Two veepin peers would still "+
			"agree with each other and no other implementation would interoperate.", err)
	}
}

// TestChooseSigAlgRefusesMLDSAWithoutTheIdentityHash: a peer advertising only
// SHA-2 cannot be sent an ML-DSA signature, and must produce a clean error
// rather than a signature it will reject.
func TestChooseSigAlgRefusesMLDSAWithoutTheIdentityHash(t *testing.T) {
	key := mldsaKey(t, mldsa.MLDSA65())
	if _, err := chooseSigAlg(key.Public(), []uint16{payload.HashSHA256, payload.HashSHA512}); err == nil {
		t.Fatal("chose an ML-DSA scheme for a peer that never said it accepts the Identity hash")
	}
	if _, err := chooseSigAlg(key.Public(), []uint16{payload.HashIdentity}); err != nil {
		t.Fatalf("refused ML-DSA for a peer that does accept the Identity hash: %v", err)
	}
}

// TestVerifyRejectsAFamilyMismatch: an AUTH payload naming ML-DSA must not be
// accepted against a classical key, or the algorithm identifier would be
// decorative.
func TestVerifyRejectsAFamilyMismatch(t *testing.T) {
	ca := newTestCA(t)
	octets := []byte("octets")

	mk := mldsaKey(t, mldsa.MLDSA65())
	mcred := ca.issue(t, "peer.example", mk)
	_, mdata, err := signAuthDigital(mcred, octets, []uint16{payload.HashIdentity})
	if err != nil {
		t.Fatal(err)
	}
	ec := ecKey(t, elliptic.P256())
	if err := verifyAuthDigital(ec.Public(), octets, mdata); err == nil {
		t.Fatal("an ML-DSA AUTH payload verified against an ECDSA key")
	}

	// And a parameter-set mismatch inside the family.
	other := mldsaKey(t, mldsa.MLDSA87())
	if err := verifyAuthDigital(other.Public(), octets, mdata); err == nil {
		t.Fatal("an ML-DSA-65 AUTH payload verified against an ML-DSA-87 key")
	}
}

// TestRequirePostQuantumRefusesAClassicalInitiator is the key-exchange half,
// and it is the whole value of the pq-ikev2 name: a client that simply omits
// the ADDKE transform must be turned away rather than quietly served a
// classical SA.
func TestRequirePostQuantumRefusesAClassicalInitiator(t *testing.T) {
	p500, p4500, srv := startPQTestServer(t)
	defer srv.Close()

	classical := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("test-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  vlog.Discard(),
		// PostQuantum deliberately unset.
	})
	if _, err := classical.Connect(); err == nil {
		classical.Close()
		t.Fatal("a classical initiator completed a handshake against a server requiring " +
			"post-quantum; the RequirePostQuantum reject path is not running")
	}
}

// TestRequirePostQuantumAcceptsAPostQuantumInitiator is the positive half, so a
// failure above can be attributed to the refusal rather than to the server
// being broken outright.
func TestRequirePostQuantumAcceptsAPostQuantumInitiator(t *testing.T) {
	p500, p4500, srv := startPQTestServer(t)
	defer srv.Close()

	c := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:         []byte("test-psk"),
		LocalID:     FQDNIdentity("client.example"),
		PostQuantum: true,
		Logger:      vlog.Discard(),
	})
	if _, err := c.Connect(); err != nil {
		t.Fatalf("a post-quantum initiator was refused: %v", err)
	}
	defer c.Close()
	if c.addkeGroup != payload.MLKEM768 {
		t.Fatal("the SA came up without ML-KEM-768, which the server was told to require")
	}
}

// startPQTestServer is startTestServer with RequirePostQuantum set. It is
// separate rather than a parameter so the existing callers stay untouched.
func startPQTestServer(t *testing.T) (p500, p4500 int, srv *Server) {
	t.Helper()
	p500, p4500 = freeUDPPort(t), freeUDPPort(t)
	srv, err := NewServer(Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		PSK:                []byte("test-psk"),
		LocalID:            FQDNIdentity("vpn.example"),
		PublicIP:           net.ParseIP("127.0.0.1"),
		Logger:             vlog.Discard(),
		RequirePostQuantum: true,
		AssignAddr: func(AddressRequest) (Assignment, error) {
			return Assignment{IP4: net.IPv4(10, 8, 8, 8), Netmask: net.IPv4(255, 255, 255, 0)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)
	return p500, p4500, srv
}

// TestRequirePostQuantumAuthRefusesEAP pins the EAP decision, which is a
// judgement rather than a consequence: EAP-MSCHAPv2 is symmetric and therefore
// not quantum-broken, and it is refused anyway because MD4 and single-DES are
// broken without needing a quantum computer.
func TestRequirePostQuantumAuthRefusesEAP(t *testing.T) {
	p500, p4500 := freeUDPPort(t), freeUDPPort(t)
	srv, err := NewServer(Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		PSK:      []byte("test-psk"),
		LocalID:  FQDNIdentity("vpn.example"),
		PublicIP: net.ParseIP("127.0.0.1"),
		Logger:   vlog.Discard(),

		RequirePostQuantum:     true,
		RequirePostQuantumAuth: true,
		EAPCredentials:         func(string) (string, bool) { return "pw", true },
		EAPServerName:          "vpn.example",
		AssignAddr: func(AddressRequest) (Assignment, error) {
			return Assignment{IP4: net.IPv4(10, 8, 8, 8), Netmask: net.IPv4(255, 255, 255, 0)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)

	c := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		LocalID:     FQDNIdentity("client.example"),
		EAPUsername: "alice",
		EAPPassword: "pw",
		PostQuantum: true,
		Logger:      vlog.Discard(),
	})
	if _, err := c.Connect(); err == nil {
		c.Close()
		t.Fatal("EAP-MSCHAPv2 succeeded against a server requiring post-quantum authentication")
	}
}

// TestPSKStillWorksUnderPostQuantumAuth is the other side of that judgement,
// and it is the one a reader is most likely to think is a bug.
//
// A pre-shared key is symmetric. It is not broken by a quantum adversary, which
// is the entire premise of RFC 8784 -- a specification that exists to give
// IKEv2 quantum resistance using exactly this property. Refusing PSK here would
// be applying the word "post-quantum" rather than the meaning.
func TestPSKStillWorksUnderPostQuantumAuth(t *testing.T) {
	p500, p4500 := freeUDPPort(t), freeUDPPort(t)
	srv, err := NewServer(Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		PSK:      []byte("test-psk"),
		LocalID:  FQDNIdentity("vpn.example"),
		PublicIP: net.ParseIP("127.0.0.1"),
		Logger:   vlog.Discard(),

		RequirePostQuantum:     true,
		RequirePostQuantumAuth: true,
		AssignAddr: func(AddressRequest) (Assignment, error) {
			return Assignment{IP4: net.IPv4(10, 8, 8, 8), Netmask: net.IPv4(255, 255, 255, 0)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)

	c := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:         []byte("test-psk"),
		LocalID:     FQDNIdentity("client.example"),
		PostQuantum: true,
		Logger:      vlog.Discard(),
	})
	if _, err := c.Connect(); err != nil {
		t.Fatalf("PSK authentication was refused under RequirePostQuantumAuth: %v.\n"+
			"A pre-shared key is symmetric and is not quantum-broken; see RFC 8784.", err)
	}
	c.Close()
}
