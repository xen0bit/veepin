package pqpolicy

// These tests exist because the whole variant scheme rests on one claim -- that
// a pq- name REFUSES what a base name would accept -- and a claim about a
// refusal is only worth what its negative tests are worth. Every test here
// drives a real handshake and asserts the failure, rather than reading back a
// field of the config that was just set.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// mint builds a self-signed credential, post-quantum or classical, plus the
// pool that verifies it.
func mint(t *testing.T, pq bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pq.example.com"},
		DNSNames:              []string{"pq.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	var pub, priv any
	if pq {
		k, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			t.Fatalf("generating ML-DSA-65: %v", err)
		}
		pub, priv = k.PublicKey(), k
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating P-256: %v", err)
		}
		pub, priv = &k.PublicKey, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, pool
}

// handshake runs one TLS exchange over a pipe and returns the client's error.
//
// The deadlines are what make this safe, and the reason is worth stating
// because the failure it prevents is a hang rather than a wrong answer.
// net.Pipe is unbuffered and fully synchronous: a Write blocks until the far
// side Reads it. When the client rejects the server's certificate it stops
// reading the server's flight and tries to write an alert -- while the server
// is still blocked writing that flight. Neither side is reading, both are
// writing, and the test hangs until the package timeout rather than failing.
//
// A deadline turns that into an ordinary I/O error. The alert write fails,
// crypto/tls discards that error and returns the verification error it already
// had, and the assertion sees what it came for.
func handshake(t *testing.T, srv, cli *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	c, s := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = c.SetDeadline(deadline)
	_ = s.SetDeadline(deadline)

	done := make(chan struct{})
	go func() { defer close(done); _ = tls.Server(s, srv).Handshake() }()

	conn := tls.Client(c, cli)
	err := conn.Handshake()
	state := conn.ConnectionState()

	c.Close()
	s.Close()
	<-done
	return state, err
}

// TestHardenedServerRefusesAClassicalKeyExchange is the contract's key-exchange
// half. A client offering only X25519 must fail, and it must fail rather than
// negotiate down -- which is exactly the outcome that would be invisible if the
// test asserted on the config instead of on the handshake.
func TestHardenedServerRefusesAClassicalKeyExchange(t *testing.T) {
	cert, pool := mint(t, true)
	srv := &tls.Config{Certificates: []tls.Certificate{cert}}
	HardenTLS(srv)

	_, err := handshake(t, srv, &tls.Config{
		RootCAs: pool, ServerName: "pq.example.com",
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})
	if err == nil {
		t.Fatal("a classical-only client completed a handshake against a pq- server; " +
			"the key exchange floor is not being enforced")
	}
}

// TestHardenedServerRefusesTLS12 covers the version floor separately, because
// a 1.2 peer fails for a different reason -- there is no key_share at all --
// and an implementation could plausibly get one right and the other wrong.
func TestHardenedServerRefusesTLS12(t *testing.T) {
	cert, pool := mint(t, true)
	srv := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	HardenTLS(srv)
	if srv.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3: HardenTLS must raise a 1.2 floor", srv.MinVersion)
	}

	_, err := handshake(t, srv, &tls.Config{
		RootCAs: pool, ServerName: "pq.example.com",
		MaxVersion: tls.VersionTLS12,
	})
	if err == nil {
		t.Fatal("a TLS 1.2 client completed a handshake against a pq- server")
	}
}

// TestHardenedClientRefusesAClassicalServerCertificate is the authentication
// half, and it is the one that distinguishes this contract from "hybrid key
// exchange". The server here has a perfectly good ECDSA certificate and a
// post-quantum key exchange; the connection must still be refused.
func TestHardenedClientRefusesAClassicalServerCertificate(t *testing.T) {
	cert, pool := mint(t, false) // classical credential
	cli := &tls.Config{RootCAs: pool, ServerName: "pq.example.com"}
	HardenTLS(cli)

	_, err := handshake(t, &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
	}, cli)
	if err == nil {
		t.Fatal("a pq- client accepted an ECDSA server certificate; the authentication " +
			"half of the contract is not enforced")
	}
	if !errors.Is(err, ErrClassicalPeer) {
		t.Errorf("error = %v, want one wrapping ErrClassicalPeer", err)
	}
}

// TestHardenedPeersCompleteBothHalves is the positive case, and it asserts both
// halves at once. Either alone is a handshake that is half classical.
func TestHardenedPeersCompleteBothHalves(t *testing.T) {
	cert, pool := mint(t, true)
	srv := &tls.Config{Certificates: []tls.Certificate{cert}}
	HardenTLS(srv)
	cli := &tls.Config{RootCAs: pool, ServerName: "pq.example.com"}
	HardenTLS(cli)

	st, err := handshake(t, srv, cli)
	if err != nil {
		t.Fatalf("two pq- peers failed to handshake: %v", err)
	}
	if st.CurveID != tls.X25519MLKEM768 {
		t.Errorf("key exchange = %v, want X25519MLKEM768", st.CurveID)
	}
	if len(st.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
	if got := st.PeerCertificates[0].PublicKeyAlgorithm; got != x509.MLDSA {
		t.Errorf("peer certificate = %v, want ML-DSA", got)
	}
}

// TestHardenTLSKeepsAnExistingVerifier pins that hardening TIGHTENS a config.
// Discarding a facade's own VerifyPeerCertificate while claiming to strengthen
// the connection would be a downgrade wearing an upgrade's name.
func TestHardenTLSKeepsAnExistingVerifier(t *testing.T) {
	sentinel := errors.New("the facade's own verifier ran")
	cfg := &tls.Config{VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
		return sentinel
	}}
	HardenTLS(cfg)
	if err := cfg.VerifyPeerCertificate(nil, nil); !errors.Is(err, sentinel) {
		t.Fatalf("existing verifier lost: got %v, want %v", err, sentinel)
	}
}

// TestCheckCredentialRejectsClassicalAtConstruction is what makes the failure
// land in NewServer rather than in the first client's handshake.
func TestCheckCredentialRejectsClassicalAtConstruction(t *testing.T) {
	classical, _ := mint(t, false)
	if err := CheckCredential(classical); !errors.Is(err, ErrClassicalCredential) {
		t.Errorf("classical credential accepted: %v", err)
	}
	pq, _ := mint(t, true)
	if err := CheckCredential(pq); err != nil {
		t.Errorf("ML-DSA credential rejected: %v", err)
	}
}

// TestCheckCredentialParsesWhenLeafIsAbsent covers the path a facade takes when
// it built the tls.Certificate itself rather than through X509KeyPair, which
// leaves Leaf nil.
func TestCheckCredentialParsesWhenLeafIsAbsent(t *testing.T) {
	pq, _ := mint(t, true)
	if err := CheckCredential(tls.Certificate{Certificate: pq.Certificate}); err != nil {
		t.Errorf("ML-DSA credential with a nil Leaf rejected: %v", err)
	}
	if err := CheckCredential(tls.Certificate{}); !errors.Is(err, ErrClassicalCredential) {
		t.Error("an empty credential was accepted")
	}
}

// TestRequireMLDSALeafAcceptsAnAbsentChain pins the deliberate hole, so that a
// later reader does not "fix" it. A server that asks for no client certificate
// is authenticating by password inside the post-quantum channel.
func TestRequireMLDSALeafAcceptsAnAbsentChain(t *testing.T) {
	if err := RequireMLDSALeaf(nil, nil); err != nil {
		t.Fatalf("an absent peer chain was rejected: %v", err)
	}
}

// TestForceRefusesAContradiction is the operator-facing refusal: a variant may
// not silently overrule an explicit choice.
func TestForceRefusesAContradiction(t *testing.T) {
	_, err := Force("pq-anyconnect", map[string]string{"no-dtls": "false"},
		map[string]string{"no-dtls": "true"})
	if err == nil {
		t.Fatal("an explicit -no-dtls=false was silently overridden")
	}
	if !strings.Contains(err.Error(), "no-dtls") {
		t.Errorf("error does not name the option: %v", err)
	}

	// Agreement is not conflict.
	out, err := Force("pq-anyconnect", map[string]string{"no-dtls": "true"},
		map[string]string{"no-dtls": "true"})
	if err != nil {
		t.Fatalf("agreeing with the forced value was rejected: %v", err)
	}
	if !Requested(out) {
		t.Error("Force did not set the post-quantum marker")
	}
}

// TestForceDoesNotMutateItsInput matters because the caller's map is the
// operator's parsed options, reused by the supervisor across restarts.
func TestForceDoesNotMutateItsInput(t *testing.T) {
	in := map[string]string{"user": "alice"}
	if _, err := Force("pq-sstp", in, nil); err != nil {
		t.Fatalf("Force: %v", err)
	}
	if _, leaked := in[OptKey]; leaked {
		t.Error("Force mutated the caller's options map")
	}
}

// TestCurvesAreAllPostQuantum is the guard against a well-meaning addition. Every
// entry must be a mechanism with a post-quantum component; adding P-256 here
// because "it is widely supported" would silently reopen the floor.
func TestCurvesAreAllPostQuantum(t *testing.T) {
	pq := map[tls.CurveID]bool{
		tls.X25519MLKEM768: true, tls.SecP256r1MLKEM768: true,
		tls.SecP384r1MLKEM1024: true, tls.MLKEM1024: true,
	}
	got := Curves()
	if len(got) == 0 {
		t.Fatal("Curves() is empty, which would make every pq- handshake fail")
	}
	for _, c := range got {
		if !pq[c] {
			t.Errorf("Curves() includes %v, which has no post-quantum component", c)
		}
	}
}

// TestCurvesDoesNotShareItsBacking catches the aliasing bug where one facade's
// append reaches another facade's config.
func TestCurvesDoesNotShareItsBacking(t *testing.T) {
	a, b := Curves(), Curves()
	a[0] = tls.X25519
	if b[0] == tls.X25519 {
		t.Fatal("Curves() hands out a shared backing array")
	}
}

// TestSSHIsTheOnlyPQAuthException holds the exception table at one entry, so a
// second exemption has to be argued for rather than added.
func TestSSHIsTheOnlyPQAuthException(t *testing.T) {
	if len(SSHKeyExchangeOnly) != 1 {
		t.Fatalf("the key-exchange-only exception table has %d entries, want 1: %v",
			len(SSHKeyExchangeOnly), SSHKeyExchangeOnly)
	}
	reason, ok := KeyExchangeOnly("pq-ssh")
	if !ok {
		t.Fatal("pq-ssh is not in the exception table")
	}
	if !strings.Contains(reason, "openssh.org/pq") {
		t.Errorf("the exemption reason should cite upstream's own statement: %q", reason)
	}
	if _, ok := KeyExchangeOnly("pq-ikev2"); ok {
		t.Error("pq-ikev2 is exempt from post-quantum authentication, which it must not be")
	}
}

// TestDescribeNamesTheExemption keeps the startup log honest: an operator
// running pq-ssh should see that its authentication is classical without
// reading doc/security.md.
func TestDescribeNamesTheExemption(t *testing.T) {
	if got := Describe("pq-ssh"); !strings.Contains(got, "classical") {
		t.Errorf("pq-ssh's description hides its exemption: %q", got)
	}
	if got := Describe("pq-ikev2"); strings.Contains(got, "authentication is classical") {
		t.Errorf("pq-ikev2's description claims an exemption it does not have: %q", got)
	}
}
