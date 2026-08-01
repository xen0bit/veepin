package keygen

// Tests for the key-material generators the management API drives from each
// protocol's OptSpec.Generate declarations. The generators are the panel's
// only way to produce a working listener without the operator hand-rolling
// keys, so each one is pinned twice: its outputs parse as what the protocol
// consumes, and a private half and its public half are mathematically
// consistent (a wrong keypair is silent -- the handshake fails, the interface
// never comes up, and there is no error anywhere).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestGenPSKReturnsHexKey(t *testing.T) {
	for _, key := range []string{"psk", "group-psk"} {
		kv, err := genPSK(key)
		if err != nil {
			t.Fatalf("genPSK(%q): %v", key, err)
		}
		v, ok := kv[key]
		if !ok {
			t.Fatalf("genPSK(%q) returned no %q key: %v", key, key, kv)
		}
		if len(v) != 64 { // 32 random bytes, hex-encoded
			t.Errorf("genPSK(%q) = %d chars, want 64", key, len(v))
		}
		if _, err := hex.DecodeString(v); err != nil {
			t.Errorf("genPSK(%q) is not hex: %v", key, err)
		}
	}
}

func TestGenWireGuardKeypairIsConsistent(t *testing.T) {
	kv, err := genWireGuardKeypair()
	if err != nil {
		t.Fatalf("genWireGuardKeypair: %v", err)
	}
	privB64, ok := kv["private-key"]
	if !ok {
		t.Fatalf("no private-key in %v", kv)
	}
	pubB64, ok := kv["public-key"]
	if !ok {
		// The public half is what the operator distributes to clients; a
		// generator that hides it is the whole defect this test exists for.
		t.Fatalf("no public-key in %v", kv)
	}
	priv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		t.Fatalf("private-key not base64: %v", err)
	}
	if len(priv) != 32 {
		t.Fatalf("private-key is %d bytes, want 32", len(priv))
	}
	// The clamped private key must produce exactly the returned public key.
	var privArr, pubArr, wantPub [32]byte
	copy(privArr[:], priv)
	curve25519.ScalarBaseMult(&pubArr, &privArr)
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("public-key not base64: %v", err)
	}
	copy(wantPub[:], pub)
	if wantPub != pubArr {
		t.Errorf("public-key does not match the private key")
	}
}

// TestWireGuardPublicKeyDerives pins the derive helper the management plane
// uses to recover a listener's server public key when only the private key is
// stored: WireGuardPublicKey(priv) must equal the generated public half.
func TestWireGuardPublicKeyDerives(t *testing.T) {
	priv, pub, err := WireGuardKeypair()
	if err != nil {
		t.Fatalf("WireGuardKeypair: %v", err)
	}
	got, err := WireGuardPublicKey(priv)
	if err != nil {
		t.Fatalf("WireGuardPublicKey: %v", err)
	}
	if got != pub {
		t.Errorf("WireGuardPublicKey = %q, want %q", got, pub)
	}
	for _, bad := range []string{"", "not-base64!!", "AAAAAAAA"} {
		if _, err := WireGuardPublicKey(bad); err == nil {
			t.Errorf("WireGuardPublicKey(%q) succeeded, want an error", bad)
		}
	}
}

func TestGenEd25519WritesAParseablePKCS8(t *testing.T) {
	dir := t.TempDir()
	kv, err := genEd25519(dir, "host-key")
	if err != nil {
		t.Fatalf("genEd25519: %v", err)
	}
	path := kv["host-key"]
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("not a PKCS#8 PEM private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing PKCS#8: %v", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok || len(ed) != ed25519.PrivateKeySize {
		t.Fatalf("parsed key is %T, want ed25519.PrivateKey", key)
	}
}

func TestGenTLSWritesAValidChain(t *testing.T) {
	dir := t.TempDir()
	kv, err := genTLS(dir)
	if err != nil {
		t.Fatalf("genTLS: %v", err)
	}
	assertCertKeyPair(t, kv["cert"], kv["key"])
	// The CA is written so the operator can distribute it, though only cert and
	// key are declared options.
	if _, err := os.Stat(filepath.Join(dir, "ca.crt")); err != nil {
		t.Errorf("ca.crt was not written: %v", err)
	}
}

func TestGenX509ChainWritesAValidChain(t *testing.T) {
	dir := t.TempDir()
	kv, err := genX509Chain(dir)
	if err != nil {
		t.Fatalf("genX509Chain: %v", err)
	}
	assertCertKeyPair(t, kv["cert"], kv["key"])
	if _, err := os.Stat(kv["ca"]); err != nil {
		t.Errorf("ca file missing: %v", err)
	}
	// The OpenVPN server cert must be signed by the returned CA, or stock
	// clients will refuse it. This is the interop-relevant consistency check.
	caPEM, _ := os.ReadFile(kv["ca"])
	caBlock, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing CA: %v", err)
	}
	certPEM, _ := os.ReadFile(kv["cert"])
	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing server cert: %v", err)
	}
	if err := cert.CheckSignatureFrom(ca); err != nil {
		t.Errorf("server cert is not signed by the generated CA: %v", err)
	}
}

// assertCertKeyPair pins the cert/key pair a TLS-ish generator produced: the
// key parses, and its public half matches the certificate's public key. A
// mismatched pair is silent at runtime -- every TLS client rejects the
// handshake and there is no error in the supervisor logs.
func assertCertKeyPair(t *testing.T, certPath, keyPath string) {
	t.Helper()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading cert %s: %v", certPath, err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("%s is not a PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing %s: %v", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading key %s: %v", keyPath, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatalf("%s is not PEM", keyPath)
	}
	var parsed any
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		t.Fatalf("%s has unexpected block type %q", keyPath, keyBlock.Type)
	}
	if err != nil {
		t.Fatalf("parsing %s: %v", keyPath, err)
	}
	var pub any
	switch k := parsed.(type) {
	case *ecdsa.PrivateKey:
		pub = k.Public()
	case ed25519.PrivateKey:
		pub = k.Public()
	}
	// Through the key's own Equal method. Comparing the interfaces with != is
	// always true here -- both sides hold *different allocations* of an
	// equivalent *ecdsa.PublicKey -- so a version that guarded this comparison
	// behind an interface inequality check was testing nothing.
	type publicKey interface{ Equal(crypto.PublicKey) bool }
	certPub, ok := cert.PublicKey.(publicKey)
	if !ok {
		t.Fatalf("cert %s carries a public key with no Equal method: %T", certPath, cert.PublicKey)
	}
	if !certPub.Equal(pub) {
		t.Errorf("cert %s public key does not match key %s", certPath, keyPath)
	}
}

// TestGeneratedKeyMaterialIsNotWorldReadable: these files are the listener's
// private keys, written by a supervisor running as root into a directory any
// local user can stat. The generators get it right today and nothing pinned it.
func TestGeneratedKeyMaterialIsNotWorldReadable(t *testing.T) {
	for _, c := range []struct {
		name string
		gen  func(dir string) (map[string]string, error)
	}{
		{"ed25519", func(dir string) (map[string]string, error) { return genEd25519(dir, "host-key") }},
		{"tls", genTLS},
		{"x509-chain", genX509Chain},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			kv, err := c.gen(dir)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			for key, path := range kv {
				fi, err := os.Stat(path)
				if err != nil {
					t.Fatalf("%s: %v", key, err)
				}
				if perm := fi.Mode().Perm(); perm&0o077 != 0 {
					t.Errorf("%s (%s) is mode %04o; key material must not be group- or world-readable", key, path, perm)
				}
			}
		})
	}
}

// TestGenerateOwnsItsListenerDirectoryTightly: Generate is what the management
// API calls, and it is the thing that creates the per-listener directory the
// files above land in. A 0755 directory hands the filenames -- and with them
// the fact that a listener exists and which protocol it runs -- to any local
// user, even where the files themselves are 0600.
func TestGenerateOwnsItsListenerDirectoryTightly(t *testing.T) {
	root := t.TempDir()
	if _, err := Generate("site-a", root, "tls", "cert"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	fi, err := os.Stat(filepath.Join(root, "site-a"))
	if err != nil {
		t.Fatalf("Generate did not create the listener directory: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("listener key directory is mode %04o, want 0700", perm)
	}
}

func TestGenerateUnknownTypeErrors(t *testing.T) {
	kv, err := Generate("site-a", t.TempDir(), "not-a-generator", "psk")
	if err == nil {
		t.Fatalf("Generate with an unknown type succeeded: %v", kv)
	}
	if !strings.Contains(err.Error(), "unknown generate type") {
		t.Errorf("error does not name the unknown type: %v", err)
	}
}
