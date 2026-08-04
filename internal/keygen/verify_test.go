package keygen

// The test the package did not have: does a generated chain verify?
//
// Everything around it was checked -- the files exist, the modes are 0600, the
// leaf is signed by the CA -- and the one property a certificate has to have
// was not. A leaf with no subjectAltName verifies against nothing, because Go
// dropped the Common Name fallback in 1.15, so the panel's one-click generate
// produced a chain that could not be used by any client that checks the name.
// Which is all of them.

import (
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// loadChain returns the CA pool and the parsed leaf for a generated chain.
func loadChain(t *testing.T, dir string, kv map[string]string, caFile string) (*x509.CertPool, *x509.Certificate) {
	t.Helper()
	caPath := kv["ca"]
	if caPath == "" {
		caPath = filepath.Join(dir, caFile)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("reading the CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the CA file is not a certificate")
	}
	pair, err := tls.LoadX509KeyPair(kv["cert"], kv["key"])
	if err != nil {
		t.Fatalf("the cert and key are not a pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parsing the leaf: %v", err)
	}
	return pool, leaf
}

// TestGeneratedChainVerifiesForTheNamesItWasAskedFor is the claim the whole
// generator exists to make: a client holding the CA can verify the server it
// dialled. Before the SANs were added this failed with "certificate is not
// valid for any names", for every protocol that generates TLS material --
// anyconnect, fortinet, gp, masque, pulse, softether, sstp and openvpn.
func TestGeneratedChainVerifiesForTheNamesItWasAskedFor(t *testing.T) {
	for _, c := range []struct {
		gen    string
		caFile string
	}{{"tls", "ca.crt"}, {"x509-chain", "ca.crt"}} {
		t.Run(c.gen, func(t *testing.T) {
			root := t.TempDir()
			hostnames := []string{"vpn.example.com", "10.0.0.5"}
			kv, err := Generate("site-a", root, c.gen, "cert", hostnames)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			pool, leaf := loadChain(t, filepath.Join(root, "site-a"), kv, c.caFile)

			for _, name := range hostnames {
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name}); err != nil {
					t.Errorf("a client dialling %q cannot verify this server: %v", name, err)
				}
			}
			// And a name it was not asked for is still refused -- SANs that
			// verified anything would be no better than none.
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "not-this-one.example"}); err == nil {
				t.Error("the certificate verifies for a name it does not carry")
			}
		})
	}
}

// TestDefaultHostnamesCoverTheLoopbackFlow: an operator who names nothing gets
// a certificate that works on the machine they generated it on. That is the
// out-of-the-box path -- generate on a laptop, dial 127.0.0.1 -- and if it did
// not verify the first thing anyone tried would fail.
func TestDefaultHostnamesCoverTheLoopbackFlow(t *testing.T) {
	root := t.TempDir()
	kv, err := Generate("site-a", root, "tls", "cert", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pool, leaf := loadChain(t, filepath.Join(root, "site-a"), kv, "ca.crt")
	for _, name := range []string{"localhost", "127.0.0.1", "::1", "site-a"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name}); err != nil {
			t.Errorf("the default certificate does not cover %q: %v", name, err)
		}
	}
}

// TestSerialNumbersAreRandom: the serials were the constants 1 and 2, on every
// host, for every listener and every regeneration. Two listeners on one box
// then produced distinct certificates sharing an issuer DN and a serial, which
// is exactly the pair a CRL and most trust stores key on.
func TestSerialNumbersAreRandom(t *testing.T) {
	root := t.TempDir()
	seen := map[string]bool{}
	for _, name := range []string{"site-a", "site-b"} {
		kv, err := Generate(name, root, "x509-chain", "cert", nil)
		if err != nil {
			t.Fatalf("Generate %s: %v", name, err)
		}
		_, leaf := loadChain(t, filepath.Join(root, name), kv, "ca.crt")
		caPEM, _ := os.ReadFile(kv["ca"])
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)

		for what, serial := range map[string]*big.Int{"leaf": leaf.SerialNumber} {
			if serial.Cmp(big.NewInt(1000)) < 0 {
				t.Errorf("%s %s serial is %v, which is a counter, not a random 128-bit value", name, what, serial)
			}
			if seen[serial.String()] {
				t.Errorf("%s %s reuses serial %v", name, what, serial)
			}
			seen[serial.String()] = true
		}
	}
}

// TestLeafIsConformant pins the three template properties that a strict
// validator checks and a permissive one does not, so the next person to touch
// the template finds out here rather than from a peer's error message.
func TestLeafIsConformant(t *testing.T) {
	root := t.TempDir()
	kv, err := Generate("site-a", root, "tls", "cert", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_, leaf := loadChain(t, filepath.Join(root, "site-a"), kv, "ca.crt")

	if !leaf.BasicConstraintsValid {
		t.Error("the leaf carries no basicConstraints extension; RFC 5280 4.2.1.9 wants one on a CA-issued cert")
	}
	if leaf.IsCA {
		t.Error("the leaf claims to be a CA")
	}
	if leaf.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("KeyEncipherment is an RSA key-transport usage and this is an ECDSA key")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("the leaf cannot sign, which is the one usage an ECDSA server cert needs")
	}
	// Backdated, so a client whose clock is a few seconds slow does not reject
	// a certificate minted moments ago as not-yet-valid.
	if !leaf.NotBefore.Before(time.Now().Add(-time.Minute)) {
		t.Errorf("NotBefore is %v, not backdated against clock skew", leaf.NotBefore)
	}
}

// TestGenerateRefusesANameThatIsNotOneWeCouldHaveWritten: Generate is exported
// and joins the name into a path. The management API validates before calling
// it, but the package cannot rely on that, and confstore.Delete makes the same
// check for the same reason.
func TestGenerateRefusesANameThatIsNotOneWeCouldHaveWritten(t *testing.T) {
	for _, name := range []string{"../escape", "mgmt", "profiles", "Site-A", ""} {
		if _, err := Generate(name, t.TempDir(), "tls", "cert", nil); err == nil {
			t.Errorf("Generate accepted the name %q", name)
		}
	}
}

// TestEveryGeneratorReturnsEveryFileItWrote: genTLS wrote ca.crt and returned
// only cert and key, so the file an operator has to distribute existed on disk
// with its path reported nowhere -- not in the create response, not in the
// config, not in the bundle.
func TestEveryGeneratorReturnsEveryFileItWrote(t *testing.T) {
	for _, gen := range []string{"tls", "x509-chain"} {
		t.Run(gen, func(t *testing.T) {
			root := t.TempDir()
			kv, err := Generate("site-a", root, gen, "cert", nil)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			returned := map[string]bool{}
			for _, p := range kv {
				returned[filepath.Base(p)] = true
			}
			ents, err := os.ReadDir(filepath.Join(root, "site-a"))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				if !returned[e.Name()] {
					t.Errorf("%s was written but its path is returned nowhere", e.Name())
				}
			}
		})
	}
}

// TestRegeneratingTightensAPermissiveMode: O_CREATE sets the mode only when it
// creates the file, so regenerating over material an older version left at
// 0644 kept that mode. The permissions test that existed worked in a fresh
// TempDir, where the case cannot arise.
func TestRegeneratingTightensAPermissiveMode(t *testing.T) {
	root := t.TempDir()
	kv, err := Generate("site-a", root, "tls", "cert", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := os.Chmod(kv["key"], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate("site-a", root, "tls", "cert", nil); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	fi, err := os.Stat(kv["key"])
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("the regenerated key is mode %04o; the permissive mode survived", perm)
	}
}
