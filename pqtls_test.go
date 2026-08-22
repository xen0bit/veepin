package veepin

// Every TLS 1.3 path in this tree already negotiates a post-quantum key
// exchange, and nothing said so or checked it.
//
// Go's crypto/tls has led its default CurvePreferences with X25519MLKEM768
// (CurveID 4588) since Go 1.24, and veepin pins CurvePreferences nowhere. So
// MASQUE's key exchange is post-quantum unconditionally -- all three of its
// configs are TLS 1.3-only -- and AnyConnect, Fortinet, GlobalProtect, Ivanti,
// SSTP, SoftEther and the OpenVPN client are whenever the peer negotiates TLS
// 1.3, which every current one does.
//
// That is a considerably better story than the docs told, and it was one
// `CurvePreferences: []tls.CurveID{tls.X25519}` away from silently vanishing --
// added for some vendor workaround, in a commit about something else, with no
// test anywhere to notice. These two guards are what make the claim in
// doc/security.md and the README load-bearing rather than incidental.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNoTLSConfigPinsCurvePreferences is the repo-wide guard. Setting
// CurvePreferences at all is the way to lose the hybrid key exchange, because
// any explicit list that omits X25519MLKEM768 replaces a default that includes
// it -- and the omission is invisible: the handshake still succeeds, just
// classically.
//
// It fails on the field name rather than on the value, deliberately. A list
// that happens to include X25519MLKEM768 today is still a list somebody will
// prune later, and "we do not pin curves" is a rule with one exception to argue
// about rather than a value to keep in sync. If a protocol ever genuinely needs
// to pin (a peer that rejects a large ClientHello, say), the exception belongs
// here by name with the peer that forced it, the way noCredentialJudged in
// autherr_test.go carries its exceptions.
func TestNoTLSConfigPinsCurvePreferences(t *testing.T) {
	// Protocols that must pin, with the reason. Empty, and it should stay that
	// way; an entry here is a protocol whose key exchange is classical.
	allowed := map[string]string{}

	fset := token.NewFileSet()
	var offenders []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "node_modules" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // not our business to police unparsable files
		}
		ast.Inspect(f, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			id, ok := kv.Key.(*ast.Ident)
			if !ok || id.Name != "CurvePreferences" {
				return true
			}
			if _, ok := allowed[path]; ok {
				return true
			}
			offenders = append(offenders, fset.Position(kv.Pos()).String())
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	for _, o := range offenders {
		t.Errorf("%s pins CurvePreferences, which drops Go's default hybrid post-quantum "+
			"key exchange (X25519MLKEM768). If a peer genuinely forces this, add the file to "+
			"the allowed map above with the peer that forced it, and say so in doc/security.md.", o)
	}
}

// TestGoDefaultsStillNegotiateMLKEM is the other half, and it checks the thing
// the guard above assumes: that an unpinned tls.Config actually produces a
// post-quantum key exchange on this toolchain.
//
// Without it the guard is an assertion about a default that a future Go release
// could change underneath it -- the tree would keep not pinning curves and
// quietly stop being post-quantum, which is the same silent-downgrade failure
// in a different costume. This handshakes over a net.Pipe with the same
// zero-value curve configuration every TLS protocol here uses, and reads the
// negotiated mechanism out of ConnectionState rather than out of the config.
func TestGoDefaultsStillNegotiateMLKEM(t *testing.T) {
	cert, err := selfSignedForTest()
	if err != nil {
		t.Fatalf("test certificate: %v", err)
	}

	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })

	serverDone := make(chan error, 1)
	go func() {
		srv := tls.Server(s, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		})
		serverDone <- srv.Handshake()
	}()

	cli := tls.Client(c, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // a net.Pipe to a throwaway self-signed cert
		MinVersion:         tls.VersionTLS13,
	})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	if got := cli.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
		t.Fatalf("negotiated key exchange = %v, want X25519MLKEM768.\n"+
			"Go's default CurvePreferences no longer leads with the hybrid, so every TLS protocol "+
			"here has silently stopped being post-quantum. doc/security.md claims otherwise.", got)
	}
}

// selfSignedForTest mints a throwaway ECDSA certificate for the handshake
// above. Nothing verifies it -- the client skips verification over a net.Pipe --
// so it exists only to give the server something to present.
func selfSignedForTest() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pq-tls-guard"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
