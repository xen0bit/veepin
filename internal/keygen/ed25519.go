package keygen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// genEd25519 generates an Ed25519 keypair and writes it to <dir>/ed25519_key
// in PKCS#8 PEM format. It is usable as an SSH host key (OpenSSH 6.5+ reads
// this format directly) and as a Nebula key. The result is keyed by optKey so
// it works for both "host-key" (ssh) and "key" (nebula).
func genEd25519(dir, optKey string) (map[string]string, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: ed25519: %w", err)
	}

	path := filepath.Join(dir, "ed25519_key")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("keygen: writing %s: %w", path, err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("keygen: pkcs8 wrapping: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}); err != nil {
		f.Close()
		return nil, fmt.Errorf("keygen: pem-encoding %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("keygen: closing %s: %w", path, err)
	}

	return map[string]string{optKey: path}, nil
}
