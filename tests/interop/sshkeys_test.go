//go:build interop

package interop

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"

	cryptossh "golang.org/x/crypto/ssh"
)

// generateSSHKeys writes a throwaway Ed25519 host key and client key into dir,
// plus an authorized_keys file holding the client's public key. The veepin SSH
// server mounts host_key + authorized_keys; the client mounts client_key.
// Regenerated per run, so no keys live in the repo.
func generateSSHKeys(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeSSHKey(filepath.Join(dir, "host_key"), ""); err != nil {
		return err
	}
	pub, err := writeSSHKeyReturnPub(filepath.Join(dir, "client_key"))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "authorized_keys"), pub, 0o644)
}

func writeSSHKey(path, _ string) error {
	_, err := writeSSHKeyReturnPub(path)
	return err
}

// writeSSHKeyReturnPub generates an Ed25519 key, writes the private key in
// OpenSSH PEM to path, and returns the authorized_keys-format public key.
func writeSSHKeyReturnPub(path string) ([]byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return cryptossh.MarshalAuthorizedKey(sshPub), nil
}
