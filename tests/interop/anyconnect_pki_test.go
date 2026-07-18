//go:build interop

package interop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// generateAnyConnectServerCert writes a throwaway self-signed server certificate
// (server.crt/server.key) into dir, valid for both interop peers' hostnames.
// Clients connect with certificate verification disabled — the password is the
// real authentication — so a self-signed leaf is all either server needs.
// Regenerated per run, so no key material lives in the repo.
func generateAnyConnectServerCert(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "veepin-anyconnect"},
		// Both directions reuse this certificate, so it names the ocserv container
		// and the veepin one.
		DNSNames:              []string{"ocserv", "veepin-anyconnect-server", "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), certPEM, 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return os.WriteFile(filepath.Join(dir, "server.key"), keyPEM, 0o600)
}
