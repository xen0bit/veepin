//go:build interop

package interop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// generateSSTPServerCert writes a throwaway self-signed server certificate
// (server.crt/server.key) into dir. SSTP clients connect with -insecure and rely
// on MS-CHAPv2 plus the crypto binding rather than the PKI, so a self-signed leaf
// is all the server needs. Regenerated per run.
func generateSSTPServerCert(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "veepin-sstp-server"},
		DNSNames:              []string{"veepin-sstp-server"},
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
	if err := writeCert(filepath.Join(dir, "server.crt"), der); err != nil {
		return err
	}
	return writeKey(filepath.Join(dir, "server.key"), key)
}

// generateSSTPServerCertMLDSA is the same thing with an ML-DSA-65 key, for the
// pq-sstp cell.
//
// It is a separate function rather than a parameter on the one above so that the
// classical cells keep minting exactly what they minted before -- the pq- work
// is meant to leave the existing matrix untouched, and sharing a code path here
// would be one edit away from changing what those cells prove.
//
// 65 is the parameter set matching ML-KEM-768's security level, which is what
// pqpolicy uses everywhere else.
func generateSSTPServerCertMLDSA(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "veepin-pq-sstp-server"},
		DNSNames:     []string{"veepin-pq-sstp-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		// No KeyEncipherment: it is an RSA key-transport usage, meaningless for
		// a signature-only algorithm and grounds for rejection in a strict
		// validator.
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		return err
	}
	if err := writeCert(filepath.Join(dir, "server.crt"), der); err != nil {
		return err
	}
	return writeKey(filepath.Join(dir, "server.key"), key)
}
