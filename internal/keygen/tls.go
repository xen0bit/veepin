package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// genTLS generates a self-signed CA certificate, then uses it to sign a server
// certificate. Both use ECDSA P-256. The CA cert, server cert, and server key
// are written to <dir>/ca.crt, <dir>/tls.crt, and <dir>/tls.key.
//
// It returns an options map with two keys: "cert" and "key" pointing to the
// server certificate and private key files. The CA certificate is written
// alongside them so the operator can distribute it if needed; only "cert" and
// "key" are set in the listener options because those are the keys the protocols
// that use "tls" generation declare.
func genTLS(dir string) (map[string]string, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: tls CA key: %w", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "veepin-generated CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("keygen: tls CA cert: %w", err)
	}
	if err := writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER); err != nil {
		return nil, err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: tls server key: %w", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "veepin-generated server"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("keygen: tls server cert: %w", err)
	}
	if err := writePEM(filepath.Join(dir, "tls.crt"), "CERTIFICATE", srvDER); err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return nil, fmt.Errorf("keygen: tls marshal key: %w", err)
	}
	if err := writePEM(filepath.Join(dir, "tls.key"), "EC PRIVATE KEY", keyDER); err != nil {
		return nil, err
	}

	return map[string]string{
		"cert": filepath.Join(dir, "tls.crt"),
		"key":  filepath.Join(dir, "tls.key"),
	}, nil
}

func writePEM(path, blockType string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("keygen: writing %s: %w", path, err)
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		f.Close()
		return fmt.Errorf("keygen: pem-encoding %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("keygen: closing %s: %w", path, err)
	}
	return nil
}
