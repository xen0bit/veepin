//go:build interop

package interop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// generateOpenVPNPKI writes a throwaway PKI into dir: a CA, a server certificate
// (serverAuth), and a client certificate (clientAuth), all EC P-256. Both the
// OpenVPN server and the veepin client mount this directory, so they share one
// trust anchor without any keys living in the repo. It is regenerated per run.
func generateOpenVPNPKI(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "veepin-interop-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writeCert(filepath.Join(dir, "ca.crt"), caDER); err != nil {
		return err
	}

	leaf := func(cn string, serial int64, eku x509.ExtKeyUsage, crtName, keyName string) error {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		if err := writeCert(filepath.Join(dir, crtName), der); err != nil {
			return err
		}
		return writeKey(filepath.Join(dir, keyName), key)
	}

	if err := leaf("server", 2, x509.ExtKeyUsageServerAuth, "server.crt", "server.key"); err != nil {
		return err
	}
	if err := leaf("client", 3, x509.ExtKeyUsageClientAuth, "client.crt", "client.key"); err != nil {
		return err
	}
	// A shared static key for the --tls-auth / --tls-crypt control-channel
	// variants; the plain and CBC profiles ignore it.
	return writeStaticKey(filepath.Join(dir, "ta.key"))
}

// writeStaticKey writes a throwaway 2048-bit OpenVPN static key in the
// "-----BEGIN OpenVPN Static key V1-----" format both ends read.
func writeStaticKey(path string) error {
	var key [256]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n")
	h := hex.EncodeToString(key[:])
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i : i+32])
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func writeCert(path string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// key is crypto.PrivateKey rather than *ecdsa.PrivateKey because PKCS#8 already
// encodes anything the standard library can marshal -- including ML-DSA, whose
// PKCS#8 form is its 32-octet seed. Narrowing the parameter would have forced a
// second near-identical writer for the pq- cells.
func writeKey(path string, key crypto.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}
