//go:build interop

package interop

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// The ML-DSA credentials the pq- cells run on, minted here rather than in the
// containers.
//
// Every other cell that needs a throwaway certificate generates it in its own
// entrypoint with `openssl req -x509`. The pq- cells cannot: the veepin runtime
// image is debian:bookworm-slim, whose OpenSSL is 3.0, and ML-DSA arrived in
// OpenSSL 3.5. Bumping that base would revalidate all 103 existing cells as a
// side effect of this work, which doc/pq-variants-plan.md §7 rules out by name.
//
// So the credential is minted in Go -- where crypto/mldsa has been in the
// standard library since 1.27 -- and bind-mounted at /pki. The server
// entrypoints branch on that directory existing, so an unchanged cell mints
// exactly what it minted before.
//
// 65 is the parameter set throughout: it matches ML-KEM-768's security level,
// which is what pqpolicy.Curves leads with.

// mldsaCertTemplate is the shape every leaf here shares. It is a function rather
// than a var because x509.CreateCertificate takes a pointer and two calls must
// not share one.
//
// Note the absent KeyEncipherment: it is an RSA key-transport usage, meaningless
// for a signature-only algorithm and grounds for rejection in a strict
// validator. OpenVPN's is strict.
func mldsaCertTemplate(cn string, serial int64, eku x509.ExtKeyUsage) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
}

// generateMLDSAServerCert writes a throwaway self-signed ML-DSA-65 server
// credential (server.crt/server.key) into dir, with cn as both the CommonName
// and the SAN so a peer that checks the name against the compose service finds
// it. Regenerated per run.
//
// This is what the six no-peer variants' self cells mount. Their clients pass
// -insecure, which skips chain building but NOT pqpolicy's VerifyPeerCertificate
// hook -- crypto/tls still calls that with InsecureSkipVerify set, which is
// exactly why a self cell can prove the authentication half at all.
func generateMLDSAServerCert(dir, cn string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return err
	}
	tmpl := mldsaCertTemplate(cn, 1, x509.ExtKeyUsageServerAuth)
	tmpl.BasicConstraintsValid = true
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		return err
	}
	if err := writeCert(filepath.Join(dir, "server.crt"), der); err != nil {
		return err
	}
	return writeKey(filepath.Join(dir, "server.key"), key)
}

// generateMLDSAPKI writes a throwaway ML-DSA-65 PKI into dir -- ca.crt, a
// serverAuth leaf and a clientAuth leaf, every key and every signature ML-DSA.
// It is the mutual-TLS shape, for pq-openvpn: OpenVPN authenticates both ends by
// certificate, so a PKI with one classical half would leave the name describing
// one direction.
//
// It mirrors generateOpenVPNPKI rather than sharing with it, for the reason
// stated above generateSSTPServerCertMLDSA: the classical cells must keep
// minting exactly what they minted before, and a shared code path here would be
// one edit away from changing what they prove.
//
// No ta.key. --tls-auth and --tls-crypt are HMAC over a symmetric key, which no
// quantum adversary breaks and which the pq- profile therefore neither needs nor
// forbids; the pq- OpenVPN configs simply do not use them.
func generateMLDSAPKI(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	caKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "veepin-pq-interop-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.PublicKey(), caKey)
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
		key, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return err
		}
		der, err := x509.CreateCertificate(rand.Reader,
			mldsaCertTemplate(cn, serial, eku), caCert, key.PublicKey(), caKey)
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
	return leaf("client", 3, x509.ExtKeyUsageClientAuth, "client.crt", "client.key")
}
