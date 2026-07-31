package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"time"
)

// genX509Chain generates an OpenVPN-style certificate chain: a self-signed CA,
// a server certificate signed by it, and a server key. Writes ca.crt, server.crt,
// and server.key into <dir>. Returns option keys "ca", "cert", and "key" pointing
// to those files.
//
// A tls-auth key is NOT generated here — it is a symmetric HMAC key the operator
// generates once and distributes to all clients, and OpenVPN's -tls-auth option
// does not have a Generate declaration (it is optional).
func genX509Chain(dir string) (map[string]string, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "veepin-generated OpenVPN CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	if err := writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER); err != nil {
		return nil, err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "veepin-generated OpenVPN server"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	if err := writePEM(filepath.Join(dir, "server.crt"), "CERTIFICATE", srvDER); err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return nil, err
	}
	if err := writePEM(filepath.Join(dir, "server.key"), "EC PRIVATE KEY", keyDER); err != nil {
		return nil, err
	}

	return map[string]string{
		"ca":   filepath.Join(dir, "ca.crt"),
		"cert": filepath.Join(dir, "server.crt"),
		"key":  filepath.Join(dir, "server.key"),
	}, nil
}
