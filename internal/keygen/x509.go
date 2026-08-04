package keygen

// The certificate generators, which were two files whose only real differences
// were three filenames and two Subject strings. They are one function now, in
// part because keeping them apart is what let them drift: the leaf template was
// wrong in both, and the error style was wrong in only one.
//
// What a generated chain has to satisfy is a client that verifies it:
//
//	ca.crt                     self-signed, IsCA, distributed to clients
//	  └── <server>.crt         leaf, signed by the CA, SANs for the names
//	      <server>.key             the operator will actually dial
//
// The SANs are the part that was missing and the part that matters. Go dropped
// the Common Name fallback in 1.15, so a leaf carrying only a CN verifies
// against nothing -- `x509: certificate is not valid for any names`. Every
// protocol here that generates TLS material feeds a client that checks the
// name, so a SAN-less leaf made the panel's one-click generate produce a chain
// no client would accept, which is a strange way for a certificate to fail: the
// files are all there, the permissions are right, and the handshake never works.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// chainSpec is what differs between the two generators: what the files are
// called, what the subjects say, and whether the CA path is returned as an
// option (OpenVPN declares a "ca" option; the SSL-VPN protocols do not).
type chainSpec struct {
	caFile, certFile, keyFile string
	caCN, leafCN              string
}

var (
	tlsSpec = chainSpec{
		caFile: "ca.crt", certFile: "tls.crt", keyFile: "tls.key",
		caCN: "veepin-generated CA", leafCN: "veepin-generated server",
	}
	openVPNSpec = chainSpec{
		caFile: "ca.crt", certFile: "server.crt", keyFile: "server.key",
		caCN: "veepin-generated OpenVPN CA", leafCN: "veepin-generated OpenVPN server",
	}
)

// certLifetime is how long a generated chain is good for. Ten years is not a
// defensible lifetime for a public CA and is the right one here: the CA exists
// to sign exactly one leaf on one host, the operator distributes it by hand,
// and an expiry is a tunnel that stops working on a date nobody wrote down.
const certLifetime = 10 * 365 * 24 * time.Hour

// clockSkew backdates NotBefore. Without it a client whose clock is a few
// seconds behind the server's rejects a certificate minted moments ago as
// not-yet-valid, which reads as a mysterious handshake failure on exactly the
// first connection an operator tries.
const clockSkew = time.Hour

// genChain writes a CA, a leaf signed by it, and the leaf's key, and returns
// the option keys pointing at them. hostnames become the leaf's SANs.
func genChain(dir string, hostnames []string, spec chainSpec) (map[string]string, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	now := time.Now()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: CA key: %w", err)
	}
	caSerial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: spec.caCN},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(certLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("keygen: CA cert: %w", err)
	}
	if err := writePEM(filepath.Join(dir, spec.caFile), "CERTIFICATE", caDER); err != nil {
		return nil, err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: server key: %w", err)
	}
	leafSerial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	dns, ips := splitSANs(hostnames)
	srvTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: spec.leafCN},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(certLifetime),
		// No KeyEncipherment: it is an RSA key-transport usage and this is an
		// ECDSA key, so asserting it is meaningless at best and grounds for
		// rejection in a strict validator.
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Set even though IsCA is false: it is what emits the basicConstraints
		// extension saying so, which RFC 5280 4.2.1.9 wants on a CA-issued
		// certificate and some validators insist on.
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("keygen: server cert: %w", err)
	}
	if err := writePEM(filepath.Join(dir, spec.certFile), "CERTIFICATE", srvDER); err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return nil, fmt.Errorf("keygen: marshalling server key: %w", err)
	}
	if err := writePEM(filepath.Join(dir, spec.keyFile), "EC PRIVATE KEY", keyDER); err != nil {
		return nil, err
	}

	// "ca" is returned whether or not the protocol declares such an option.
	// OpenVPN does, and gets it merged into its config; the SSL-VPN protocols
	// do not, so it lands in the create response's "generated" map instead --
	// which is where the caller surfaces the material an operator has to act on
	// but the option form never shows, exactly as it does a WireGuard server's
	// public key. Writing a file the operator is never told the path of is how
	// this behaved before, and the file is the one they have to distribute.
	return map[string]string{
		"ca":   filepath.Join(dir, spec.caFile),
		"cert": filepath.Join(dir, spec.certFile),
		"key":  filepath.Join(dir, spec.keyFile),
	}, nil
}

// serialNumber returns a random 128-bit positive serial.
//
// The constants 1 and 2 were here before, for every listener on every host. Two
// listeners on one box then produced distinct certificates sharing an issuer DN
// and a serial, which is the pair a CRL and most trust stores key on: revoking
// one revokes the other, and pinning by serial cannot tell them apart.
func serialNumber() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("keygen: serial number: %w", err)
	}
	// Zero is a legal serial and an odd one; shift it to 1 rather than retry.
	return n.Add(n, big.NewInt(1)), nil
}

// splitSANs sorts hostnames into DNS names and IP addresses, which is the
// distinction a certificate draws and an operator typing into a form does not.
func splitSANs(hostnames []string) (dns []string, ips []net.IP) {
	for _, h := range hostnames {
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dns = append(dns, h)
	}
	return dns, ips
}

func writePEM(path, blockType string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("keygen: writing %s: %w", path, err)
	}
	// O_CREATE sets the mode only when it creates the file. Regenerating over
	// material an older version left at 0644 would otherwise keep that mode,
	// and the one test covering permissions works in a fresh TempDir where the
	// case cannot arise.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("keygen: chmod %s: %w", path, err)
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
