package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newPolicyCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert, key}
}

func (ca testCA) issue(t *testing.T, serial int64, subject pkix.Name, eku []x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

var serverEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

// TestVerifyX509NamePinsOneServer: providers sign every node from one CA and
// tell them apart with verify-x509-name. If this fails, any node's certificate
// passes for any other.
func TestVerifyX509NamePinsOneServer(t *testing.T) {
	ca := newPolicyCA(t)
	srv := ca.issue(t, 2, pkix.Name{Country: []string{"US"}, Organization: []string{"Acme"}, CommonName: "node-1"}, serverEKU)
	cases := []struct {
		p  PeerPolicy
		ok bool
	}{
		{PeerPolicy{X509Name: "node-1", X509NameType: "name"}, true},
		{PeerPolicy{X509Name: "node-2", X509NameType: "name"}, false},
		{PeerPolicy{X509Name: "node-", X509NameType: "name-prefix"}, true},
		{PeerPolicy{X509Name: "other-", X509NameType: "name-prefix"}, false},
		{PeerPolicy{X509Name: "C=US, O=Acme, CN=node-1"}, true},
		{PeerPolicy{X509Name: "/C=US/O=Acme/CN=node-1", X509NameType: "subject"}, true},
		{PeerPolicy{X509Name: "CN=node-1"}, false}, // a subject must match whole
		{PeerPolicy{X509Name: "C=US, O=Acme, CN=node-2"}, false},
	}
	for _, tc := range cases {
		if err := tc.p.check(srv, ca.cert); (err == nil) != tc.ok {
			t.Errorf("%+v: got %v, want ok=%v", tc.p, err, tc.ok)
		}
	}
}

// TestRemoteCertTLSServerNeedsTheServerUsage: Go's chain check accepts a leaf
// with no extended key usage as good for anything. remote-cert-tls server
// exists to refuse that, and a client certificate from the same CA.
func TestRemoteCertTLSServerNeedsTheServerUsage(t *testing.T) {
	ca := newPolicyCA(t)
	p := PeerPolicy{RequireServerUsage: true}
	if err := p.check(ca.issue(t, 3, pkix.Name{CommonName: "s"}, serverEKU), ca.cert); err != nil {
		t.Errorf("a server certificate was refused: %v", err)
	}
	if err := p.check(ca.issue(t, 4, pkix.Name{CommonName: "s"}, nil), ca.cert); err == nil {
		t.Error("a certificate with no extended key usage was accepted")
	}
	if err := p.check(ca.issue(t, 5, pkix.Name{CommonName: "c"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}), ca.cert); err == nil {
		t.Error("a client certificate was accepted as the server")
	}
}

// TestCRLVerifyRefusesARevokedServer: a seized or retired node's certificate
// still chains to the CA; the CRL is what says it no longer counts.
func TestCRLVerifyRefusesARevokedServer(t *testing.T) {
	ca := newPolicyCA(t)
	good := ca.issue(t, 10, pkix.Name{CommonName: "good"}, serverEKU)
	revoked := ca.issue(t, 11, pkix.Name{CommonName: "revoked"}, serverEKU)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(11), RevocationTime: time.Now()}},
	}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	p := PeerPolicy{CRL: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})}
	if err := p.check(good, ca.cert); err != nil {
		t.Errorf("an unrevoked server was refused: %v", err)
	}
	if err := p.check(revoked, ca.cert); err == nil {
		t.Error("a revoked server was accepted")
	}
	other := newPolicyCA(t)
	if err := p.check(good, other.cert); err == nil {
		t.Error("a CRL signed by another CA was trusted")
	}
}
