package openvpn

import (
	"strings"
	"testing"
)

// TestSecurityDirectivesTheClientCannotHonourAreRefused: a profile relying on
// one of these would otherwise dial without the check it asked for.
func TestSecurityDirectivesTheClientCannotHonourAreRefused(t *testing.T) {
	for _, d := range []string{"tls-verify /bin/check", "verify-hash AA:BB", "peer-fingerprint AA:BB",
		"tls-crypt-v2 key.pem", "ns-cert-type server", "remote-cert-ku a0", "crl-verify /etc/crl dir",
		"remote-cert-tls client", "tls-version-min 1.4"} {
		if _, err := parseConfig(strings.NewReader("remote vpn.example\n"+d+"\n"), t.TempDir()); err == nil {
			t.Errorf("%q was accepted", d)
		}
	}
}

func TestVerifyX509NameParsesQuotedSubjects(t *testing.T) {
	cfg, err := parseConfig(strings.NewReader("verify-x509-name 'C=US, O=Acme, CN=node-1' subject\nremote-cert-tls server\n"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyX509Name != "C=US, O=Acme, CN=node-1" || cfg.VerifyX509Type != "subject" || !cfg.RemoteCertTLSServer {
		t.Fatalf("parsed %q %q %v", cfg.VerifyX509Name, cfg.VerifyX509Type, cfg.RemoteCertTLSServer)
	}
	cfg, err = parseConfig(strings.NewReader("verify-x509-name node- name-prefix\n"), t.TempDir())
	if err != nil || cfg.VerifyX509Name != "node-" || cfg.VerifyX509Type != "name-prefix" {
		t.Fatalf("parsed %+v, %v", cfg, err)
	}
}
