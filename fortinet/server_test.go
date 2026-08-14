package fortinet

// Server option parsing. These are the checks that run before anything is
// opened: parseServerOptions validates and only then calls NewServer, and
// NewServer validates before it touches the TUN. So every case here runs
// unprivileged, which is the point — the option surface is the part of a server
// facade that a unit test can actually reach, and it is where a mistake is
// silent rather than loud.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/veepin/client"
)

// validOptions is the minimum that gets past option parsing. The certificate
// paths are deliberately absent: every test here is expected to fail earlier
// than the point where they are read, and a test that accidentally got that far
// would report a confusing file error instead of what it meant to check.
func validOptions() map[string]string {
	return map[string]string{
		OptServerUser: "alice",
		OptServerPass: "hunter2",
	}
}

func TestParseServerOptions(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string // substring the error must contain
	}{
		{
			name:    "some credential source is required",
			mutate:  func(o map[string]string) { delete(o, OptServerUser); delete(o, OptServerPass) },
			wantErr: "user and pass, or users-file, are required",
		},
		{
			name:    "pass alone is not enough",
			mutate:  func(o map[string]string) { delete(o, OptServerUser) },
			wantErr: "user and pass, or users-file, are required",
		},
		{
			name:    "user alone is not enough",
			mutate:  func(o map[string]string) { delete(o, OptServerPass) },
			wantErr: "a named user needs a pass",
		},
		{
			name:    "port must be a number",
			mutate:  func(o map[string]string) { o[OptServerPort] = "https" },
			wantErr: "invalid port",
		},
		{
			name:    "port must be in range",
			mutate:  func(o map[string]string) { o[OptServerPort] = "65536" },
			wantErr: "invalid port",
		},
		{
			name:    "port zero is rejected rather than treated as the default",
			mutate:  func(o map[string]string) { o[OptServerPort] = "0" },
			wantErr: "invalid port",
		},
		{
			name:    "shape must be a number",
			mutate:  func(o map[string]string) { o[OptServerShape] = "lots" },
			wantErr: "invalid shape",
		},
		{
			// A negative budget would otherwise reach the shaper as a value that
			// disables shaping, which is the opposite of what asking for it means.
			name:    "shape must not be negative",
			mutate:  func(o map[string]string) { o[OptServerShape] = "-1" },
			wantErr: "invalid shape",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := validOptions()
			tt.mutate(opts)

			srv, err := parseServerOptions(opts)
			if err == nil {
				if srv != nil {
					_ = srv.Close()
				}
				t.Fatalf("parseServerOptions accepted %v, want an error containing %q", opts, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestParseServerOptionsAcceptsAValidShape guards the other direction: the
// rejections above must not be so eager that a legitimate budget is refused. It
// gets past shape parsing and fails later, on the missing certificate.
func TestParseServerOptionsAcceptsAValidShape(t *testing.T) {
	opts := validOptions()
	opts[OptServerShape] = "16384"
	opts[OptServerPort] = "8443"

	srv, err := parseServerOptions(opts)
	if err == nil {
		if srv != nil {
			_ = srv.Close()
		}
		t.Fatal("expected the missing certificate to fail the parse")
	}
	if strings.Contains(err.Error(), "invalid shape") || strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("a valid shape/port was rejected: %v", err)
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error = %q, want the missing certificate", err)
	}
}

func TestNewServerRequiresCertificateAndUsers(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ServerConfig
		wantErr string
	}{
		{
			name:    "no certificate",
			cfg:     ServerConfig{Users: map[string]string{"alice": "hunter2"}},
			wantErr: "certificate and key are required",
		},
		{
			name:    "certificate without a key",
			cfg:     ServerConfig{Cert: []byte("cert"), Users: map[string]string{"alice": "hunter2"}},
			wantErr: "certificate and key are required",
		},
		{
			name:    "no users",
			cfg:     ServerConfig{Cert: []byte("cert"), Key: []byte("key")},
			wantErr: "at least one user is required",
		},
		{
			name: "unparseable keypair",
			cfg: ServerConfig{
				Cert:  []byte("not a PEM certificate"),
				Key:   []byte("not a PEM key"),
				Users: map[string]string{"alice": "hunter2"},
			},
			wantErr: "server keypair",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := NewServer(tt.cfg)
			if err == nil {
				if srv != nil {
					_ = srv.Close()
				}
				t.Fatalf("NewServer accepted %+v, want an error containing %q", tt.cfg, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestServerIsRegistered guards the init() side effect the CLI depends on:
// without it `veepin serve fortinet` fails at run time with an unknown-protocol
// error, and nothing at compile time says so.
func TestServerIsRegistered(t *testing.T) {
	if !slices.Contains(client.ServerProtocols(), "fortinet") {
		t.Fatalf("fortinet is not in client.ServerProtocols() = %v", client.ServerProtocols())
	}
}

// selfSignedKeypair returns a PEM certificate and key good enough to get past
// tls.X509KeyPair, so a test can reach the validation that happens after it.
func selfSignedKeypair(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vpn.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"vpn.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// TestNewServerRejectsABadTOTPSecretBeforeOpeningTheTUN pins both halves of the
// ordering. That the secret is rejected at all, and — because this test runs
// unprivileged and would otherwise fail on the TUN open instead — that it is
// rejected *before* the TUN is opened. The check used to sit after the open and
// return without closing it, leaking the interface on a typo.
func TestNewServerRejectsABadTOTPSecretBeforeOpeningTheTUN(t *testing.T) {
	certPEM, keyPEM := selfSignedKeypair(t)

	srv, err := NewServer(ServerConfig{
		Cert:        certPEM,
		Key:         keyPEM,
		Users:       map[string]string{"alice": "hunter2"},
		TOTPSecrets: map[string]string{"alice": "not!base32"},
	})
	if err == nil {
		if srv != nil {
			_ = srv.Close()
		}
		t.Fatal("NewServer accepted an invalid TOTP secret")
	}
	if !strings.Contains(err.Error(), "TOTP secret") {
		t.Fatalf("error = %q, want the TOTP secret to be named; if this reports a TUN "+
			"failure the validation has moved back after the open", err)
	}
}
