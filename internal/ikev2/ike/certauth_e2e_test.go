package ike

import (
	"crypto"
	"crypto/elliptic"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/vlog"
)

// certAuthServer starts a server configured for mutual certificate
// authentication: it presents serverCert and trusts client certificates that
// chain to ca. Its LocalID matches the server certificate's DNS SAN so the
// client's identity check passes.
func certAuthServer(t *testing.T, ca *testCA, serverKey crypto.Signer) (p500, p4500 int, srv *Server, dp *capturingDataPath) {
	t.Helper()
	p500 = freeUDPPort(t)
	p4500 = freeUDPPort(t)
	dp = newCapturingDataPath()
	cfg := Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		LocalID:    FQDNIdentity("vpn.example"),
		ServerCert: ca.issueTLS(t, "vpn.example", serverKey),
		ClientCAs:  ca.pool,
		PublicIP:   net.ParseIP("127.0.0.1"),
		Logger:     vlog.Discard(),
		AssignAddr: func(AddressRequest) (Assignment, error) {
			return Assignment{IP4: net.IPv4(10, 9, 9, 9), Netmask: net.IPv4(255, 255, 255, 0)}, nil
		},
		DataPath: dp,
	}
	var err error
	srv, err = NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)
	return p500, p4500, srv, dp
}

// TestCertAuthHandshake is the end-to-end proof of certificate authentication:
// the production Client authenticates to the production Server with a
// certificate (no PSK), each verifying the other's chain and RFC 7427 signature,
// and a Child SA comes up. It runs for both an ECDSA and an RSA client key so
// both signature families are exercised through the real handshake.
func TestCertAuthHandshake(t *testing.T) {
	cases := []struct {
		name      string
		clientKey crypto.Signer
		serverKey crypto.Signer
	}{
		{"ECDSA", ecKey(t, elliptic.P256()), ecKey(t, elliptic.P256())},
		{"RSA", rsaKey(t), rsaKey(t)},
		{"mixed-RSAclient-ECDSAserver", rsaKey(t), ecKey(t, elliptic.P256())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newTestCA(t)
			p500, p4500, srv, dp := certAuthServer(t, ca, tc.serverKey)
			defer srv.Close()

			client := NewClient(ClientConfig{
				ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
				LocalID:    FQDNIdentity("client.example"),
				RemoteID:   ptrID(FQDNIdentity("vpn.example")),
				ClientCert: ca.issueTLS(t, "client.example", tc.clientKey),
				CARoots:    ca.pool,
				Logger:     vlog.Discard(),
			})
			res, err := client.Connect()
			if err != nil {
				t.Fatalf("cert handshake: %v", err)
			}
			defer client.Close()

			if res.AssignedIP == nil {
				t.Fatal("no address assigned")
			}
			select {
			case child := <-dp.added:
				if child.InboundSPI == 0 || child.OutboundSPI == 0 {
					t.Fatalf("child SPIs not set: in=%#x out=%#x", child.InboundSPI, child.OutboundSPI)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no Child SA established after cert handshake")
			}
		})
	}
}

// TestCertAuthUntrustedClientRejected proves the server rejects a client whose
// certificate does not chain to its ClientCAs.
func TestCertAuthUntrustedClientRejected(t *testing.T) {
	serverCA := newTestCA(t)
	p500, p4500, srv, _ := certAuthServer(t, serverCA, ecKey(t, elliptic.P256()))
	defer srv.Close()

	// Client cert from a *different* CA the server does not trust.
	strangerCA := newTestCA(t)
	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		LocalID:    FQDNIdentity("client.example"),
		RemoteID:   ptrID(FQDNIdentity("vpn.example")),
		ClientCert: strangerCA.issueTLS(t, "client.example", ecKey(t, elliptic.P256())),
		CARoots:    serverCA.pool,
		Logger:     vlog.Discard(),
	})
	if _, err := client.Connect(); err == nil {
		client.Close()
		t.Fatal("server accepted a client whose certificate it does not trust")
	}
}

// TestCertAuthWrongServerIDRejected proves the client rejects a server whose
// certificate does not match the expected RemoteID.
func TestCertAuthWrongServerIDRejected(t *testing.T) {
	ca := newTestCA(t)
	p500, p4500, srv, _ := certAuthServer(t, ca, ecKey(t, elliptic.P256()))
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		LocalID:    FQDNIdentity("client.example"),
		RemoteID:   ptrID(FQDNIdentity("not-the-server.example")),
		ClientCert: ca.issueTLS(t, "client.example", ecKey(t, elliptic.P256())),
		CARoots:    ca.pool,
		Logger:     vlog.Discard(),
	})
	if _, err := client.Connect(); err == nil {
		client.Close()
		t.Fatal("client accepted a server whose identity did not match RemoteID")
	}
}

func ptrID(id Identity) *Identity { return &id }
