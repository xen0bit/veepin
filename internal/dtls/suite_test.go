package dtls

import (
	"strings"
	"testing"
	"time"
)

// TestClientRefusesASuiteItDidNotOffer: the key exchange follows the suite the
// server names, so a client that accepted any suite could be moved onto the
// other key exchange -- a PSK exchange with no PSK, whose premaster is a
// constant, or a certificate exchange in place of the PSK its security rests
// on. If this fails, a server the client never authenticated completes the
// handshake.
func TestClientRefusesASuiteItDidNotOffer(t *testing.T) {
	cert := selfSignedECDSA(t)
	psk := testPSK(t)
	cases := []struct {
		name   string
		server Config
		client Config
	}{
		{
			name:   "PSK client steered to ECDHE",
			server: Config{Certificate: &cert, forceSuite: tlsECDHEECDSAWithAES128GCMSHA256},
			client: Config{PSK: psk, InsecureSkipVerify: true},
		},
		{
			name:   "certificate client steered to PSK",
			server: Config{PSK: psk, forceSuite: tlsPSKWithAES256GCMSHA384},
			client: Config{InsecureSkipVerify: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cliConn, srvConn := udpPair(t)
			tc.server.HandshakeTimeout = 2 * time.Second
			tc.client.HandshakeTimeout = 2 * time.Second
			go func() { _, _ = Server(srvConn, tc.server) }()
			c, err := Client(cliConn, tc.client)
			if err == nil {
				c.Close()
				t.Fatal("client completed a handshake on a suite it did not offer")
			}
			if !strings.Contains(err.Error(), "did not offer") {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// TestClientRequiresAServerNameToVerify: x509.Verify skips the hostname check
// for an empty DNSName, so verifying a chain with no ServerName would accept
// any certificate from a trusted root.
func TestClientRequiresAServerNameToVerify(t *testing.T) {
	c := &Conn{cfg: Config{}}
	if err := c.verifyServerCertificate([][]byte{{0x30}}); err == nil || !strings.Contains(err.Error(), "ServerName") {
		t.Fatalf("got %v, want a refusal naming ServerName", err)
	}
}
