package masque

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/xen0bit/veepin/dataplane"
	"golang.org/x/net/quic"
)

// tokenServer starts a proxy that requires token and returns a dialled QUIC
// connection to it.
func tokenServer(t *testing.T, cfg ServerConfig) *quic.Conn {
	t.Helper()
	ctx := context.Background()
	srvTLS, cliTLS := testTLS(t)
	pool, _, err := dataplane.NewAddrPool("10.37.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Pool = pool
	srvEnd, err := quic.Listen("udp", "127.0.0.1:0", &quic.Config{TLSConfig: srvTLS, MaxBidiRemoteStreams: 100, MaxUniRemoteStreams: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(srvEnd, newFakeTUN(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run() }()
	t.Cleanup(func() { _ = srv.Close() })
	cliEnd, err := quic.Listen("udp", "127.0.0.1:0", &quic.Config{TLSConfig: cliTLS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cliEnd.Close(ctx) })
	qc, err := cliEnd.Dial(ctx, "udp", srvEnd.LocalAddr().String(), &quic.Config{TLSConfig: cliTLS})
	if err != nil {
		t.Fatal(err)
	}
	return qc
}

// TestServerRefusesAMissingOrWrongToken: a proxy that checks no credential
// hands any host that reaches it an address on its network. If this fails, a
// client with no token, or the wrong one, gets a tunnel.
func TestServerRefusesAMissingOrWrongToken(t *testing.T) {
	for _, tok := range []string{"", "wrong-token", "right-token-but-longer"} {
		qc := tokenServer(t, ServerConfig{Token: []byte("right-token")})
		_, _, _, _, err := Connect(context.Background(), qc, ClientConfig{Authority: "p", Token: tok})
		if err == nil {
			t.Fatalf("token %q was accepted", tok)
		}
		if !errors.Is(err, ErrAuth) {
			t.Fatalf("token %q: refusal is not ErrAuth: %v", tok, err)
		}
	}
}

// TestNewServerRequiresATokenOrAnonymous: an open proxy has to be asked for.
func TestNewServerRequiresATokenOrAnonymous(t *testing.T) {
	pool, _, _ := dataplane.NewAddrPool("10.37.0.0/24")
	if _, err := NewServer(nil, newFakeTUN(), ServerConfig{Pool: pool}); err == nil {
		t.Fatal("a server with no token and no AllowAnonymous was constructed")
	}
	if _, err := NewServer(nil, newFakeTUN(), ServerConfig{Pool: pool, AllowAnonymous: true}); err != nil {
		t.Fatalf("AllowAnonymous was refused: %v", err)
	}
}

// TestUDPTargetPolicyRefusesInternalDestinations: CONNECT-UDP dials from
// inside the proxy's network, so a destination that is not public must be one
// the operator listed. If this fails, a client reaches services on the
// proxy's loopback or LAN that were never meant to face it.
func TestUDPTargetPolicyRefusesInternalDestinations(t *testing.T) {
	pool, _, _ := dataplane.NewAddrPool("10.37.0.0/24")
	srv := &Server{cfg: ServerConfig{Pool: pool}}
	refused := []string{
		"127.0.0.1", "::1", "0.0.0.0", "::", "169.254.169.254", "fe80::1",
		"10.0.0.5", "192.168.1.1", "172.16.4.4", "fd00::1", "100.64.0.1",
		"10.37.0.9", "224.0.0.1", "ff02::1", "255.255.255.255",
	}
	for _, a := range refused {
		if srv.udpTargetAllowed(net.ParseIP(a)) {
			t.Errorf("%s was allowed", a)
		}
	}
	for _, a := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !srv.udpTargetAllowed(net.ParseIP(a)) {
			t.Errorf("public %s was refused", a)
		}
	}

	srv.cfg.UDPAllow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("0.0.0.0/0")}
	if !srv.udpTargetAllowed(net.ParseIP("10.0.0.5")) {
		t.Error("an allow-listed private destination was refused")
	}
	for _, a := range []string{"0.0.0.0", "224.0.0.1", "255.255.255.255"} {
		if srv.udpTargetAllowed(net.ParseIP(a)) {
			t.Errorf("%s was allowed through UDPAllow", a)
		}
	}
}
