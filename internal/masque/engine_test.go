package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"golang.org/x/net/quic"
)

// fakeTUN is an in-memory TUN: packets written to it appear on outbound, and
// packets placed on inbound are returned by Read. It lets the engine be driven
// end to end without a real interface.
type fakeTUN struct {
	inbound  chan []byte
	outbound chan []byte
	closed   chan struct{}
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{
		inbound:  make(chan []byte, 16),
		outbound: make(chan []byte, 16),
		closed:   make(chan struct{}),
	}
}

func (t *fakeTUN) Read(b []byte) (int, error) {
	select {
	case pkt := <-t.inbound:
		return copy(b, pkt), nil
	case <-t.closed:
		return 0, net.ErrClosed
	}
}

func (t *fakeTUN) Write(b []byte) (int, error) {
	pkt := make([]byte, len(b))
	copy(pkt, b)
	select {
	case t.outbound <- pkt:
	case <-t.closed:
		return 0, net.ErrClosed
	}
	return len(b), nil
}

func (t *fakeTUN) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

func testTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "masque-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	srv := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}
	cli := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}
	return srv, cli
}

// ipv4Packet builds a minimal well-formed IPv4 packet from src to dst.
func ipv4Packet(src, dst netip.Addr, payload string) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 253 // an experimental protocol number; the content is irrelevant
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	copy(pkt[20:], payload)
	return pkt
}

// The whole data path over real QUIC: a veepin client dials a veepin server,
// gets an address, and a packet crosses in each direction through the TUNs.
func TestClientServerDataPath(t *testing.T) {
	ctx := context.Background()
	srvTLS, cliTLS := testTLS(t)

	pool, gateway, err := dataplane.NewAddrPool("10.30.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	srvEnd, err := quic.Listen("udp", "127.0.0.1:0", &quic.Config{TLSConfig: srvTLS, MaxBidiRemoteStreams: 100, MaxUniRemoteStreams: 100})
	if err != nil {
		t.Fatal(err)
	}
	srvTUN := newFakeTUN()
	srv, err := NewServer(srvEnd, srvTUN, ServerConfig{Pool: pool, MTU: 1350, Token: []byte("test-token")})
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

	h3conn, rs, assigned, routes, err := Connect(ctx, qc, ClientConfig{Authority: "proxy.example", Token: "test-token"})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !assigned.Addr().Is4() {
		t.Fatalf("assigned %v is not IPv4", assigned)
	}
	if len(routes) == 0 {
		t.Error("no route advertised")
	}

	cliTUN := newFakeTUN()
	cli := StartClient(h3conn, rs, cliTUN, assigned, routes, nil)
	t.Cleanup(func() { _ = cli.Close() })

	clientAddr := assigned.Addr()
	gw, _ := netip.AddrFromSlice(gateway.To4())
	gw = gw.Unmap()

	// Client -> server: a packet from the assigned address to the gateway must
	// arrive on the server's TUN.
	out := ipv4Packet(clientAddr, gw, "ping")
	cliTUN.inbound <- out
	select {
	case got := <-srvTUN.outbound:
		if string(got[20:]) != "ping" {
			t.Errorf("server TUN payload = %q, want ping", got[20:])
		}
		if s, _ := innerSrc(got); s != clientAddr {
			t.Errorf("server TUN src = %v, want %v", s, clientAddr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet did not reach the server TUN")
	}

	// Server -> client: a packet addressed to the client must come back out the
	// client's TUN.
	in := ipv4Packet(gw, clientAddr, "pong")
	srvTUN.inbound <- in
	select {
	case got := <-cliTUN.outbound:
		if string(got[20:]) != "pong" {
			t.Errorf("client TUN payload = %q, want pong", got[20:])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet did not reach the client TUN")
	}
}

// A client must not be able to source traffic from an address other than the
// one it was assigned. Such a packet is dropped before it reaches the TUN.
func TestServerDropsSpoofedSource(t *testing.T) {
	ctx := context.Background()
	srvTLS, cliTLS := testTLS(t)
	pool, _, err := dataplane.NewAddrPool("10.30.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	srvEnd, err := quic.Listen("udp", "127.0.0.1:0", &quic.Config{TLSConfig: srvTLS, MaxBidiRemoteStreams: 100, MaxUniRemoteStreams: 100})
	if err != nil {
		t.Fatal(err)
	}
	srvTUN := newFakeTUN()
	srv, err := NewServer(srvEnd, srvTUN, ServerConfig{Pool: pool, Token: []byte("test-token")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run() }()
	t.Cleanup(func() { _ = srv.Close() })

	cliEnd, _ := quic.Listen("udp", "127.0.0.1:0", &quic.Config{TLSConfig: cliTLS})
	t.Cleanup(func() { _ = cliEnd.Close(ctx) })
	qc, err := cliEnd.Dial(ctx, "udp", srvEnd.LocalAddr().String(), &quic.Config{TLSConfig: cliTLS})
	if err != nil {
		t.Fatal(err)
	}
	h3conn, rs, assigned, routes, err := Connect(ctx, qc, ClientConfig{Token: "test-token"})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	cliTUN := newFakeTUN()
	cli := StartClient(h3conn, rs, cliTUN, assigned, routes, nil)
	t.Cleanup(func() { _ = cli.Close() })

	// Source an address that is not the assigned one.
	spoof := netip.MustParseAddr("10.30.0.99")
	if spoof == assigned.Addr() {
		spoof = netip.MustParseAddr("10.30.0.98")
	}
	cliTUN.inbound <- ipv4Packet(spoof, netip.MustParseAddr("10.30.0.1"), "spoof")

	select {
	case got := <-srvTUN.outbound:
		t.Errorf("a spoofed-source packet reached the server TUN: % x", got)
	case <-time.After(500 * time.Millisecond):
		// Correct: dropped.
	}
}
