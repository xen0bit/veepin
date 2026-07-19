package masque

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/masque/http3"
	"golang.org/x/net/quic"
)

// udpEcho starts a UDP echo server and returns its address. It is the target a
// CONNECT-UDP flow proxies to: whatever it receives, it sends straight back.
func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

// A CONNECT-UDP flow proxied by the veepin server must carry a datagram to the
// target and bring its echo back, over real QUIC.
func TestServerConnectUDPRelay(t *testing.T) {
	ctx := context.Background()
	srvTLS, cliTLS := testTLS(t)
	echo := udpEcho(t)

	pool, _, err := dataplane.NewAddrPool("10.33.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	srvEnd, err := quic.Listen("udp", "127.0.0.1:0", &quic.Config{TLSConfig: srvTLS, MaxBidiRemoteStreams: 100, MaxUniRemoteStreams: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(srvEnd, newFakeTUN(), ServerConfig{Pool: pool})
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

	h3conn, err := http3.Client(ctx, qc)
	if err != nil {
		t.Fatal(err)
	}
	path := ConnectUDPPath("127.0.0.1", echo.Port)
	rs, err := h3conn.OpenConnect(ctx, ConnectUDPHeaders("proxy.example", path))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if fieldValue(resp, ":status") != "200" {
		t.Fatalf("status = %q, want 200", fieldValue(resp, ":status"))
	}

	// Send a datagram; expect the echo back as a DATAGRAM capsule.
	msg := []byte("connect-udp round trip")
	if err := WriteCapsule(rs, CapsuleDatagram, EncodeDatagramPayload(msg)); err != nil {
		t.Fatal(err)
	}

	type result struct {
		payload []byte
		err     error
	}
	got := make(chan result, 1)
	go func() {
		c, err := ReadCapsule(rs)
		if err != nil {
			got <- result{err: err}
			return
		}
		payload, _, _ := DecodeDatagramPayload(c.Value)
		got <- result{payload: payload}
	}()

	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("reading echo: %v", r.err)
		}
		if string(r.payload) != string(msg) {
			t.Errorf("echo = %q, want %q", r.payload, msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no echo returned through the CONNECT-UDP flow")
	}
}

// A CONNECT-UDP request naming a malformed target must be refused, not dialed.
func TestServerConnectUDPRejectsBadTarget(t *testing.T) {
	ctx := context.Background()
	srvTLS, cliTLS := testTLS(t)
	pool, _, _ := dataplane.NewAddrPool("10.33.0.0/24")

	srvEnd, err := quic.Listen("udp", "127.0.0.1:0", &quic.Config{TLSConfig: srvTLS, MaxBidiRemoteStreams: 100, MaxUniRemoteStreams: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := NewServer(srvEnd, newFakeTUN(), ServerConfig{Pool: pool})
	go func() { _ = srv.Run() }()
	t.Cleanup(func() { _ = srv.Close() })

	cliEnd, _ := quic.Listen("udp", "127.0.0.1:0", &quic.Config{TLSConfig: cliTLS})
	t.Cleanup(func() { _ = cliEnd.Close(ctx) })
	qc, err := cliEnd.Dial(ctx, "udp", srvEnd.LocalAddr().String(), &quic.Config{TLSConfig: cliTLS})
	if err != nil {
		t.Fatal(err)
	}
	h3conn, err := http3.Client(ctx, qc)
	if err != nil {
		t.Fatal(err)
	}
	// A path the target parser rejects (port out of range).
	rs, err := h3conn.OpenConnect(ctx, ConnectUDPHeaders("proxy", "/.well-known/masque/udp/1.1.1.1/70000/"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if s := fieldValue(resp, ":status"); s == "200" {
		t.Errorf("a malformed CONNECT-UDP target was accepted (status %q)", s)
	}
}
