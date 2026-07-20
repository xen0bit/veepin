package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	imasque "github.com/xen0bit/veepin/internal/masque"
	"golang.org/x/net/quic"
)

func selfSignedTLS(t *testing.T) (srv, cli *tls.Config) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "masque-udp-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}
}

// The whole CONNECT-UDP path through the public facade: a local UDP client sends
// to the forwarder, which proxies through a veepin MASQUE server to a UDP echo
// target, and the echo returns to the local client.
func TestUDPProxyEndToEnd(t *testing.T) {
	ctx := context.Background()
	srvTLS, _ := selfSignedTLS(t)

	// A UDP echo target.
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], from)
		}
	}()
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	// A veepin MASQUE proxy (serves CONNECT-UDP alongside CONNECT-IP).
	pool, _, _ := dataplane.NewAddrPool("10.34.0.0/24")
	srvEnd, err := quic.Listen("udp", "127.0.0.1:0", &quic.Config{TLSConfig: srvTLS, MaxBidiRemoteStreams: 100, MaxUniRemoteStreams: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := imasque.NewServer(srvEnd, newTestTUN(), imasque.ServerConfig{Pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run() }()
	defer srv.Close()

	proxyHost, proxyPort, _ := net.SplitHostPort(srvEnd.LocalAddr().String())
	pp := atoi(proxyPort)

	// The forwarder, bound to an ephemeral local port.
	proxy, err := NewUDPProxy(ctx, UDPProxyConfig{
		Server:     proxyHost,
		Port:       pp,
		Insecure:   true,
		Listen:     "127.0.0.1:0",
		TargetHost: "127.0.0.1",
		TargetPort: echoPort,
	})
	if err != nil {
		t.Fatalf("NewUDPProxy: %v", err)
	}
	defer proxy.Close()
	go func() { _ = proxy.ListenAndServe() }()

	// A local client sends a datagram to the forwarder and expects the echo.
	client, err := net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	msg := []byte("hello via connect-udp")
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 2048)
	n, err := client.Read(got)
	if err != nil {
		t.Fatalf("no echo returned through the forwarder: %v", err)
	}
	if string(got[:n]) != string(msg) {
		t.Errorf("echo = %q, want %q", got[:n], msg)
	}
}

// newTestTUN is a minimal io.ReadWriteCloser standing in for the proxy's TUN,
// which CONNECT-UDP never touches. Read blocks until close.
func newTestTUN() *blockTUN { return &blockTUN{ch: make(chan struct{})} }

type blockTUN struct{ ch chan struct{} }

func (b *blockTUN) Read(p []byte) (int, error) {
	<-b.ch
	return 0, net.ErrClosed
}
func (b *blockTUN) Write(p []byte) (int, error) { return len(p), nil }
func (b *blockTUN) Close() error {
	select {
	case <-b.ch:
	default:
		close(b.ch)
	}
	return nil
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
