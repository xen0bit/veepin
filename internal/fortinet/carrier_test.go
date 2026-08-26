package fortinet

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"
)

// The DTLS carrier dying under a write must cost the carrier, not the tunnel.
// If SendPPP reports the error instead of falling back, tunLoop reads it as the
// link ending and one packet unlucky enough to be in flight when the UDP socket
// closed takes the whole session down -- with the TLS carrier still open.
func TestAFailedCarrierWriteFallsBackToTLS(t *testing.T) {
	tlsSide, peer := net.Pipe()
	defer tlsSide.Close()
	defer peer.Close()

	dead, deadPeer := net.Pipe()
	_ = dead.Close()
	_ = deadPeer.Close()

	l := &pppLink{conn: tlsSide, alt: dead, done: make(chan struct{})}

	arrived := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, err := peer.Read(buf)
		if err != nil {
			return
		}
		arrived <- buf[:n]
	}()

	if err := l.SendPPP([]byte{0xff, 0x03, 0x00, 0x21}); err != nil {
		t.Fatalf("SendPPP over a dead carrier = %v, want nil: the TLS carrier is still there", err)
	}
	select {
	case got := <-arrived:
		if len(got) == 0 {
			t.Fatal("the TLS carrier received an empty record")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the frame reached neither carrier; it was dropped rather than resent over TLS")
	}

	l.writeMu.Lock()
	alt := l.alt
	l.writeMu.Unlock()
	if alt != nil {
		t.Error("the dead carrier is still the egress; every later write fails the same way")
	}
}

// The same thing over the whole stack, with the race the unit test above stands
// in for made deterministic: the TUN loop is given a backlog *before* the
// carrier is closed, so it is guaranteed to write to the dead socket before
// readAlt can detach. That window is what made TestDTLSAttachesToTLSTunnel fail
// on a loaded CI runner and pass everywhere else.
func TestABacklogWrittenAsTheCarrierDiesDoesNotEndTheTunnel(t *testing.T) {
	cert, roots := selfSignedECDSA(t)
	pool, gateway, err := newTestPool()
	if err != nil {
		t.Fatal(err)
	}
	serverTUN := newFakeTUN()
	srv, err := NewServer(ServerConfig{
		Users:       map[string]string{"alice": "s3cret"},
		Pool:        pool,
		ServerIP:    gateway,
		Certificate: &cert,
	}, serverTUN)
	if err != nil {
		t.Fatal(err)
	}
	go srv.RunTUN()
	defer srv.Close()

	base, udpAddr := dtlsTestServer(t, srv, cert)
	host := strings.TrimPrefix(base, "https://")

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	cfg, cookie, err := Login(hc, base, "alice", "s3cret", "", nil)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	clientIP := cfg.AssignedIP

	conn, err := tls.Dial("tcp", host, &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(TunnelRequest(host, cookie)); err != nil {
		t.Fatal(err)
	}
	clientTUN := newFakeTUN()
	client, err := RunClient(conn, cfg, clientTUN, nil)
	if err != nil {
		t.Fatalf("RunClient: %v", err)
	}
	defer client.Close()

	udp, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	dc, err := DialDTLS(udp, cookie, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("DialDTLS: %v", err)
	}
	client.AttachDTLS(dc)
	roundTrip(t, clientTUN, serverTUN, clientIP, gateway, "over-dtls")

	for range cap(clientTUN.inbound) / 2 {
		clientTUN.inbound <- ipv4(clientIP, gateway, "backlog")
	}
	_ = dc.Close()

	select {
	case <-client.link.done:
		t.Fatalf("the client link ended on a write to the lost carrier: %v", client.link.err)
	case <-time.After(500 * time.Millisecond):
	}
	roundTripEventually(t, clientTUN, serverTUN, clientIP, gateway, "after-detach")
}
