package ike

import (
	"bytes"
	"io"
	"log"
	"net"
	"strconv"
	"testing"
	"time"
)

// startTCPTestServer is startTestServer with the RFC 8229/9329 listener on. The
// UDP sockets are still bound, because the TCP listener is additive: that is
// what the fallback test below relies on.
func startTCPTestServer(t *testing.T) (p500, p4500 int, srv *Server, childCh chan *ChildSA) {
	t.Helper()
	// One free port serves both the UDP and the TCP 4500 listener: they are
	// different sockets, and a real deployment uses the same number for both.
	p500, p4500 = freeUDPPort(t), freeUDPPort(t)
	childCh = make(chan *ChildSA, 4)

	var err error
	srv, err = NewServer(Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		TCP:      true,
		PSK:      []byte("test-psk"),
		LocalID:  FQDNIdentity("vpn.example"),
		PublicIP: net.ParseIP("127.0.0.1"),
		Logger:   log.New(io.Discard, "", 0),
		AssignAddr: func(want AddressRequest) (Assignment, error) {
			a := Assignment{DNS: []net.IP{net.IPv4(1, 1, 1, 1)}}
			if want.IP4 {
				a.IP4, a.Netmask = net.IPv4(10, 8, 8, 8), net.IPv4(255, 255, 255, 0)
			}
			return a, nil
		},
		OnChildSA: func(sa *IKESA, c *ChildSA) { childCh <- c },
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)
	return p500, p4500, srv, childCh
}

// TestAWholeHandshakeAndDataPathCrossOneTCPStream is the RFC 8229/9329 claim in
// one test: the IKE exchange and the ESP that follows it share one TCP
// connection, and nothing rides UDP.
//
// The UDP sockets are bound throughout, so a client that quietly fell back to
// them would pass a bare "the handshake worked" assertion. That is why the
// server is asked afterwards whether it saw a stream at all: a session that
// used UDP registers none.
func TestAWholeHandshakeAndDataPathCrossOneTCPStream(t *testing.T) {
	p500, p4500, srv, childCh := startTCPTestServer(t)
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		TCP:     true,
		PSK:     []byte("test-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	res, err := client.Connect()
	if err != nil {
		t.Fatalf("connect over TCP: %v", err)
	}
	defer client.Close()

	if !res.AssignedIP.Equal(net.IPv4(10, 8, 8, 8)) {
		t.Fatalf("assigned IP = %v, want 10.8.8.8", res.AssignedIP)
	}
	// ESP on a stream is length-prefixed, not UDP-encapsulated. Reporting
	// otherwise would be a lie the operator reads in the peer table.
	if res.UDPEncap {
		t.Error("the result claims UDP encapsulation for a session that never touched UDP")
	}
	// The one thing that separates this from a silent fallback.
	if client.DataStream() == nil {
		t.Fatal("the client kept no TCP stream, so ESP would leave by the UDP socket")
	}
	if client.DataConn() != nil {
		t.Error("the client kept a UDP socket as well; exactly one transport carries an SA")
	}
	if n := srv.liveStreams(); n != 1 {
		t.Fatalf("server holds %d TCP stream(s), want exactly 1 — the session did not arrive on TCP", n)
	}

	var serverChild *ChildSA
	select {
	case serverChild = <-childCh:
	case <-time.After(2 * time.Second):
		t.Fatal("server never established a Child SA over the stream")
	}
	if serverChild.UDPEncap {
		t.Error("the server's Child SA claims UDP encapsulation for a TCP-encapsulated peer")
	}

	// The data path itself: a packet each way through the negotiated keys.
	tunnel, err := res.BuildTunnel()
	if err != nil {
		t.Fatal(err)
	}
	serverSA, err := BuildESPSA(serverChild)
	if err != nil {
		t.Fatal(err)
	}
	inner := makeIPv4Packet(res.AssignedIP, net.IPv4(93, 184, 216, 34), []byte("client to server over TCP"))
	espPkt, err := tunnel.Encapsulate(inner)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := serverSA.Decapsulate(espPkt)
	if err != nil {
		t.Fatalf("server decap failed: %v", err)
	}
	if !bytes.Equal(got, inner) {
		t.Fatal("client->server packet corrupted")
	}
}

// TestATCPServerStillAnswersUDP: the TCP listener is additive, not a mode. A
// server with it on must keep serving every UDP peer it had before, which is
// what makes "turn it on everywhere" a safe default and libreswan's
// enable-tcp=fallback meaningful.
func TestATCPServerStillAnswersUDP(t *testing.T) {
	p500, p4500, srv, childCh := startTCPTestServer(t)
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("test-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	res, err := client.Connect()
	if err != nil {
		t.Fatalf("UDP connect against a TCP-enabled server: %v", err)
	}
	defer client.Close()
	if !res.UDPEncap {
		t.Error("a UDP session reported no UDP encapsulation")
	}
	if n := srv.liveStreams(); n != 0 {
		t.Errorf("server registered %d TCP stream(s) for a UDP session", n)
	}
	select {
	case <-childCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no Child SA over UDP")
	}
}

// TestATCPClientFailsRatherThanFallingBackToUDP: veepin's -tcp is "use TCP",
// not "prefer TCP". A client that silently used UDP when the TCP listener was
// absent would defeat the entire purpose — the deployments this exists for are
// the ones where UDP is blocked, so a fallback is a tunnel that cannot work
// pretending it can.
func TestATCPClientFailsRatherThanFallingBackToUDP(t *testing.T) {
	// A server with TCP off: UDP 500/4500 answer, TCP 4500 refuses.
	p500, p4500, srv, _ := startTestServer(t, nil)
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		TCP:     true,
		PSK:     []byte("test-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	if _, err := client.Connect(); err == nil {
		client.Close()
		t.Fatal("connect succeeded against a server with no TCP listener; it fell back to UDP")
	}
}

// TestTheResponderSendsNoStreamPrefix: RFC 8229 section 3 gives the prefix to
// the TCP ORIGINATOR only. A responder that sent its own would put six octets
// where the originator expects a length field, and the originator would read
// 0x494b ("IK") as a 18763-octet frame and block forever on a stream that has
// gone permanently out of phase.
func TestTheResponderSendsNoStreamPrefix(t *testing.T) {
	_, p4500, srv, _ := startTCPTestServer(t)
	defer srv.Close()

	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p4500)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(tcpStreamPrefix)); err != nil {
		t.Fatal(err)
	}
	// Nothing else is sent, so a correct responder says nothing at all.
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err == nil {
		t.Fatalf("responder sent %d octet(s) (%x) before being asked anything", n, buf[:n])
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("read ended with %v, want a timeout (i.e. silence)", err)
	}
}

// TestAStreamThatDoesNotBeginWithIKETCPIsDropped: the prefix is the only thing
// separating an RFC 8229 peer from a port scanner, and the responder must not
// start parsing frames out of whatever arrives.
func TestAStreamThatDoesNotBeginWithIKETCPIsDropped(t *testing.T) {
	_, p4500, srv, _ := startTCPTestServer(t)
	defer srv.Close()

	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p4500)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("responder answered a stream that never sent the IKETCP prefix")
	}
	if n := srv.liveStreams(); n != 0 {
		t.Errorf("responder registered %d stream(s) for a peer that sent no prefix", n)
	}
}
