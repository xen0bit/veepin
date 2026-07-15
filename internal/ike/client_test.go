package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/ikennkt/internal/esp"
)

// startTestServer spins up a real server on loopback and returns its ports.
func startTestServer(t *testing.T, eapUsers map[string]string) (p500, p4500 int, srv *Server, childCh chan *ChildSA) {
	t.Helper()
	p500 = freeUDPPort(t)
	p4500 = freeUDPPort(t)
	childCh = make(chan *ChildSA, 4)

	cfg := Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		PSK:      []byte("test-psk"),
		LocalID:  FQDNIdentity("vpn.example"),
		PublicIP: net.ParseIP("127.0.0.1"),
		Logger:   log.New(io.Discard, "", 0),
		AssignAddr: func() (net.IP, net.IP, []net.IP, error) {
			return net.IPv4(10, 8, 8, 8), net.IPv4(255, 255, 255, 0), []net.IP{net.IPv4(1, 1, 1, 1)}, nil
		},
		OnChildSA: func(sa *IKESA, c *ChildSA) { childCh <- c },
	}
	if eapUsers != nil {
		cfg.EAPCredentials = func(u string) (string, bool) { p, ok := eapUsers[u]; return p, ok }
		cfg.EAPServerName = "vpn.example"
	}
	var err error
	srv, err = NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)
	return p500, p4500, srv, childCh
}

// TestClientConnectPSK drives the production Client through a PSK handshake
// against the live server and verifies the data path end to end.
func TestClientConnectPSK(t *testing.T) {
	p500, p4500, srv, childCh := startTestServer(t, nil)
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("test-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	res, err := client.Connect()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	if !res.AssignedIP.Equal(net.IPv4(10, 8, 8, 8)) {
		t.Fatalf("assigned IP = %v, want 10.8.8.8", res.AssignedIP)
	}
	if len(res.DNS) != 1 || !res.DNS[0].Equal(net.IPv4(1, 1, 1, 1)) {
		t.Fatalf("DNS = %v", res.DNS)
	}

	// Wait for the server's Child SA.
	var serverChild *ChildSA
	select {
	case serverChild = <-childCh:
	case <-time.After(2 * time.Second):
		t.Fatal("server never established a Child SA")
	}

	// Build the client tunnel and verify a packet round-trips through ESP.
	tunnel, err := res.BuildTunnel()
	if err != nil {
		t.Fatal(err)
	}
	serverSA, err := BuildESPSA(serverChild)
	if err != nil {
		t.Fatal(err)
	}

	// Client encrypts an inner packet; server must decrypt it.
	inner := makeIPv4Packet(res.AssignedIP, net.IPv4(93, 184, 216, 34), []byte("client to server"))
	espPkt, err := tunnel.Encapsulate(inner)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := serverSA.Decapsulate(espPkt)
	if err != nil {
		t.Fatalf("server decap of client packet failed: %v", err)
	}
	if !bytes.Equal(got, inner) {
		t.Fatal("client->server packet corrupted")
	}

	// Server encrypts a reply; client must decrypt it.
	reply := makeIPv4Packet(net.IPv4(93, 184, 216, 34), res.AssignedIP, []byte("server to client"))
	espReply, err := serverSA.Encapsulate(reply, 4)
	if err != nil {
		t.Fatal(err)
	}
	gotReply, err := tunnel.Decapsulate(espReply)
	if err != nil {
		t.Fatalf("client decap of server packet failed: %v", err)
	}
	if !bytes.Equal(gotReply, reply) {
		t.Fatal("server->client packet corrupted")
	}
	t.Logf("client %v established bidirectional ESP with server", res.AssignedIP)
}

// TestClientConnectEAP drives the Client through an EAP-MSCHAPv2 handshake.
func TestClientConnectEAP(t *testing.T) {
	p500, p4500, srv, childCh := startTestServer(t, map[string]string{"alice": "wonderland"})
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:         []byte("test-psk"),
		LocalID:     FQDNIdentity("alice"),
		EAPUsername: "alice", EAPPassword: "wonderland",
		Logger: log.New(io.Discard, "", 0),
	})
	res, err := client.Connect()
	if err != nil {
		t.Fatalf("EAP connect: %v", err)
	}
	defer client.Close()
	if res.AssignedIP == nil {
		t.Fatal("no address assigned via EAP")
	}
	select {
	case <-childCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no Child SA after EAP")
	}
	t.Logf("EAP client authenticated and assigned %v", res.AssignedIP)
}

// TestClientWrongPSK confirms the client rejects a server it can't authenticate.
func TestClientWrongPSK(t *testing.T) {
	p500, p4500, srv, _ := startTestServer(t, nil)
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("WRONG-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	_, err := client.Connect()
	if err == nil {
		client.Close()
		t.Fatal("connect should have failed with wrong PSK")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("wrong PSK should be an auth failure, got: %v", err)
	}
}

func makeIPv4Packet(src, dst net.IP, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}

var _ = esp.SA{}
