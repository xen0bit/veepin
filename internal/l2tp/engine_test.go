package l2tp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
)

// fakeTUN is an in-memory TUN: the engine Reads packets pushed onto in and the
// packets it Writes land on out.
type fakeTUN struct {
	in  chan []byte
	out chan []byte
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{in: make(chan []byte, 16), out: make(chan []byte, 16)}
}

func (f *fakeTUN) Read(p []byte) (int, error) {
	pkt, ok := <-f.in
	if !ok {
		return 0, io.EOF
	}
	return copy(p, pkt), nil
}

func (f *fakeTUN) Write(p []byte) (int, error) {
	f.out <- append([]byte(nil), p...)
	return len(p), nil
}

// makeIPv4 builds a minimal IPv4 packet (header only) from src to dst so the
// server's TUN-egress routing can read the destination.
func makeIPv4(src, dst net.IP) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	p[9] = 1 // protocol (ICMP-ish; irrelevant here)
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	return p
}

func TestClientServerLoopback(t *testing.T) {
	pool, gateway, err := dataplane.NewAddrPool("10.20.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	// The server binds two sockets, as it does in production: Main Mode on one
	// and floated IKE plus ESP on the other. Both are ephemeral here, since the
	// real 500/4500 need privileges — hence the ports on ClientConfig.
	loopback := net.IPv4(127, 0, 0, 1)
	ikeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	nattConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	serverTUN := newFakeTUN()
	server := NewServer(ikeConn, nattConn, serverTUN, ServerConfig{
		PSK:     []byte("secret"),
		Users:   map[string]string{"alice": "password"},
		Pool:    pool,
		Gateway: gateway,
	})
	go func() { _ = server.Serve() }()
	defer server.Close()

	// The client's single unconnected socket addresses both server ports.
	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	clientTUN := newFakeTUN()
	client := NewClient(cliConn, clientTUN, ClientConfig{
		ServerIP: loopback,
		LocalIP:  loopback,
		IKEPort:  ikeConn.LocalAddr().(*net.UDPAddr).Port,
		NATTPort: nattConn.LocalAddr().(*net.UDPAddr).Port,
		PSK:      []byte("secret"),
		Username: "alice",
		Password: "password",
	})
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nc, err := client.Handshake(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if nc.AssignedIP == nil || !nc.Gateway.Equal(gateway) {
		t.Fatalf("bad NetConfig: %+v (gateway want %s)", nc, gateway)
	}
	t.Logf("client assigned %s, gateway %s", nc.AssignedIP, nc.Gateway)

	// Client -> server: an IP packet injected at the client TUN must emerge at the
	// server TUN, having traversed PPP -> L2TP -> ESP and back.
	up := makeIPv4(nc.AssignedIP, gateway)
	clientTUN.in <- up
	assertPacket(t, "client->server", serverTUN.out, up)

	// Server -> client: an IP packet destined to the client's assigned address
	// must be routed to it and emerge at the client TUN.
	down := makeIPv4(gateway, nc.AssignedIP)
	serverTUN.in <- down
	assertPacket(t, "server->client", clientTUN.out, down)
}

func assertPacket(t *testing.T, dir string, out <-chan []byte, want []byte) {
	t.Helper()
	select {
	case got := <-out:
		if string(got) != string(want) {
			t.Errorf("%s: got %x, want %x", dir, got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: timed out waiting for packet", dir)
	}
}
