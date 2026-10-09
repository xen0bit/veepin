package l2tp

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
)

// TestAForgedDatagramDoesNotRedirectAnEstablishedClient runs a real loopback
// session and then attacks it from a third socket with the two things anyone on
// the path can read off the wire: the client's inbound SPI, which opens every
// ESP packet, and its initiator cookie, which opens every IKE header. Both reach
// the shared NAT-T port, and both used to move the address the server sends the
// client's ESP to -- before anything had been decrypted. If this fails, one
// datagram of either kind takes the tunnel's downstream traffic away from the
// client for as long as the forger keeps sending.
func TestAForgedDatagramDoesNotRedirectAnEstablishedClient(t *testing.T) {
	for _, tc := range []struct {
		name  string
		forge func(inSPI uint32, cookie [8]byte) []byte
	}{
		{"ESP carrying the client's SPI", func(inSPI uint32, _ [8]byte) []byte {
			pkt := make([]byte, 64)
			binary.BigEndian.PutUint32(pkt[0:4], inSPI)
			binary.BigEndian.PutUint32(pkt[4:8], 1<<20)
			return pkt
		}},
		{"IKE carrying the client's cookie", func(_ uint32, cookie [8]byte) []byte {
			// A non-ESP marker, then an encrypted Informational for the
			// client's SA: the one exchange an established session reads.
			pkt := make([]byte, 4+28+32)
			copy(pkt[4:12], cookie[:])
			pkt[4+16] = 8    // next payload: HASH
			pkt[4+17] = 0x10 // version 1.0
			pkt[4+18] = 5    // exchange: Informational
			pkt[4+19] = 1    // flags: encrypted
			binary.BigEndian.PutUint32(pkt[4+20:], 0x01020304)
			binary.BigEndian.PutUint32(pkt[4+24:], uint32(len(pkt)-4))
			return pkt
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLoopback(t)

			l.server.mu.Lock()
			var peer *serverPeer
			var cookie [8]byte
			for c, p := range l.server.byCookie {
				peer, cookie = p, c
			}
			l.server.mu.Unlock()
			peer.mu.Lock()
			inSPI, home := peer.inSPI, peer.nattAddr
			peer.mu.Unlock()

			forger, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer forger.Close()
			if _, err := forger.WriteToUDP(tc.forge(inSPI, cookie), l.natt); err != nil {
				t.Fatal(err)
			}

			// Nothing genuine may cross the NAT-T port until the verdict is
			// in: an authenticated packet from the client would move the
			// address straight back and hide the bug. So watch for a while,
			// then send downstream only -- the half that goes wherever the
			// server thinks the client is.
			deadline := time.Now().Add(300 * time.Millisecond)
			for time.Now().Before(deadline) {
				peer.mu.Lock()
				now := peer.nattAddr
				peer.mu.Unlock()
				if now.Port != home.Port || !now.IP.Equal(home.IP) {
					t.Fatalf("a forged datagram moved the client's ESP address from %v to %v", home, now)
				}
				time.Sleep(time.Millisecond)
			}
			down := makeIPv4(l.gateway, l.assigned)
			l.serverTUN.in <- down
			assertPacket(t, "server->client after the forgery", l.clientTUN.out, down)
		})
	}
}

// loopback is an established client/server pair over 127.0.0.1.
type loopback struct {
	server               *Server
	natt                 *net.UDPAddr
	gateway, assigned    net.IP
	serverTUN, clientTUN *fakeTUN
}

func newLoopback(t *testing.T) *loopback {
	t.Helper()
	pool, gateway, err := dataplane.NewAddrPool("10.21.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ip := net.IPv4(127, 0, 0, 1)
	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ikeConn, nattConn := listen(), listen()
	l := &loopback{gateway: gateway, serverTUN: newFakeTUN(), clientTUN: newFakeTUN()}
	l.natt = nattConn.LocalAddr().(*net.UDPAddr)
	l.server = NewServer(ikeConn, nattConn, l.serverTUN, ServerConfig{
		PSK: []byte("secret"), Users: map[string]string{"alice": "password"},
		Pool: pool, Gateway: gateway,
	})
	go func() { _ = l.server.Serve() }()
	t.Cleanup(func() { l.server.Close() })

	client := NewClient(listen(), l.clientTUN, ClientConfig{
		ServerIP: ip, LocalIP: ip,
		IKEPort:  ikeConn.LocalAddr().(*net.UDPAddr).Port,
		NATTPort: l.natt.Port,
		PSK:      []byte("secret"), Username: "alice", Password: "password",
	})
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nc, err := client.Handshake(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	l.assigned = nc.AssignedIP
	return l
}
