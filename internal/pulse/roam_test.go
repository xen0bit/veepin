package pulse

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestAForgedESPPacketDoesNotRedirectTheClient attacks a real loopback session
// from a third socket with the client's SPI, which is cleartext in every ESP
// packet. The gateway used to note the source of any datagram bearing a known
// SPI before decrypting it, so if this fails, one forged packet sends the
// client's downstream traffic to the forger until the client next speaks.
func TestAForgedESPPacketDoesNotRedirectTheClient(t *testing.T) {
	h := newHarness(t, true, 0)

	h.server.mu.Lock()
	var peer *espPeer
	var spi uint32
	for k, p := range h.server.bySPI {
		peer, spi = p, k
	}
	h.server.mu.Unlock()
	if peer == nil {
		t.Fatal("the session negotiated no ESP peer")
	}

	// Wait for the client's first ESP packet to settle the peer's address: the
	// gateway learns it from traffic, not from the handshake.
	var home *net.UDPAddr
	deadline := time.Now().Add(5 * time.Second)
	for home == nil && time.Now().Before(deadline) {
		peer.mu.Lock()
		home = peer.addr
		peer.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	if home == nil {
		t.Fatal("the client never sent ESP")
	}

	forger, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer forger.Close()
	pkt := make([]byte, 64)
	pkt[0], pkt[1], pkt[2], pkt[3] = byte(spi>>24), byte(spi>>16), byte(spi>>8), byte(spi)
	pkt[7] = 0x40 // a sequence number the replay window has not seen
	if _, err := forger.WriteToUDP(pkt, h.server.udp().LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	deadline = time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		peer.mu.Lock()
		now := peer.addr
		peer.mu.Unlock()
		if now.Port != home.Port || !now.IP.Equal(home.IP) {
			t.Fatalf("a forged ESP packet moved the client's address from %v to %v", home, now)
		}
		time.Sleep(time.Millisecond)
	}

	down := makeIPv4(net.IPv4(203, 0, 113, 5), h.client.AssignedConfig().Address, 128)
	h.serverTUN.in <- down
	select {
	case got := <-h.clientTUN.out:
		if !bytes.Equal(got, down) {
			t.Fatalf("the client received %x, want %x", got, down)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("downstream traffic never reached the client after the forgery")
	}
}
