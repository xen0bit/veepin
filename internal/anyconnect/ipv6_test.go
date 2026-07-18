package anyconnect

import (
	"net"
	"testing"
	"time"
)

// ipv6MulticastFrame is the shape of what Linux puts on a TUN the moment the
// interface comes up: an IPv6 packet to a link-local multicast group (here an
// MLDv2 report to ff02::16). Only the version nibble and length matter here.
func ipv6MulticastFrame() []byte {
	pkt := make([]byte, 60)
	pkt[0] = 0x60 // version 6
	pkt[6] = 58   // next header: ICMPv6
	pkt[7] = 1    // hop limit
	// Destination ff02::16.
	pkt[24], pkt[25] = 0xff, 0x02
	pkt[39] = 0x16
	return pkt
}

// TestClientDropsIPv6FromTUN guards the regression that made the AnyConnect
// interop test fail about one CI run in three while passing on a workstation:
// whether the kernel emits IPv6 on a new TUN depends on the host's disable_ipv6
// sysctls, so the bug appeared and vanished with the environment rather than the
// code. The session negotiates IPv4 only, so anything else must not reach it.
func TestClientDropsIPv6FromTUN(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	tun := newFakeTUN()
	c := NewClient(client, tun, ClientConfig{Host: "example", Username: "u", Password: "p"})

	// Establish just enough state for the pump: Run's read loop is not started,
	// so only tunLoop is exercised.
	go c.tunLoop()

	// An IPv6 frame first, then an IPv4 one. Only the IPv4 packet may appear.
	tun.in <- ipv6MulticastFrame()
	want := makeIPv4(net.IPv4(10, 11, 0, 2), net.IPv4(10, 11, 0, 1))
	tun.in <- want

	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, payload, err := readPacket(server)
	if err != nil {
		t.Fatalf("reading from the tunnel: %v", err)
	}
	if typ != typeData {
		t.Fatalf("type = %#x, want data", typ)
	}
	if !isIPv4(payload) {
		t.Fatalf("an IPv6 packet reached an IPv4-only session: % x", payload[:8])
	}
	if string(payload) != string(want) {
		t.Errorf("payload = % x, want the IPv4 packet % x", payload, want)
	}
}

func TestIsIPv4(t *testing.T) {
	if !isIPv4(makeIPv4(net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8))) {
		t.Error("an IPv4 packet was not recognised")
	}
	if isIPv4(ipv6MulticastFrame()) {
		t.Error("an IPv6 packet was recognised as IPv4")
	}
	if isIPv4([]byte{0x45, 0x00}) {
		t.Error("a runt shorter than an IPv4 header was accepted")
	}
}
