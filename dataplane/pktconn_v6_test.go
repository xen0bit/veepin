//go:build linux

package dataplane

import (
	"net"
	"testing"
	"time"
)

// TestPacketConnIPv6SourcePinning exercises the IPv6 PKTINFO path: a `::`
// wildcard-bound socket must detect the v6 family, enable IPV6_RECVPKTINFO, parse
// the in6_pktinfo control message on read (so the peer's local address is
// remembered), and pin it back as the reply source on write.
//
// IPv6 loopback offers only ::1, so this cannot show the multi-homing
// distinction the IPv4 test does (two loopback addresses); it proves the v6 code
// path is correctly wired end to end, which is the regression that matters — the
// distinction logic is shared with the IPv4 path.
func TestPacketConnIPv6SourcePinning(t *testing.T) {
	server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Skipf("IPv6 unavailable on this host: %v", err)
	}
	pc := NewPacketConn(server)
	defer pc.Close()

	if !pc.v6 {
		t.Fatal("wildcard :: bind was not detected as IPv6")
	}
	if !pc.PreservesSource() {
		t.Skip("IPV6_RECVPKTINFO unavailable on this host; the wrapper is a pass-through")
	}
	port := server.LocalAddr().(*net.UDPAddr).Port

	// Echo one datagram back to whoever sent it, pinning the source.
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], from)
		}
	}()

	client, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatalf("binding client: %v", err)
	}
	defer client.Close()

	dst := &net.UDPAddr{IP: net.IPv6loopback, Port: port}
	if _, err := client.WriteToUDP([]byte("ping"), dst); err != nil {
		t.Fatalf("sending: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	_, from, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	// The reply must come from the address contacted (::1), which is what the v6
	// PKTINFO pinning guarantees on a wildcard socket.
	if got := from.IP; !got.IsLoopback() {
		t.Errorf("reply came from %s, want the ::1 address contacted", got)
	}

	// The peer's local address must have been recorded from the parsed
	// in6_pktinfo — proof the v6 control-message decode ran.
	clientAP := client.LocalAddr().(*net.UDPAddr)
	local, ok := pc.lookup(clientAP)
	if !ok || !local.IsValid() {
		t.Fatal("server did not remember the peer's local address from IPV6_PKTINFO")
	}
	if !local.Is6() {
		t.Errorf("remembered local address %s is not IPv6", local)
	}
}

// TestPacketConnDualStackPinsV4 mirrors how the real server binds — the "udp"
// network yields an AF_INET6 dual-stack socket even for 0.0.0.0 — and proves the
// IPv6 PKTINFO path pins the source for IPv4-mapped clients too. Loopback's two
// addresses (127.0.0.1 / 127.0.0.2) give the multi-homing the assertion needs.
// Before source pinning was driven off the socket domain, this socket requested
// IP_PKTINFO and pinned nothing, so this guards the fix as well as v4-mapped v6.
func TestPacketConnDualStackPinsV4(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatalf("binding server: %v", err)
	}
	pc := NewPacketConn(server)
	defer pc.Close()

	if !pc.v6 {
		t.Fatal("dual-stack udp socket was not detected as AF_INET6")
	}
	if !pc.PreservesSource() {
		t.Skip("IPV6_RECVPKTINFO unavailable on this host; the wrapper is a pass-through")
	}
	port := server.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], from)
		}
	}()

	for _, target := range []string{"127.0.0.1", "127.0.0.2"} {
		t.Run(target, func(t *testing.T) {
			client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatalf("binding client: %v", err)
			}
			defer client.Close()

			dst := &net.UDPAddr{IP: net.ParseIP(target), Port: port}
			if _, err := client.WriteToUDP([]byte("ping"), dst); err != nil {
				t.Fatalf("sending: %v", err)
			}
			_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 64)
			_, from, err := client.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("no reply from %s: %v", target, err)
			}
			if got := from.IP.String(); got != target {
				t.Errorf("contacted %s but the reply came from %s", target, got)
			}
		})
	}
}
