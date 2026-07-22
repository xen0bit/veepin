package dataplane

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// The behaviour under test is only observable on a socket bound to the wildcard,
// because that is the case where the kernel has a choice to make. Loopback
// provides the multi-homing for free: 127.0.0.1 and 127.0.0.2 are both local, so
// a client can reach a wildcard-bound server on either and check which address
// the reply came from.

func TestPacketConnRepliesFromTheAddressContacted(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatalf("binding server: %v", err)
	}
	pc := NewPacketConn(server)
	defer pc.Close()

	if !pc.PreservesSource() {
		t.Skip("IP_PKTINFO unavailable on this host; the wrapper is a pass-through")
	}
	port := server.LocalAddr().(*net.UDPAddr).Port

	// Echo one datagram back to whoever sent it.
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

			// The point: the reply must come from the address contacted, not
			// from whatever the route lookup would otherwise have picked.
			if got := from.IP.String(); got != target {
				t.Errorf("contacted %s but the reply came from %s", target, got)
			}
		})
	}
}

// ReadBatch must recover every datagram with its size and source intact, in
// however many calls the platform needs (one recvmmsg on Linux, one datagram
// per call elsewhere).
func TestPacketConnReadBatchRoundTrip(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("binding server: %v", err)
	}
	pc := NewPacketConn(server)
	defer pc.Close()

	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dialing: %v", err)
	}
	defer client.Close()

	want := []string{"one", "two-2", "three-33", "four", "five-5555"}
	for _, w := range want {
		if _, err := client.Write([]byte(w)); err != nil {
			t.Fatalf("sending %q: %v", w, err)
		}
	}

	bufs := make([][]byte, len(want))
	for i := range bufs {
		bufs[i] = make([]byte, 64)
	}
	sizes := make([]int, len(want))
	froms := make([]*net.UDPAddr, len(want))
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := map[string]bool{}
	for len(got) < len(want) {
		n, err := pc.ReadBatch(bufs, sizes, froms)
		if err != nil {
			t.Fatalf("ReadBatch (have %d/%d): %v", len(got), len(want), err)
		}
		for i := range n {
			got[string(bufs[i][:sizes[i]])] = true
			if froms[i] == nil || froms[i].Port != client.LocalAddr().(*net.UDPAddr).Port {
				t.Errorf("datagram %d: source %v, want the client's %v", i, froms[i], client.LocalAddr())
			}
		}
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("datagram %q not received", w)
		}
	}
}

// Batched reads must keep the property the wrapper exists for: a reply still
// goes out from the address each datagram was sent to, because every message in
// the batch carries its own IP_PKTINFO control data.
func TestPacketConnReadBatchPreservesSource(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatalf("binding server: %v", err)
	}
	pc := NewPacketConn(server)
	defer pc.Close()

	if !pc.PreservesSource() {
		t.Skip("IP_PKTINFO unavailable on this host; the wrapper is a pass-through")
	}
	port := server.LocalAddr().(*net.UDPAddr).Port

	// Echo every datagram of every batch back to whoever sent it.
	go func() {
		bufs := make([][]byte, 8)
		for i := range bufs {
			bufs[i] = make([]byte, 64)
		}
		sizes := make([]int, len(bufs))
		froms := make([]*net.UDPAddr, len(bufs))
		for {
			n, err := pc.ReadBatch(bufs, sizes, froms)
			for i := range n {
				_, _ = pc.WriteToUDP(bufs[i][:sizes[i]], froms[i])
			}
			if err != nil {
				return
			}
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

// The association table is a cache, and a cache on a public UDP socket has to be
// bounded or it is the denial of service the admission gate exists to prevent.
func TestPacketConnBoundsItsAssociationTable(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	pc := NewPacketConn(conn)
	defer pc.Close()

	now := time.Unix(1_700_000_000, 0)
	pc.now = func() time.Time { return now }
	pc.lastGC = now
	local := net.ParseIP("127.0.0.1")

	for i := range peerAddrMax + 5_000 {
		pc.remember(&net.UDPAddr{IP: local, Port: 1024 + i%60000}, mustAddr("127.0.0.1"))
	}

	pc.mu.Lock()
	size := len(pc.locals)
	pc.mu.Unlock()
	if size > peerAddrMax {
		t.Errorf("association table grew to %d entries, past the %d cap", size, peerAddrMax)
	}
}

// Entries for peers that have gone quiet are dropped, so a server that has
// talked to many clients over its lifetime does not hold them all forever.
func TestPacketConnEvictsIdlePeers(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	pc := NewPacketConn(conn)
	defer pc.Close()

	now := time.Unix(1_700_000_000, 0)
	pc.now = func() time.Time { return now }
	pc.lastGC = now

	for i := range 100 {
		pc.remember(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2000 + i}, mustAddr("127.0.0.1"))
	}
	pc.mu.Lock()
	before := len(pc.locals)
	pc.mu.Unlock()

	now = now.Add(2 * peerAddrIdle)
	pc.remember(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}, mustAddr("127.0.0.1"))

	pc.mu.Lock()
	after := len(pc.locals)
	pc.mu.Unlock()
	if after >= before {
		t.Errorf("idle associations were not evicted: %d before, %d after", before, after)
	}
}

// An unsolicited send -- to a peer never heard from -- must still work, falling
// back to the kernel's choice.
func TestPacketConnUnsolicitedSendWorks(t *testing.T) {
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("binding sender: %v", err)
	}
	pc := NewPacketConn(sender)
	defer pc.Close()

	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("binding receiver: %v", err)
	}
	defer receiver.Close()

	if _, err := pc.WriteToUDP([]byte("hello"), receiver.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("unsolicited send failed: %v", err)
	}

	_ = receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	n, _, err := receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("receiving: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("got %q, want hello", buf[:n])
	}
}
