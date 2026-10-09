package toy

import (
	"net"
	"testing"

	"github.com/xen0bit/veepin/dataplane"
)

// discardTUN accepts the pump's writes and never yields a read.
type discardTUN struct{}

func (discardTUN) Read([]byte) (int, error)    { select {} }
func (discardTUN) Write(p []byte) (int, error) { return len(p), nil }

func samePeer(got, want *net.UDPAddr) bool {
	return got != nil && got.Port == want.Port && got.IP.Equal(want.IP)
}

// TestTheSessionRoamsOnlyOnAnAuthenticatedPacket holds the pump to the contract
// SetPeerAddr's own comment states: callers must only repoint a session after a
// packet has authenticated. The server's handler kept that contract by hand for
// keepalives, and then passed every DATA datagram to a pump that broke it. If
// this fails, the worked example teaches the opposite of what it says.
func TestTheSessionRoamsOnlyOnAnAuthenticatedPacket(t *testing.T) {
	client, server := newTestSessions(t)
	home := server.PeerAddr()
	away := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 44), Port: 61000}
	forger := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 66), Port: 5555}

	pump := dataplane.NewPump(discardTUN{}, func([]byte, *net.UDPAddr) {}, SessionOf, nil)
	pump.AddTunnel(server)

	genuine, err := client.Encapsulate(make([]byte, 20))
	if err != nil {
		t.Fatal(err)
	}
	forged := append([]byte(nil), genuine...)
	forged[len(forged)-1] ^= 1
	replayed := append([]byte(nil), genuine...)

	pump.HandleInbound(forged, forger)
	if !samePeer(server.PeerAddr(), home) {
		t.Fatalf("a datagram that failed its tag moved the session to %v", server.PeerAddr())
	}
	pump.HandleInbound(genuine, away)
	if !samePeer(server.PeerAddr(), away) {
		t.Fatalf("an authenticated datagram from %v left the session at %v", away, server.PeerAddr())
	}
	pump.HandleInbound(replayed, forger)
	if !samePeer(server.PeerAddr(), away) {
		t.Fatalf("a genuine datagram replayed from %v moved the session there", forger)
	}
}

// TestAForgedDataPacketDoesNotMoveAnEstablishedSession drives the server's own
// handler rather than the pump. It used to roam after handing data to the pump
// on the strength of "this session has authenticated something before", which
// is true of every established session -- so a forged DATA datagram arriving
// after the first genuine one moved the peer anyway.
func TestAForgedDataPacketDoesNotMoveAnEstablishedSession(t *testing.T) {
	srv, _ := newTestServer(t, "10.9.0.0/24")
	srv.pump = dataplane.NewPump(discardTUN{}, func([]byte, *net.UDPAddr) {}, SessionOf, nil)

	client, sess := newTestSessions(t)
	srv.mu.Lock()
	srv.sessions[sess.ID] = sess
	srv.mu.Unlock()
	srv.pump.AddTunnel(sess)

	away := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 44), Port: 61000}
	forger := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 66), Port: 5555}
	deliver := func(pkt []byte, from *net.UDPAddr) {
		t.Helper()
		h, _, err := ParseHeader(pkt)
		if err != nil {
			t.Fatal(err)
		}
		srv.handleSealed(h, pkt, from)
	}

	first, err := client.Encapsulate(make([]byte, 20))
	if err != nil {
		t.Fatal(err)
	}
	deliver(first, away)
	if !samePeer(sess.PeerAddr(), away) {
		t.Fatalf("a genuine DATA datagram from %v left the session at %v", away, sess.PeerAddr())
	}

	next, err := client.Encapsulate(make([]byte, 20))
	if err != nil {
		t.Fatal(err)
	}
	next[len(next)-1] ^= 1
	deliver(next, forger)
	if !samePeer(sess.PeerAddr(), away) {
		t.Fatalf("a forged DATA datagram moved an established session to %v", sess.PeerAddr())
	}
}
