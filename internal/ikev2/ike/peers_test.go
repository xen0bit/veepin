package ike

import (
	"net"

	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// TestPeerIDStringRendersTypesTheWayOperatorsReadThem pins the display form the
// management panel shows for a connected client's identity: an FQDN/email/key
// id renders as its bytes, an IP type as an address, and unknown types never
// come out blank.
func TestPeerIDStringRendersTypesTheWayOperatorsReadThem(t *testing.T) {
	cases := []struct {
		id   payload.IDPayload
		want string
	}{
		{payload.IDPayload{Type: payload.IDFQDN, Data: []byte("client.example.com")}, "client.example.com"},
		{payload.IDPayload{Type: payload.IDRFC822, Data: []byte("alice@example.com")}, "alice@example.com"},
		{payload.IDPayload{Type: payload.IDIPv4Addr, Data: []byte{192, 0, 2, 10}}, "192.0.2.10"},
		{payload.IDPayload{Type: payload.IDDERASN1DN, Data: []byte{0x30, 0x03}}, "3003"},
		{payload.IDPayload{Type: payload.IDKeyID}, "id-type-11"},
	}
	for _, c := range cases {
		if got := peerIDString(c.id); got != c.want {
			t.Errorf("peerIDString(%+v) = %q, want %q", c.id, got, c.want)
		}
	}
}

// TestPeersReleasesTheRegistryLockBeforeLockingAnySA is the deadlock guard. The
// package's lock order is sa.mu then s.mu: handleSecured holds sa.mu across a
// whole exchange and calls storeSA/deleteSA from under it. A Peers that iterated
// the registry under s.mu.RLock while taking sa.mu inverted that, and a panel
// poll racing a rekey wedged both -- and the listener with them, since every
// later lookupByRSPI queues behind the stalled s.mu writer.
//
// The order matters to the test as well as to the code: Peers has to be parked
// on sa.mu *while already holding whatever it holds* before the writer arrives.
// Starting the writer first proves nothing, because a pending s.mu writer blocks
// Peers at the RLock it has not taken yet and the pair completes either way.
func TestPeersReleasesTheRegistryLockBeforeLockingAnySA(t *testing.T) {
	s := &Server{byRSPI: make(map[uint64]*IKESA), byRemote: make(map[string]*IKESA)}
	sa := newIKESA()
	sa.ResponderSPI = 1
	sa.Children[1] = &ChildSA{ClientIP: net.IPv4(10, 0, 0, 2)}
	s.byRSPI[sa.ResponderSPI] = sa

	// Stand in for handleSecured, which owns sa.mu for the duration.
	sa.mu.Lock()
	defer sa.mu.Unlock()

	polling := make(chan struct{})
	go func() { close(polling); _ = s.Peers() }()
	<-polling
	// Let Peers reach the sa.mu it cannot have. Without the fix it parks there
	// still holding the registry read lock.
	time.Sleep(100 * time.Millisecond)

	// The storeSA an in-flight rekey performs from under sa.mu. It must not
	// block: if Peers is still holding s.mu.RLock, this writer waits forever.
	stored := make(chan struct{})
	go func() { s.storeSA(newIKESA()); close(stored) }()
	select {
	case <-stored:
	case <-time.After(5 * time.Second):
		t.Fatal("storeSA blocked while Peers waited on sa.mu: Peers is holding the registry lock across an SA lock")
	}
}

// TestPeerAddressNeverRendersTheNilLiteral: a peer that never requested Config
// Mode has no assigned IPv4, and net.IP(nil).String() is the literal "<nil>",
// which the panel would show as if it were an address.
func TestPeerAddressNeverRendersTheNilLiteral(t *testing.T) {
	cases := []struct {
		child *ChildSA
		want  string
	}{
		{&ChildSA{ClientIP: net.IPv4(10, 0, 0, 2)}, "10.0.0.2"},
		{&ChildSA{ClientIP6: net.ParseIP("fd00::2")}, "fd00::2"},
		{&ChildSA{}, ""},
	}
	for _, c := range cases {
		if got := peerAddress(c.child); got != c.want {
			t.Errorf("peerAddress(%+v) = %q, want %q", c.child, got, c.want)
		}
	}
}

// TestPeersReportsLastActivityNotEstablishment: the panel's column is a liveness
// signal, so an SA idle since it came up must not look like one that just did.
func TestPeersReportsLastActivityNotEstablishment(t *testing.T) {
	s := &Server{byRSPI: make(map[uint64]*IKESA), byRemote: make(map[string]*IKESA)}
	sa := newIKESA()
	sa.CreatedAt = time.Now().Add(-time.Hour)
	sa.lastSeen = sa.CreatedAt
	sa.Children[1] = &ChildSA{ClientIP: net.IPv4(10, 0, 0, 2)}
	s.byRSPI[1] = sa

	before := s.Peers()
	if len(before) != 1 {
		t.Fatalf("Peers() returned %d entries, want 1", len(before))
	}
	if !before[0].LastActive.Equal(sa.CreatedAt) {
		t.Fatalf("LastActive = %v, want the SA's last-seen time %v", before[0].LastActive, sa.CreatedAt)
	}

	sa.mu.Lock()
	sa.touch()
	sa.mu.Unlock()
	after := s.Peers()
	if !after[0].LastActive.After(before[0].LastActive) {
		t.Error("LastActive did not advance after a protected exchange: it is reporting CreatedAt")
	}
}
