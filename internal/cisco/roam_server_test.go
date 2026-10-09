package cisco

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestAForgedIKEMessageDoesNotMoveAnEstablishedClient attacks a real loopback
// session from a third socket with the initiator cookie, which every IKE header
// carries in cleartext. The gateway used to record the source of any message
// bearing a known cookie before the session had looked at it, so if this fails,
// one datagram repoints where an established client's IKE -- its DPD -- goes.
func TestAForgedIKEMessageDoesNotMoveAnEstablishedClient(t *testing.T) {
	h := newHarness(t, 0)

	h.server.mu.Lock()
	var peer *serverPeer
	var cookie [8]byte
	for c, p := range h.server.byCookie {
		peer, cookie = p, c
	}
	h.server.mu.Unlock()
	peer.mu.Lock()
	home := peer.nattAddr
	peer.mu.Unlock()

	forger, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer forger.Close()

	// A non-ESP marker, then an encrypted Informational for the client's SA:
	// the one exchange an established session still reads.
	pkt := make([]byte, 4+28+32)
	copy(pkt[4:12], cookie[:])
	pkt[4+16] = 8    // next payload: HASH
	pkt[4+17] = 0x10 // version 1.0
	pkt[4+18] = 5    // exchange: Informational
	pkt[4+19] = 1    // flags: encrypted
	binary.BigEndian.PutUint32(pkt[4+20:], 0x01020304)
	binary.BigEndian.PutUint32(pkt[4+24:], uint32(len(pkt)-4))
	if _, err := forger.WriteToUDP(pkt, h.server.nattConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	// Polled rather than synchronised: any genuine packet from the client
	// would move the address back and hide the bug, so nothing else is sent.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		peer.mu.Lock()
		now := peer.nattAddr
		peer.mu.Unlock()
		if now.Port != home.Port || !now.IP.Equal(home.IP) {
			t.Fatalf("a forged IKE message moved the client's IKE address from %v to %v", home, now)
		}
		time.Sleep(time.Millisecond)
	}
}
