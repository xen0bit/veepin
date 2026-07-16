package wireguard

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/wireguard/transport"
)

// sessionPair builds the two ends of one transport session from crossed keys,
// with the given receiver indices. "us" is what a wgTunnel holds; "peer" is what
// seals packets addressed to us (receiver = our index).
func sessionPair(t *testing.T, seed byte, usIdx, peerIdx uint32) (us, peer *transport.Session) {
	t.Helper()
	var k1, k2 [32]byte
	for i := range k1 {
		k1[i] = seed + byte(i)
		k2[i] = seed + 0x80 + byte(i)
	}
	us, err := transport.NewSession(k1, k2, usIdx, peerIdx)
	if err != nil {
		t.Fatal(err)
	}
	peer, err = transport.NewSession(k2, k1, peerIdx, usIdx)
	if err != nil {
		t.Fatal(err)
	}
	return us, peer
}

func ipv4Packet(src, dst string, size int) []byte {
	if size < 20 {
		size = 20
	}
	pkt := make([]byte, size)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(size))
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())
	return pkt
}

// TestTunnelRekeyKeepsBothKeypairs is the core rekey property: after install,
// packets under the new (current) key and the old (previous) key both decrypt,
// while a retired keypair's packets no longer do.
func TestTunnelRekeyKeepsBothKeypairs(t *testing.T) {
	usA, peerA := sessionPair(t, 1, 100, 200) // first session
	usB, peerB := sessionPair(t, 2, 101, 201) // rekey
	usC, peerC := sessionPair(t, 3, 102, 202) // second rekey

	routes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	tun := newTunnel(usA, routes, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 51820}, false)

	// First rekey: current=usB, previous=usA, nothing evicted yet.
	if evicted := tun.install(usB); evicted != nil {
		t.Errorf("first install evicted a session, want none")
	}

	pkt := ipv4Packet("10.0.0.9", "10.0.0.1", 40)
	decap := func(peer *transport.Session) ([]byte, error) {
		sealed, err := peer.Seal(pkt)
		if err != nil {
			t.Fatal(err)
		}
		return tun.Decapsulate(sealed)
	}

	// Current (usB) and previous (usA) both open.
	if got, err := decap(peerB); err != nil || !bytes.Equal(got, pkt) {
		t.Errorf("current keypair did not decap: %v", err)
	}
	if got, err := decap(peerA); err != nil || !bytes.Equal(got, pkt) {
		t.Errorf("previous keypair did not decap: %v", err)
	}

	// Second rekey: current=usC, previous=usB, usA evicted.
	evicted := tun.install(usC)
	if evicted != usA {
		t.Errorf("second install evicted %p, want usA %p", evicted, usA)
	}
	if got, err := decap(peerC); err != nil || !bytes.Equal(got, pkt) {
		t.Errorf("new current did not decap: %v", err)
	}
	if got, err := decap(peerB); err != nil || !bytes.Equal(got, pkt) {
		t.Errorf("new previous did not decap: %v", err)
	}
	// usA is gone: its packets no longer match any keypair index.
	if _, err := decap(peerA); err != errUnknownIndex {
		t.Errorf("evicted keypair still decapping: %v, want errUnknownIndex", err)
	}
}

// TestTunnelEncapsulatesUnderCurrent checks that outbound traffic uses the
// current keypair, so the peer's matching session opens it.
func TestTunnelEncapsulatesUnderCurrent(t *testing.T) {
	usA, _ := sessionPair(t, 1, 100, 200)
	usB, peerB := sessionPair(t, 2, 101, 201)
	tun := newTunnel(usA, nil, nil, false)
	tun.install(usB) // current = usB

	pkt := ipv4Packet("10.0.0.1", "10.0.0.9", 60)
	sealed, err := tun.Encapsulate(pkt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := peerB.Open(sealed)
	if err != nil || !bytes.Equal(got, pkt) {
		t.Errorf("current keypair peer could not open outbound packet: %v", err)
	}
}

// TestTunnelExpiry checks that a session past rejectAfterTime refuses to seal,
// so the data path stops sending under a key the peer would reject.
func TestTunnelExpiry(t *testing.T) {
	us, _ := sessionPair(t, 1, 100, 200)
	tun := newTunnel(us, nil, nil, false)

	if _, err := tun.Encapsulate(ipv4Packet("10.0.0.1", "10.0.0.9", 40)); err != nil {
		t.Fatalf("fresh session should seal: %v", err)
	}
	// Age it past rejectAfterTime.
	tun.mu.Lock()
	tun.established = time.Now().Add(-rejectAfterTime - time.Second)
	tun.mu.Unlock()
	if _, err := tun.Encapsulate(ipv4Packet("10.0.0.1", "10.0.0.9", 40)); err != errSessionExpired {
		t.Errorf("expired session sealed: %v, want errSessionExpired", err)
	}
}

// TestTunnelSourceVerification checks the inbound half of cryptokey routing: a
// decrypted packet sourced outside the peer's AllowedIPs is dropped.
func TestTunnelSourceVerification(t *testing.T) {
	us, peer := sessionPair(t, 1, 100, 200)
	routes := []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}
	tun := newTunnel(us, routes, nil, true) // verifySource on

	ok := ipv4Packet("10.0.0.2", "10.0.0.1", 40)
	sealed, _ := peer.Seal(ok)
	if _, err := tun.Decapsulate(sealed); err != nil {
		t.Errorf("allowed source was dropped: %v", err)
	}

	bad := ipv4Packet("10.0.0.9", "10.0.0.1", 40)
	sealed, _ = peer.Seal(bad)
	if _, err := tun.Decapsulate(sealed); err != errSourceNotAllowed {
		t.Errorf("spoofed source: %v, want errSourceNotAllowed", err)
	}
}
