package dtls

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"
)

// pktConn is a net.Conn over an unconnected UDP socket with a fixed peer. It is
// how a real server addresses one client on a shared socket, and it preserves
// datagram boundaries, which is what DTLS needs — a stream pipe would not do.
type pktConn struct {
	*net.UDPConn
	peer *net.UDPAddr
}

func (p *pktConn) Write(b []byte) (int, error) { return p.WriteToUDP(b, p.peer) }
func (p *pktConn) RemoteAddr() net.Addr        { return p.peer }

// udpPair returns two UDP endpoints on loopback addressed to each other.
func udpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	loopback := net.IPv4(127, 0, 0, 1)
	a, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return &pktConn{UDPConn: a, peer: b.LocalAddr().(*net.UDPAddr)},
		&pktConn{UDPConn: b, peer: a.LocalAddr().(*net.UDPAddr)}
}

func testPSK(t *testing.T) []byte {
	t.Helper()
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	return psk
}

// TestHandshakeAndDataPath drives a full PSK handshake over real UDP sockets and
// then moves datagrams both ways. It exercises the record layer, the flights,
// the key schedule and the Finished verification together — if any of them
// disagreed between the two roles, the handshake could not complete.
func TestHandshakeAndDataPath(t *testing.T) {
	cliConn, srvConn := udpPair(t)
	psk := testPSK(t)
	appID := []byte("session-identifier")

	type result struct {
		c   *Conn
		err error
	}
	srvCh := make(chan result, 1)
	go func() {
		c, err := Server(srvConn, Config{PSK: psk, HandshakeTimeout: 10 * time.Second})
		srvCh <- result{c, err}
	}()

	cli, err := Client(cliConn, Config{
		PSK:              psk,
		PSKIdentity:      []byte("veepin"),
		SessionID:        appID,
		HandshakeTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	got := <-srvCh
	if got.err != nil {
		t.Fatalf("server handshake: %v", got.err)
	}
	srv := got.c

	if cli.CipherSuite() != srv.CipherSuite() {
		t.Errorf("suite mismatch: client %#04x, server %#04x", cli.CipherSuite(), srv.CipherSuite())
	}
	if cli.CipherSuite() != tlsPSKWithAES256GCMSHA384 {
		t.Errorf("suite = %#04x, want the AES-256-GCM PSK suite", cli.CipherSuite())
	}

	// Client to server, then server to client.
	for i, payload := range [][]byte{
		[]byte("the first datagram"),
		bytes.Repeat([]byte("x"), 1000),
	} {
		if _, err := cli.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		buf := make([]byte, 2048)
		_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := srv.Read(buf)
		if err != nil {
			t.Fatalf("server read %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Errorf("datagram %d round-tripped as %d octets, want %d", i, n, len(payload))
		}
	}

	reply := []byte("and the reply")
	if _, err := srv.Write(reply); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf[:n], reply) {
		t.Errorf("reply = %q, want %q", buf[:n], reply)
	}
}

// TestWrongPSKFails: the Finished exchange is what binds the handshake to the
// key, so a mismatched PSK must be rejected there rather than yielding a
// connection that silently cannot decrypt.
func TestWrongPSKFails(t *testing.T) {
	cliConn, srvConn := udpPair(t)

	go func() {
		_, _ = Server(srvConn, Config{PSK: testPSK(t), HandshakeTimeout: 3 * time.Second})
	}()

	_, err := Client(cliConn, Config{
		PSK:              testPSK(t),
		PSKIdentity:      []byte("veepin"),
		HandshakeTimeout: 3 * time.Second,
	})
	if err == nil {
		t.Fatal("handshake succeeded with mismatched pre-shared keys")
	}
	t.Logf("rejected as expected: %v", err)
}

// TestReplayWindow covers the anti-replay filter directly: without it a captured
// datagram could be re-injected indefinitely, since the AEAD only proves a record
// was genuine once.
func TestReplayWindow(t *testing.T) {
	var w replayWindow

	for _, seq := range []uint64{0, 1, 2, 5, 4, 3} {
		if err := w.check(seq); err != nil {
			t.Errorf("seq %d rejected on first sight: %v", seq, err)
		}
	}
	for _, seq := range []uint64{0, 1, 5, 3} {
		if err := w.check(seq); !errors.Is(err, errReplay) {
			t.Errorf("replay of seq %d accepted (err=%v)", seq, err)
		}
	}
	// A jump far ahead resets the window; anything older than it is then too old
	// to judge and must be refused.
	if err := w.check(1000); err != nil {
		t.Errorf("a large forward jump was rejected: %v", err)
	}
	if err := w.check(10); !errors.Is(err, errReplay) {
		t.Error("a record older than the window was accepted")
	}
}

// TestRecordRoundTrip checks the AEAD record layer in isolation, including that
// the sequence number and type are authenticated: altering either must make the
// record fail to open, which is what stops a record being replayed into a
// different epoch or retyped.
func TestRecordRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	salt := make([]byte, 4)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := newAEAD(key, salt)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("application data")
	sealed := a.seal(recordApplicationData, version1_2, 1, 42, plaintext)

	opened, err := a.open(recordApplicationData, version1_2, 1, 42, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("opened %q, want %q", opened, plaintext)
	}
	if _, err := a.open(recordApplicationData, version1_2, 1, 43, sealed); err == nil {
		t.Error("a record opened under the wrong sequence number")
	}
	if _, err := a.open(recordHandshake, version1_2, 1, 42, sealed); err == nil {
		t.Error("a record opened under the wrong content type")
	}
	if _, err := a.open(recordApplicationData, version1_2, 2, 42, sealed); err == nil {
		t.Error("a record opened under the wrong epoch")
	}
}

// TestHandshakeFragmentReassembly: a message larger than the MTU is split across
// records and rebuilt by offset, and duplicate or overlapping fragments — which
// a peer produces whenever it retransmits a flight — must be absorbed rather
// than corrupting the result.
func TestHandshakeFragmentReassembly(t *testing.T) {
	body := make([]byte, 900)
	for i := range body {
		body[i] = byte(i)
	}
	msg := handshakeMsg{typ: handshakeClientHello, seq: 0, body: body}
	frags := msg.fragments(300)
	if len(frags) < 3 {
		t.Fatalf("got %d fragments, want the message split", len(frags))
	}

	r := newReassembler()
	var done []handshakeMsg
	// Deliver out of order, with the first fragment repeated.
	order := []int{len(frags) - 1, 0, 0}
	for i := 1; i < len(frags)-1; i++ {
		order = append(order, i)
	}
	for _, idx := range order {
		h, err := parseFragment(frags[idx])
		if err != nil {
			t.Fatal(err)
		}
		ready, err := r.accept(h)
		if err != nil {
			t.Fatal(err)
		}
		done = append(done, ready...)
	}
	if len(done) != 1 {
		t.Fatalf("reassembled %d messages, want 1", len(done))
	}
	if !bytes.Equal(done[0].body, body) {
		t.Error("the reassembled message does not match the original")
	}
}

// TestPRFMatchesRFC5246Vector checks the TLS 1.2 PRF against a published
// SHA-256 test vector, so an error in the key schedule surfaces here rather than
// as an unexplained handshake failure against another implementation.
func TestPRFMatchesRFC5246Vector(t *testing.T) {
	secret := []byte{0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35}
	seed := []byte{0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c}
	want := []byte{
		0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b,
		0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c, 0xd4, 0x53,
		0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95,
		0x32, 0x9b, 0x52, 0xd4, 0xe6, 0x1e, 0xdb, 0x5a,
		0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9,
		0xc9, 0xa4, 0x6b, 0x4e, 0x14, 0xba, 0xf9, 0xaf,
		0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17,
		0xab, 0xfd, 0x37, 0x97, 0xc0, 0x56, 0x4b, 0xab,
		0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d, 0xef, 0x9b,
		0x97, 0xfc, 0xe3, 0x4f, 0x79, 0x67, 0x89, 0xba,
		0xa4, 0x80, 0x82, 0xd1, 0x22, 0xee, 0x42, 0xc5,
		0xa7, 0x2e, 0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01,
		0x87, 0x34, 0x7b, 0x66,
	}
	got := prf(hashSHA256, secret, "test label", seed, len(want))
	if !bytes.Equal(got, want) {
		t.Errorf("PRF output does not match the RFC 5246 vector:\n got %x\nwant %x", got, want)
	}
}
