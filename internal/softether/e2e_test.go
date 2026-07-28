package softether

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "veepin-softether"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

func makeEthernetFrame(dst, src MACAddr, etherType uint16, body []byte) []byte {
	frame := make([]byte, 14+len(body))
	copy(frame[0:6], dst[:])
	copy(frame[6:12], src[:])
	frame[12] = byte(etherType >> 8)
	frame[13] = byte(etherType)
	copy(frame[14:], body)
	return frame
}

// startTestServer brings up a SoftEther server on loopback with one account.
func startTestServer(t *testing.T, user, pass string) (addr string, bridge *Bridge) {
	t.Helper()
	cert := selfSignedCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	bridge = NewBridge(DefaultAgeTime)
	server := NewServer(tlsCfg, bridge,
		MACAddr{0x00, 0x0c, 0x29, 0x01, 0x02, 0x03}, net.ParseIP("10.70.0.1"),
		SingleUser(user, pass))

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() { _ = server.Serve(ln) }()
	return ln.Addr().String(), bridge
}

// TestServerLearnsTheSourceMACOfAForwardedFrame drives a real client through
// the full control exchange and asserts the layer-2 switch learned the frame's
// source. Waiting on the bridge rather than sleeping keeps it off the clock.
func TestServerLearnsTheSourceMACOfAForwardedFrame(t *testing.T) {
	addr, bridge := startTestServer(t, "testuser", "testpass")

	client, err := Connect(addr, &tls.Config{InsecureSkipVerify: true},
		"testuser", "testpass", "VPN")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	macA := MACAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	macB := MACAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	frame := makeEthernetFrame(macB, macA, EtherTypeIPv4, []byte{0x45, 0, 0, 0x20, 0, 1, 0, 0, 0x40, 6})

	if err := client.WriteFrame(frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for bridge.TableLen() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the bridge never learned the frame's source MAC")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestWrongPasswordIsRejected is the claim the previous version of this test
// only pretended to make: it logged whatever happened and passed either way,
// which is exactly what let the server ship without checking the password at
// all. Connect MUST fail.
func TestWrongPasswordIsRejected(t *testing.T) {
	addr, _ := startTestServer(t, "testuser", "testpass")

	sess, err := Connect(addr, &tls.Config{InsecureSkipVerify: true},
		"testuser", "wrongpass", "VPN")
	if err == nil {
		sess.Close()
		t.Fatal("the server accepted a login with the wrong password")
	}
}

// TestUnknownUserIsRejected: a valid password for a user that does not exist
// must not authenticate either.
func TestUnknownUserIsRejected(t *testing.T) {
	addr, _ := startTestServer(t, "testuser", "testpass")

	sess, err := Connect(addr, &tls.Config{InsecureSkipVerify: true},
		"nosuchuser", "testpass", "VPN")
	if err == nil {
		sess.Close()
		t.Fatal("the server accepted a login for an unknown user")
	}
}

// TestServerWithNoCredentialsRejectsEveryone. A server constructed without a
// credential lookup must fail closed. Failing open would mean a caller that
// forgets to wire credentials — as the facade originally did — silently runs an
// open VPN gateway.
func TestServerWithNoCredentialsRejectsEveryone(t *testing.T) {
	cert := selfSignedCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	server := NewServer(tlsCfg, NewBridge(DefaultAgeTime), MACAddr{}, net.IPv4zero, nil)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = server.Serve(ln) }()

	sess, err := Connect(ln.Addr().String(), &tls.Config{InsecureSkipVerify: true},
		"anyone", "anything", "VPN")
	if err == nil {
		sess.Close()
		t.Fatal("a server with no credentials configured accepted a login")
	}
}

// TestEachSessionGetsAFreshChallenge: the password digest is bound to the
// server's random, so a repeated challenge would make a captured login
// replayable against a later session.
func TestEachSessionGetsAFreshChallenge(t *testing.T) {
	addr, _ := startTestServer(t, "u", "p")
	seen := map[string]bool{}
	for range 4 {
		c, err := Connect(addr, &tls.Config{InsecureSkipVerify: true}, "u", "p", "VPN")
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		key := string(c.serverRandom[:])
		if seen[key] {
			t.Fatal("the server reused a login challenge across sessions")
		}
		seen[key] = true
		c.Close()
	}
}

// TestFrameReachesAnotherClient is the claim the data path exists at all. Two
// clients, one frame: it must arrive. The server previously parsed frames,
// learned their addresses and discarded them — every unit test still passed,
// because none of them asked whether anything came out the other side.
func TestFrameReachesAnotherClient(t *testing.T) {
	addr, _ := startTestServer(t, "u", "p")

	a, err := Connect(addr, &tls.Config{InsecureSkipVerify: true}, "u", "p", "VPN")
	if err != nil {
		t.Fatalf("client A: %v", err)
	}
	defer a.Close()
	b, err := Connect(addr, &tls.Config{InsecureSkipVerify: true}, "u", "p", "VPN")
	if err != nil {
		t.Fatalf("client B: %v", err)
	}
	defer b.Close()

	macA := MACAddr{0x02, 0, 0, 0, 0, 0x0a}
	macB := MACAddr{0x02, 0, 0, 0, 0, 0x0b}
	payload := []byte{0x45, 0, 0, 0x20, 0, 1, 0, 0, 0x40, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	sent := makeEthernetFrame(macB, macA, EtherTypeIPv4, payload)

	// B speaks first so the bridge learns its address; otherwise A's frame
	// floods, which would also reach B and make the test prove less.
	if err := b.WriteFrame(makeEthernetFrame(macA, macB, EtherTypeIPv4, payload)); err != nil {
		t.Fatalf("B announce: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if err := a.WriteFrame(sent); err != nil {
		t.Fatalf("A write: %v", err)
	}

	done := make(chan []byte, 1)
	go func() {
		f, rerr := b.ReadFrame()
		if rerr == nil {
			done <- append([]byte(nil), f...)
		}
		close(done)
	}()

	select {
	case got := <-done:
		if got == nil {
			t.Fatal("client B's read failed")
		}
		if !bytes.Equal(got, sent) {
			t.Fatalf("frame changed in transit\n got %x\nwant %x", got, sent)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the frame never reached the other client; the switch forwards nothing")
	}
}
