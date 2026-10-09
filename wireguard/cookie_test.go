package wireguard

import (
	"context"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/wireguard/noise"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// loadedServer is a responder that is permanently under load: an initiation
// without a valid mac2 for its source gets a cookie reply, and one with gets a
// real handshake response. It is built from noise's own CookieChecker and
// Responder, the same parts the veepin server uses -- the tests in noise hold
// those to wireguard-go's arithmetic; these hold the client's handling of them.
type loadedServer struct {
	addr      *net.UDPAddr
	priv      [32]byte
	checker   *noise.CookieChecker
	cookied   atomic.Int32 // initiations answered with a cookie reply
	completed atomic.Int32 // initiations answered with a response
	obf       ObfuscationConfig
	// forgeFirst, when set, sends a cookie reply that does not authenticate
	// ahead of each genuine answer.
	forgeFirst bool
}

func newLoadedServer(t *testing.T, obf ObfuscationConfig) *loadedServer {
	t.Helper()
	ls := &loadedServer{obf: obf}
	for i := range ls.priv {
		ls.priv[i] = byte(i + 100)
	}
	var err error
	ls.checker, err = noise.NewCookieChecker(ls.priv, obf.TypeInitiation)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ls.addr = conn.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := deobfuscateRecv(append([]byte(nil), buf[:n]...), obf)
			if req == nil || len(req) != wire.SizeHandshakeInitiation {
				continue // junk, or a keepalive after the handshake
			}
			if ls.forgeFirst {
				forged := make([]byte, wire.SizeCookieReply)
				rand.Read(forged)
				forged[0], forged[1], forged[2], forged[3] = wire.TypeCookieReply, 0, 0, 0
				copy(forged[4:8], req[4:8]) // addressed to this initiation
				_, _ = conn.WriteToUDP(obfuscateSend(forged, obf), from)
			}
			if !ls.checker.CheckMAC2(req, from.AddrPort()) {
				reply, err := ls.checker.CookieReply(req, from.AddrPort())
				if err != nil {
					t.Error(err)
					return
				}
				ls.cookied.Add(1)
				_, _ = conn.WriteToUDP(obfuscateSend(reply, obf), from)
				continue
			}
			r, err := noise.NewResponderWithTypes(ls.priv, obf.TypeInitiation, obf.TypeResponse)
			if err != nil {
				t.Error(err)
				return
			}
			if _, _, err := r.Consume(req); err != nil {
				t.Errorf("the retried initiation did not consume: %v", err)
				continue
			}
			resp, _, err := r.Response([32]byte{})
			if err != nil {
				t.Error(err)
				return
			}
			ls.completed.Add(1)
			_, _ = conn.WriteToUDP(obfuscateSend(resp, obf), from)
		}
	}()
	return ls
}

func (ls *loadedServer) clientConfig(t *testing.T) noise.Config {
	t.Helper()
	pub, err := noise.PublicKey(ls.priv)
	if err != nil {
		t.Fatal(err)
	}
	var priv [32]byte
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	return noise.Config{LocalStatic: priv, RemoteStatic: pub,
		TypeInitiation: ls.obf.TypeInitiation, TypeResponse: ls.obf.TypeResponse}
}

// TestTheFirstHandshakeAnswersACookie: a server under load answers a bare
// initiation with a cookie reply, and this client used to read that as an
// unparseable response and retry without a cookie -- forever, so nothing could
// connect to a loaded wireguard-go server until its load fell. It must retry
// with mac2, and at once rather than after a five-second retransmit timer.
func TestTheFirstHandshakeAnswersACookie(t *testing.T) {
	ls := newLoadedServer(t, ObfuscationConfig{})
	conn, err := net.DialUDP("udp", nil, ls.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	jar := &cookieJar{}
	if _, err := handshake(ctx, conn, ls.clientConfig(t), discardLogger(), ObfuscationConfig{}, jar); err != nil {
		t.Fatalf("handshake against a loaded server: %v", err)
	}
	if took := time.Since(start); took >= rekeyTimeout {
		t.Errorf("the handshake took %v: the cookie retry waited for the retransmit timer", took)
	}
	if ls.cookied.Load() != 1 || ls.completed.Load() != 1 {
		t.Errorf("server answered %d with a cookie and completed %d, want 1 and 1",
			ls.cookied.Load(), ls.completed.Load())
	}
	if jar.at.IsZero() {
		t.Error("the cookie was not kept for the session's rekeys")
	}
}

// TestAForgedCookieReplyCostsNoAttempt: a reply that does not authenticate is
// read past like junk. If it were acted on, anyone who could see an initiation
// could make the client throw it away and start again, once per datagram.
func TestAForgedCookieReplyCostsNoAttempt(t *testing.T) {
	ls := newLoadedServer(t, ObfuscationConfig{})
	ls.forgeFirst = true
	conn, err := net.DialUDP("udp", nil, ls.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := handshake(ctx, conn, ls.clientConfig(t), discardLogger(), ObfuscationConfig{}, &cookieJar{}); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// One initiation to get the cookie, one to use it: the forgeries that
	// preceded each genuine answer prompted nothing.
	if got := ls.cookied.Load() + ls.completed.Load(); got != 2 {
		t.Errorf("the server saw %d initiations, want 2: a forged cookie reply caused a retry", got)
	}
}

// TestAnAmneziaWGCookieReplyFitsTheBuffer. The client sized its receive buffer
// for a padded response; AmneziaWG pads a cookie reply by its own S3, and with
// S3 larger than S2 plus the difference in message sizes the read truncated it
// to something that parses as nothing at all.
func TestAnAmneziaWGCookieReplyFitsTheBuffer(t *testing.T) {
	obf := ObfuscationConfig{
		TypeInitiation: 0x5f1a2b3c, TypeResponse: 0x6a7b8c9d, TypeCookie: 0x11223344, TypeTransport: 0x55667788,
		PadInitiation: 17, PadResponse: 9, PadCookie: 140, PadTransport: 0,
	}
	ls := newLoadedServer(t, obf)
	conn, err := net.DialUDP("udp", nil, ls.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := handshake(ctx, conn, ls.clientConfig(t), discardLogger(), obf, &cookieJar{}); err != nil {
		t.Fatalf("handshake against a loaded AmneziaWG server: %v", err)
	}
	if ls.cookied.Load() != 1 {
		t.Errorf("cookie replies sent: %d, want 1", ls.cookied.Load())
	}
}

// TestARekeyAnswersACookie: a rekey is dispatched through readLoop, which used
// to drop cookie replies as "nothing an established client acts on" -- so the
// first rekey against a server that had come under load since the tunnel came
// up would time out every attempt until the old keys expired.
func TestARekeyAnswersACookie(t *testing.T) {
	ls := newLoadedServer(t, ObfuscationConfig{})
	conn, err := net.DialUDP("udp", nil, ls.addr)
	if err != nil {
		t.Fatal(err)
	}
	s := &session{
		conn:     conn,
		logger:   discardLogger(),
		noiseCfg: ls.clientConfig(t),
		cookies:  &cookieJar{},
		done:     make(chan struct{}),
		stop:     make(chan struct{}),
	}
	go s.readLoop()
	t.Cleanup(func() {
		conn.Close()
		<-s.done
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := s.doHandshake(ctx); err != nil {
		t.Fatalf("rekey against a loaded server: %v", err)
	}
	if took := time.Since(start); took >= rekeyTimeout {
		t.Errorf("the rekey took %v: the cookie retry waited for the timer", took)
	}
	if ls.cookied.Load() != 1 || ls.completed.Load() != 1 {
		t.Errorf("server answered %d with a cookie and completed %d, want 1 and 1",
			ls.cookied.Load(), ls.completed.Load())
	}
}
