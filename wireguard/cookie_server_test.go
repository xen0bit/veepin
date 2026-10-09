package wireguard

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/wireguard/noise"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// socketServer is a Server with everything ListenAndServe would give it except
// the TUN: a real UDP socket, a pump over a discarding device, and one peer.
// handleInitiation is driven directly, so a test controls exactly which
// datagrams it sees.
func socketServer(t *testing.T, threshold int) (*Server, noise.Config) {
	t.Helper()
	var serverPriv, clientPriv [32]byte
	for i := range serverPriv {
		serverPriv[i] = byte(i + 100)
		clientPriv[i] = byte(i + 1)
	}
	serverPub, _ := noise.PublicKey(serverPriv)
	clientPub, _ := noise.PublicKey(clientPriv)

	raw, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	cookies, err := noise.NewCookieChecker(serverPriv, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		localStatic: serverPriv,
		logger:      discardLogger(),
		gate:        dataplane.NewGate(dataplane.AdmissionConfig{}),
		cookies:     cookies,
		load:        handshakeLoad{threshold: threshold, now: time.Now},
		conn:        dataplane.NewPacketConn(raw),
		pump:        dataplane.NewPump(discardTUN{}, func([]byte, *net.UDPAddr) {}, wire.Demux, nil),
		peers: map[[keySize]byte]*serverPeer{clientPub: {
			pubKey:     clientPub,
			allowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
		}},
		closed: make(chan struct{}),
	}
	return s, noise.Config{LocalStatic: clientPriv, RemoteStatic: serverPub}
}

// readOne reads the next datagram the server sent to client, or fails.
func readOne(t *testing.T, client *net.UDPConn) []byte {
	t.Helper()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("the server sent nothing: %v", err)
	}
	return buf[:n]
}

// TestALoadedServerSpendsNothingUntilTheCookieComesBack is the server's half of
// the defence. Under load an initiation without a valid mac2 must get a cookie
// reply and nothing else -- no Diffie-Hellman, no admission reservation, no
// state -- because its source may be spoofed and the reply is how we find out.
// The same initiator retrying with the cookie must then get a real handshake.
// If this fails, either a spoofed flood still costs the server its DH budget,
// or a genuine client under load can never get in.
func TestALoadedServerSpendsNothingUntilTheCookieComesBack(t *testing.T) {
	s, cfg := socketServer(t, -1)
	client, err := net.DialUDP("udp", nil, s.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	from := client.LocalAddr().(*net.UDPAddr)

	first, _ := noise.NewInitiator(cfg)
	init, err := first.Initiation()
	if err != nil {
		t.Fatal(err)
	}
	s.handleInitiation(init, from)

	reply := readOne(t, client)
	if typ, _ := wire.Type(reply); typ != wire.TypeCookieReply {
		t.Fatalf("a loaded server answered a cookie-less initiation with type %d, want a cookie reply", typ)
	}
	if peer := s.peers[[keySize]byte(mustPub(t, cfg.LocalStatic))]; peer.tunnel != nil || peer.lastTS != ([wire.TimestampLen]byte{}) {
		t.Fatal("the server ran the handshake for an initiation that had not proved its address")
	}

	cookie, err := first.ConsumeCookieReply(reply)
	if err != nil {
		t.Fatalf("the server's cookie reply does not open: %v", err)
	}
	retry, _ := noise.NewInitiator(cfg)
	retry.SetCookie(cookie)
	init2, err := retry.Initiation()
	if err != nil {
		t.Fatal(err)
	}
	s.handleInitiation(init2, from)

	resp := readOne(t, client)
	if _, err := retry.Consume(resp); err != nil {
		t.Fatalf("the retry with a cookie did not get a handshake response: %v", err)
	}
}

// TestACookieFromOneAddressDoesNotAdmitAnother: the cookie proves one source.
// An initiation that carries a cookie issued to a different address is a
// cookie-less one as far as the server is concerned, and gets a cookie reply
// sent to where it came from rather than a handshake.
func TestACookieFromOneAddressDoesNotAdmitAnother(t *testing.T) {
	s, cfg := socketServer(t, -1)
	a, _ := net.DialUDP("udp", nil, s.conn.LocalAddr().(*net.UDPAddr))
	b, _ := net.DialUDP("udp", nil, s.conn.LocalAddr().(*net.UDPAddr))
	defer a.Close()
	defer b.Close()

	first, _ := noise.NewInitiator(cfg)
	init, _ := first.Initiation()
	s.handleInitiation(init, a.LocalAddr().(*net.UDPAddr))
	cookie, err := first.ConsumeCookieReply(readOne(t, a))
	if err != nil {
		t.Fatal(err)
	}

	retry, _ := noise.NewInitiator(cfg)
	retry.SetCookie(cookie)
	init2, _ := retry.Initiation()
	s.handleInitiation(init2, b.LocalAddr().(*net.UDPAddr))
	if typ, _ := wire.Type(readOne(t, b)); typ != wire.TypeCookieReply {
		t.Fatalf("a cookie issued to %v admitted an initiation from %v", a.LocalAddr(), b.LocalAddr())
	}
}

// TestAServerNotUnderLoadNeedsNoCookie: below the threshold nothing changes for
// a stock client, which sends mac2 as zeros and must get its response first
// time. A server that demanded cookies unconditionally would add a round trip
// to every handshake on every quiet server.
func TestAServerNotUnderLoadNeedsNoCookie(t *testing.T) {
	s, cfg := socketServer(t, DefaultCookieThreshold)
	client, _ := net.DialUDP("udp", nil, s.conn.LocalAddr().(*net.UDPAddr))
	defer client.Close()

	i, _ := noise.NewInitiator(cfg)
	init, _ := i.Initiation()
	s.handleInitiation(init, client.LocalAddr().(*net.UDPAddr))
	if _, err := i.Consume(readOne(t, client)); err != nil {
		t.Fatalf("a quiet server did not answer a stock initiation with a response: %v", err)
	}
}

func mustPub(t *testing.T, priv [32]byte) [32]byte {
	t.Helper()
	pub, err := noise.PublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestLoadIsARateWithHysteresis pins the load decision: more than threshold
// initiations within a second puts the server under load, it stays there for
// underLoadFor after the last such second so a flood that pauses does not make
// it flap, and it leaves when the rate falls. Negative is always.
func TestLoadIsARateWithHysteresis(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := handshakeLoad{threshold: 3, now: func() time.Time { return now }}

	for i := range 3 {
		if under, _ := l.observe(); under {
			t.Fatalf("initiation %d of 3 in a second put the server under load", i+1)
		}
	}
	if under, changed := l.observe(); !under || !changed {
		t.Fatalf("the fourth initiation in a second: under=%v changed=%v, want true, true", under, changed)
	}
	now = now.Add(500 * time.Millisecond)
	if under, changed := l.observe(); !under || changed {
		t.Fatalf("half a second later: under=%v changed=%v, want still under, no change", under, changed)
	}
	now = now.Add(2 * time.Second)
	if under, changed := l.observe(); under || !changed {
		t.Fatalf("after the rate fell: under=%v changed=%v, want false, true", under, changed)
	}

	always := handshakeLoad{threshold: -1, now: time.Now}
	if under, _ := always.observe(); !under {
		t.Fatal("a negative threshold did not mean always under load")
	}
}

// TestCookieThresholdParses holds the option to its documented values: a rate,
// or -1 for always -- and an explicit 0, which the struct would otherwise read
// as "the default", meaning what it says.
func TestCookieThresholdParses(t *testing.T) {
	base := map[string]string{OptServerPrivateKey: "x"}
	for _, tc := range []struct {
		in   string
		want int
		ok   bool
	}{
		{"", 0, true},
		{"500", 500, true},
		{"-1", -1, true},
		{"0", -1, true},
		{"-2", 0, false},
		{"lots", 0, false},
	} {
		opts := map[string]string{}
		for k, v := range base {
			opts[k] = v
		}
		if tc.in != "" {
			opts[OptServerCookieThreshold] = tc.in
		}
		sc, err := ServerConfigFromOptions(opts)
		if (err == nil) != tc.ok {
			t.Errorf("%q: err = %v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && sc.CookieThreshold != tc.want {
			t.Errorf("%q: CookieThreshold = %d, want %d", tc.in, sc.CookieThreshold, tc.want)
		}
	}
}
