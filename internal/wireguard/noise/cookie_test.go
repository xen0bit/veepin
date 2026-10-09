package noise

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// The cookie exchange is the textbook case of a mutually-consistent bug: both
// halves are in this package, so a wrong label, a wrong AAD or a swapped key
// would make an initiator and a checker agree perfectly with each other and
// with no real WireGuard. The tests below that matter most are therefore
// written from the PEER's side: each recomputes what wireguard-go computes,
// directly from golang.org/x/crypto and the paper's formulas, and holds this
// package to it. The round-trip tests come after, as the cheap check that the
// two halves also agree with each other.

// peerCookieKey is HASH(LABEL_COOKIE || pub), as wireguard-go's
// CookieChecker.Init and CookieGenerator.Init derive it.
func peerCookieKey(pub []byte) []byte {
	h, _ := blake2s.New256(nil)
	h.Write([]byte("cookie--"))
	h.Write(pub)
	return h.Sum(nil)
}

// peerMAC is keyed BLAKE2s-128, wireguard-go's MAC().
func peerMAC(key, data []byte) []byte {
	h, _ := blake2s.New128(key)
	h.Write(data)
	return h.Sum(nil)
}

type cookieWorld struct {
	initStatic, respStatic [KeySize]byte
	respPub                [KeySize]byte
	checker                *CookieChecker
	now                    time.Time
}

func newCookieWorld(t *testing.T, typeInitiation uint32) *cookieWorld {
	t.Helper()
	w := &cookieWorld{now: time.Unix(1_700_000_000, 0)}
	w.initStatic, _ = genKey(t)
	w.respStatic, _ = genKey(t)
	pub, err := PublicKey(w.respStatic)
	if err != nil {
		t.Fatal(err)
	}
	w.respPub = pub
	w.checker, err = NewCookieChecker(w.respStatic, typeInitiation)
	if err != nil {
		t.Fatal(err)
	}
	w.checker.Now = func() time.Time { return w.now }
	return w
}

func (w *cookieWorld) initiator(t *testing.T, typeInitiation uint32) *Initiator {
	t.Helper()
	i, err := NewInitiator(Config{LocalStatic: w.initStatic, RemoteStatic: w.respPub, TypeInitiation: typeInitiation})
	if err != nil {
		t.Fatal(err)
	}
	return i
}

var cookieSrc = netip.MustParseAddrPort("198.51.100.7:51820")

// TestOurCookieReplyIsOneWireGuardGoCanOpen. The initiator wireguard-go runs
// decrypts a cookie reply with XChaCha20-Poly1305 under HASH(LABEL_COOKIE ||
// the responder's public key), with the mac1 of its own initiation as the
// additional data, and computes mac2 over everything before mac2 with the
// cookie as key. If this fails, a veepin server under load answers every stock
// client with a reply it cannot open, and no client connects until the load
// subsides -- the opposite of what cookies are for.
func TestOurCookieReplyIsOneWireGuardGoCanOpen(t *testing.T) {
	w := newCookieWorld(t, 0)
	init, err := w.initiator(t, 0).Initiation()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := w.checker.CookieReply(init, cookieSrc)
	if err != nil {
		t.Fatal(err)
	}

	// The frame, as wireguard-go's MessageCookieReply reads it.
	if len(reply) != 64 || reply[0] != 3 || !bytes.Equal(reply[1:4], []byte{0, 0, 0}) {
		t.Fatalf("the reply is not a type-3 message with zero reserved octets: %x", reply[:4])
	}
	if got, want := binary.LittleEndian.Uint32(reply[4:8]), binary.LittleEndian.Uint32(init[4:8]); got != want {
		t.Fatalf("receiver index %#x, want the initiation's sender index %#x", got, want)
	}

	aead, err := chacha20poly1305.NewX(peerCookieKey(w.respPub[:]))
	if err != nil {
		t.Fatal(err)
	}
	mac1 := init[116:132]
	cookie, err := aead.Open(nil, reply[8:32], reply[32:64], mac1)
	if err != nil {
		t.Fatalf("an independent XChaCha20-Poly1305 open of our reply failed: %v", err)
	}

	// Then the retry, with mac2 computed as wireguard-go's AddMacs does: over
	// msg[:132] -- everything up to mac2, mac1 included -- keyed by the cookie.
	retry, err := w.initiator(t, 0).Initiation()
	if err != nil {
		t.Fatal(err)
	}
	copy(retry[132:148], peerMAC(cookie, retry[:132]))
	if !w.checker.CheckMAC2(retry, cookieSrc) {
		t.Fatal("an initiation whose mac2 was computed as wireguard-go computes it was refused")
	}
}

// TestWeOpenACookieReplyBuiltAsWireGuardGoBuildsIt is the other direction: a
// reply sealed the way wireguard-go's CookieChecker.CreateReply seals one, and
// the mac2 that follows checked against an independent computation. If this
// fails, a veepin client facing a loaded wireguard-go server can never satisfy
// it.
func TestWeOpenACookieReplyBuiltAsWireGuardGoBuildsIt(t *testing.T) {
	w := newCookieWorld(t, 0)
	i := w.initiator(t, 0)
	init, err := i.Initiation()
	if err != nil {
		t.Fatal(err)
	}

	cookie := make([]byte, 16)
	rand.Read(cookie)
	reply := make([]byte, 64)
	reply[0] = 3
	copy(reply[4:8], init[4:8])
	rand.Read(reply[8:32])
	aead, _ := chacha20poly1305.NewX(peerCookieKey(w.respPub[:]))
	aead.Seal(reply[32:32], reply[8:32], cookie, init[116:132])

	got, err := i.ConsumeCookieReply(reply)
	if err != nil {
		t.Fatalf("a reply sealed as wireguard-go seals it did not open: %v", err)
	}
	if !bytes.Equal(got[:], cookie) {
		t.Fatal("the cookie opened to the wrong bytes")
	}

	next := w.initiator(t, 0)
	next.SetCookie(got)
	retry, err := next.Initiation()
	if err != nil {
		t.Fatal(err)
	}
	if want := peerMAC(cookie, retry[:132]); !bytes.Equal(retry[132:148], want) {
		t.Fatalf("mac2 = %x, want %x: not MAC(cookie, msg[0:offsetof(mac2)])", retry[132:148], want)
	}
	if want := peerMAC(peerMAC1Key(w.respPub[:]), retry[:116]); !bytes.Equal(retry[116:132], want) {
		t.Fatal("setting a cookie changed mac1")
	}
}

// peerMAC1Key is HASH(LABEL_MAC1 || pub), wireguard-go's mac1 key.
func peerMAC1Key(pub []byte) []byte {
	h, _ := blake2s.New256(nil)
	h.Write([]byte("mac1----"))
	h.Write(pub)
	return h.Sum(nil)
}

// TestACookieIsBoundToItsAddress is what makes a cookie worth anything: it
// proves the sender can receive at the address it claims. A cookie that
// validated from another address -- another port included, since a NAT maps
// many hosts onto one address -- would let a forger who captured one reply
// spray valid initiations from anywhere.
func TestACookieIsBoundToItsAddress(t *testing.T) {
	w := newCookieWorld(t, 0)
	cookie := w.obtain(t, cookieSrc)

	i := w.initiator(t, 0)
	i.SetCookie(cookie)
	retry, err := i.Initiation()
	if err != nil {
		t.Fatal(err)
	}
	if !w.checker.CheckMAC2(retry, cookieSrc) {
		t.Fatal("the cookie did not validate from the address it was issued to")
	}
	for _, other := range []string{"198.51.100.7:51821", "198.51.100.8:51820", "[2001:db8::7]:51820"} {
		if w.checker.CheckMAC2(retry, netip.MustParseAddrPort(other)) {
			t.Errorf("a cookie issued to %v validated from %s", cookieSrc, other)
		}
	}
	// An IPv4-mapped form is the same sender, however the socket reported it.
	mapped := netip.AddrPortFrom(netip.AddrFrom16(cookieSrc.Addr().As16()), cookieSrc.Port())
	if !w.checker.CheckMAC2(retry, mapped) {
		t.Error("the IPv4-mapped form of the issuing address was refused")
	}
}

// obtain runs one cookie exchange for an initiator at src and returns the
// cookie it was given.
func (w *cookieWorld) obtain(t *testing.T, src netip.AddrPort) Cookie {
	t.Helper()
	i := w.initiator(t, 0)
	init, err := i.Initiation()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := w.checker.CookieReply(init, src)
	if err != nil {
		t.Fatal(err)
	}
	c, err := i.ConsumeCookieReply(reply)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestACookieExpiresWithItsSecret: the secret rotates every two minutes, and a
// cookie made from an expired one must stop validating. Otherwise one captured
// reply would admit its holder's initiations for as long as the server ran.
func TestACookieExpiresWithItsSecret(t *testing.T) {
	w := newCookieWorld(t, 0)
	cookie := w.obtain(t, cookieSrc)
	i := w.initiator(t, 0)
	i.SetCookie(cookie)
	retry, err := i.Initiation()
	if err != nil {
		t.Fatal(err)
	}

	w.now = w.now.Add(CookieRefreshTime)
	if !w.checker.CheckMAC2(retry, cookieSrc) {
		t.Fatal("the cookie stopped validating before its secret's lifetime was up")
	}
	w.now = w.now.Add(time.Second)
	if w.checker.CheckMAC2(retry, cookieSrc) {
		t.Fatal("a cookie from an expired secret still validated")
	}
	// And the next reply is under a fresh secret, so the old cookie stays dead.
	if _, err := w.checker.CookieReply(retry, cookieSrc); err != nil {
		t.Fatal(err)
	}
	if w.checker.CheckMAC2(retry, cookieSrc) {
		t.Fatal("a cookie from the previous secret validated against the new one")
	}
}

// TestAForgedCookieReplyIsRefused: a reply is bound to the initiation it
// answers by that initiation's mac1. One that is not -- addressed to another
// index, tampered with, or built for someone else's initiation -- must not
// change the cookie an initiator uses, or an off-path sender could make every
// retry fail by feeding it garbage.
func TestAForgedCookieReplyIsRefused(t *testing.T) {
	w := newCookieWorld(t, 0)
	i := w.initiator(t, 0)
	init, err := i.Initiation()
	if err != nil {
		t.Fatal(err)
	}
	genuine, err := w.checker.CookieReply(init, cookieSrc)
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), genuine...)
	tampered[40] ^= 1
	misaddressed := append([]byte(nil), genuine...)
	misaddressed[4] ^= 1
	otherInit, err := w.initiator(t, 0).Initiation()
	if err != nil {
		t.Fatal(err)
	}
	forOther, err := w.checker.CookieReply(otherInit, cookieSrc)
	if err != nil {
		t.Fatal(err)
	}
	copy(forOther[4:8], init[4:8]) // readdressed to us, but bound to their mac1

	for name, pkt := range map[string][]byte{
		"tampered":                   tampered,
		"addressed to another index": misaddressed,
		"for another initiation":     forOther,
	} {
		if _, err := i.ConsumeCookieReply(pkt); !errors.Is(err, ErrCookieReply) {
			t.Errorf("%s: got %v, want ErrCookieReply", name, err)
		}
	}
	if _, err := i.ConsumeCookieReply(genuine); err != nil {
		t.Fatalf("the genuine reply was refused after the forgeries: %v", err)
	}
}

// TestCookiesSurviveAmneziaWGTypes. AmneziaWG computes both MACs over the
// message with its substituted type word in place, so mac2 must be too, at
// both ends; computing it over the stock word is invisible between two veepin
// endpoints and refused by amneziawg-go.
func TestCookiesSurviveAmneziaWGTypes(t *testing.T) {
	const h1 = 0x7a3c1e55
	w := newCookieWorld(t, h1)
	i := w.initiator(t, h1)
	init, err := i.Initiation()
	if err != nil {
		t.Fatal(err)
	}
	if !w.checker.CheckMAC1(init) {
		t.Fatal("mac1 under H1 did not check")
	}
	reply, err := w.checker.CookieReply(init, cookieSrc)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := i.ConsumeCookieReply(reply)
	if err != nil {
		t.Fatal(err)
	}
	next := w.initiator(t, h1)
	next.SetCookie(cookie)
	retry, err := next.Initiation()
	if err != nil {
		t.Fatal(err)
	}
	if !w.checker.CheckMAC2(retry, cookieSrc) {
		t.Fatal("mac2 under H1 did not check")
	}
	// From the peer's side: the substituted word is what is authenticated.
	over := append([]byte(nil), retry[:132]...)
	binary.LittleEndian.PutUint32(over[0:4], h1)
	if want := peerMAC(cookie[:], over); !bytes.Equal(retry[132:148], want) {
		t.Fatal("mac2 was not computed over the H1 type word")
	}
}

// TestMAC1IsCheckedWithoutTheHandshake: CheckMAC1 is the server's first gate,
// run before the load decision, so it must refuse what Consume would refuse on
// mac1 alone -- and refuse it without spending a Diffie-Hellman.
func TestMAC1IsCheckedWithoutTheHandshake(t *testing.T) {
	w := newCookieWorld(t, 0)
	init, err := w.initiator(t, 0).Initiation()
	if err != nil {
		t.Fatal(err)
	}
	if !w.checker.CheckMAC1(init) {
		t.Fatal("a genuine initiation's mac1 did not check")
	}
	bad := append([]byte(nil), init...)
	bad[120] ^= 1
	if w.checker.CheckMAC1(bad) {
		t.Fatal("a corrupted mac1 checked")
	}
	if w.checker.CheckMAC1(init[:100]) || w.checker.CheckMAC1(append(init, 0)) {
		t.Fatal("a message of the wrong length checked")
	}
	other := newCookieWorld(t, 0)
	if other.checker.CheckMAC1(init) {
		t.Fatal("an initiation for another responder's key checked")
	}
}

// TestNoCookieMeansNoMAC2: an initiator that has not been asked for a cookie
// sends mac2 as zeros, as the paper says and every stock responder expects.
func TestNoCookieMeansNoMAC2(t *testing.T) {
	w := newCookieWorld(t, 0)
	init, err := w.initiator(t, 0).Initiation()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(init[132:148], make([]byte, wire.MACSize)) {
		t.Fatalf("mac2 = %x without a cookie, want zeros", init[132:148])
	}
	if w.checker.CheckMAC2(init, cookieSrc) {
		t.Fatal("a zero mac2 checked")
	}
}
