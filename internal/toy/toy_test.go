package toy

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

func testKey(t *testing.T) Key {
	t.Helper()
	return DeriveKey("secret", bytes.Repeat([]byte{0x11}, NonceLen), bytes.Repeat([]byte{0x22}, NonceLen))
}

func TestHeaderRoundTrip(t *testing.T) {
	want := Header{Type: MsgData, Flags: 0, Session: 0xbeef, Counter: 0x01020304}
	got, body, err := ParseHeader(AppendHeader(nil, want))
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
	if len(body) != 0 {
		t.Errorf("body = %d octets, want 0", len(body))
	}
}

func TestParseHeaderRejects(t *testing.T) {
	good := AppendHeader(nil, Header{Type: MsgData, Session: 1, Counter: 1})

	t.Run("truncated", func(t *testing.T) {
		if _, _, err := ParseHeader(good[:HeaderLen-1]); err != ErrShort {
			t.Errorf("err = %v, want ErrShort", err)
		}
	})
	t.Run("wrong magic", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[0] = 'X'
		if _, _, err := ParseHeader(bad); err != ErrNotTOY {
			t.Errorf("err = %v, want ErrNotTOY", err)
		}
	})
	t.Run("wrong version", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[3] = 99
		if _, _, err := ParseHeader(bad); err != ErrVersion {
			t.Errorf("err = %v, want ErrVersion", err)
		}
	})
}

// Every parser here reads attacker-controlled bytes, so the property that
// matters is that a truncated or lying length field is an error rather than a
// panic. Feeding each parser every prefix of a valid message is a cheap way to
// cover that exhaustively.
func TestParsersRejectEveryTruncation(t *testing.T) {
	hello := AppendHello(nil, Hello{User: "alice"})
	welcome := AppendWelcome(nil, Welcome{
		AssignedIP: netip.MustParseAddr("10.9.0.2"),
		Netmask:    netip.MustParseAddr("255.255.255.0"),
		Gateway:    netip.MustParseAddr("10.9.0.1"),
		MTU:        1400,
		DNS:        []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")},
	})
	reject := AppendReject(nil, "authentication failed")

	for _, tc := range []struct {
		name  string
		full  []byte
		parse func([]byte) error
	}{
		{"hello", hello, func(b []byte) error { _, err := ParseHello(b); return err }},
		{"welcome", welcome, func(b []byte) error { _, err := ParseWelcome(b); return err }},
		{"reject", reject, func(b []byte) error { _, err := ParseReject(b); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i := range len(tc.full) {
				// Must not panic; an error is the correct outcome.
				if err := tc.parse(tc.full[:i]); err == nil {
					t.Errorf("prefix of %d octets parsed successfully, want an error", i)
				}
			}
			if err := tc.parse(tc.full); err != nil {
				t.Errorf("the complete message failed to parse: %v", err)
			}
		})
	}
}

// A lying length prefix must be rejected rather than used to slice past the end.
func TestParseHelloRejectsOverlongUserLength(t *testing.T) {
	b := make([]byte, NonceLen+1+3)
	b[NonceLen] = 200 // claims 200 octets of username; only 3 follow
	if _, err := ParseHello(b); err != ErrMalformed {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

func TestWelcomeRoundTrip(t *testing.T) {
	want := Welcome{
		AssignedIP: netip.MustParseAddr("10.9.0.7"),
		Netmask:    netip.MustParseAddr("255.255.255.0"),
		Gateway:    netip.MustParseAddr("10.9.0.1"),
		MTU:        1400,
		DNS:        []netip.Addr{netip.MustParseAddr("1.1.1.1")},
	}
	got, err := ParseWelcome(AppendWelcome(nil, want))
	if err != nil {
		t.Fatalf("ParseWelcome: %v", err)
	}
	if got.AssignedIP != want.AssignedIP || got.Netmask != want.Netmask ||
		got.Gateway != want.Gateway || got.MTU != want.MTU {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
	if len(got.DNS) != 1 || got.DNS[0] != want.DNS[0] {
		t.Errorf("DNS = %v, want %v", got.DNS, want.DNS)
	}
}

func TestKeystreamIsItsOwnInverse(t *testing.T) {
	k := testKey(t)
	plain := []byte("the quick brown fox jumps over the lazy dog, twice over")

	buf := append([]byte(nil), plain...)
	Keystream(k, 7, buf)
	if bytes.Equal(buf, plain) {
		t.Fatal("the keystream left the payload unchanged")
	}
	Keystream(k, 7, buf)
	if !bytes.Equal(buf, plain) {
		t.Error("applying the keystream twice did not restore the plaintext")
	}
}

// The counter is mixed into the keystream, so the same plaintext at different
// counters must not produce the same ciphertext. (It is still trivially
// breakable -- see TestKeystreamRepeatsAndLeaks -- but not *that* trivially.)
func TestKeystreamVariesWithCounter(t *testing.T) {
	k := testKey(t)
	plain := bytes.Repeat([]byte{0x00}, 64)

	a := append([]byte(nil), plain...)
	b := append([]byte(nil), plain...)
	Keystream(k, 1, a)
	Keystream(k, 2, b)
	if bytes.Equal(a, b) {
		t.Error("the same plaintext encrypted identically at two counters")
	}
}

// This test exists to make the insecurity concrete rather than merely asserted.
//
// The keystream is a 32-octet pad, so two payloads encrypted under the *same*
// counter share it entirely; XORing the ciphertexts cancels the pad and yields
// the XOR of the plaintexts. Against traffic as predictable as IP headers that
// is a full break. If someone ever "fixes" this file into something that looks
// respectable, this test failing is the signal that SPEC.md's warnings need
// rewriting too.
func TestKeystreamRepeatsAndLeaks(t *testing.T) {
	k := testKey(t)

	p1 := []byte("GET /secret HTTP/1.1\r\nHost: example\r\n")
	p2 := []byte("GET /public HTTP/1.1\r\nHost: example\r\n")

	c1 := append([]byte(nil), p1...)
	c2 := append([]byte(nil), p2...)
	Keystream(k, 42, c1)
	Keystream(k, 42, c2)

	for i := range c1 {
		if c1[i]^c2[i] != p1[i]^p2[i] {
			t.Fatalf("at octet %d the pad did not cancel; the keystream is no longer a simple pad", i)
		}
	}
	// Which means: wherever the plaintexts agree, the ciphertexts agree too,
	// leaking the shape of the traffic outright.
	if c1[0] != c2[0] {
		t.Error("identical leading plaintext produced differing ciphertext")
	}
}

func TestProofVerifies(t *testing.T) {
	cn := bytes.Repeat([]byte{0xaa}, NonceLen)
	sn := bytes.Repeat([]byte{0xbb}, NonceLen)

	p := Proof("hunter2", cn, sn)
	if !CheckProof("hunter2", cn, sn, p[:]) {
		t.Error("a correct proof did not verify")
	}
	if CheckProof("wrong", cn, sn, p[:]) {
		t.Error("a proof verified under the wrong secret")
	}
	// Both nonces must be bound in, or a recorded proof would be replayable
	// against a fresh challenge.
	if CheckProof("hunter2", cn, bytes.Repeat([]byte{0xcc}, NonceLen), p[:]) {
		t.Error("a proof verified against a different server nonce")
	}
	if CheckProof("hunter2", bytes.Repeat([]byte{0xcc}, NonceLen), sn, p[:]) {
		t.Error("a proof verified against a different client nonce")
	}
}

func newTestSessions(t *testing.T) (client, server *Session) {
	t.Helper()
	k := testKey(t)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}
	routes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	return NewSession(7, k, addr, routes), NewSession(7, k, addr, routes)
}

func TestSealOpenRoundTrip(t *testing.T) {
	c, s := newTestSessions(t)

	for _, payload := range [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte{0xcd}, 1400),
		{},
	} {
		pkt, err := c.Encapsulate(payload)
		if err != nil {
			t.Fatalf("Encapsulate: %v", err)
		}
		got, err := s.Decapsulate(pkt)
		if err != nil {
			t.Fatalf("Decapsulate: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("round trip = %x, want %x", got, payload)
		}
	}
}

// The tag covers the header, so editing any of it must fail verification rather
// than take effect. This is the property a real AEAD gets by taking the header
// as additional data.
func TestTagCoversTheHeader(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{"type", 4},
		{"flags", 5},
		{"session", 6},
		{"counter", 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := newTestSessions(t)
			pkt, err := c.Encapsulate([]byte("payload"))
			if err != nil {
				t.Fatalf("Encapsulate: %v", err)
			}
			pkt[tc.offset] ^= 0xff
			if _, err := s.Decapsulate(pkt); err == nil {
				t.Errorf("a packet with an altered %s verified", tc.name)
			}
		})
	}
}

func TestCiphertextTamperingDetected(t *testing.T) {
	c, s := newTestSessions(t)
	pkt, err := c.Encapsulate([]byte("payload"))
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	pkt[HeaderLen+TagLen] ^= 0x01
	if _, err := s.Decapsulate(pkt); err != ErrBadTag {
		t.Errorf("err = %v, want ErrBadTag", err)
	}
}

func TestReplayRejected(t *testing.T) {
	c, s := newTestSessions(t)
	pkt, err := c.Encapsulate([]byte("once"))
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if _, err := s.Decapsulate(pkt); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if _, err := s.Decapsulate(pkt); err != ErrReplay {
		t.Errorf("err = %v, want ErrReplay", err)
	}
}

// UDP reorders, so packets arriving late but within the window must still be
// accepted; a strictly-increasing check would drop real traffic.
func TestOutOfOrderWithinWindowAccepted(t *testing.T) {
	c, s := newTestSessions(t)

	var pkts [][]byte
	for range 8 {
		pkt, err := c.Encapsulate([]byte("x"))
		if err != nil {
			t.Fatalf("Encapsulate: %v", err)
		}
		pkts = append(pkts, pkt)
	}

	if _, err := s.Decapsulate(pkts[7]); err != nil {
		t.Fatalf("newest packet first: %v", err)
	}
	for i := range 7 {
		if _, err := s.Decapsulate(pkts[i]); err != nil {
			t.Errorf("packet %d arriving late was rejected: %v", i, err)
		}
	}
}

// A tag must be checked before the counter touches the replay window, or anyone
// able to send a datagram could advance it and lock the real peer out.
func TestForgedPacketDoesNotAdvanceTheWindow(t *testing.T) {
	c, s := newTestSessions(t)

	// A forgery claiming a counter far ahead, with a tag that will not verify.
	forged := AppendHeader(nil, Header{Type: MsgData, Session: 7, Counter: 10_000})
	forged = append(forged, bytes.Repeat([]byte{0xff}, TagLen)...)
	forged = append(forged, []byte("junk")...)
	if _, err := s.Decapsulate(forged); err == nil {
		t.Fatal("a forged packet verified")
	}

	// The real peer's next packet must still be accepted.
	pkt, err := c.Encapsulate([]byte("legitimate"))
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if _, err := s.Decapsulate(pkt); err != nil {
		t.Errorf("a forgery locked the session out of real traffic: %v", err)
	}
}

func TestDecapsulateRejectsNonData(t *testing.T) {
	c, s := newTestSessions(t)
	ka, err := c.Keepalive()
	if err != nil {
		t.Fatalf("Keepalive: %v", err)
	}
	if _, err := s.Decapsulate(ka); err != ErrMalformed {
		t.Errorf("Decapsulate accepted a KEEPALIVE: err = %v", err)
	}

	typ, inner, err := s.OpenAny(ka)
	if err != nil {
		t.Fatalf("OpenAny: %v", err)
	}
	if typ != MsgKeepalive || len(inner) != 0 {
		t.Errorf("OpenAny = (%v, %d octets), want (KEEPALIVE, 0)", typ, len(inner))
	}
}

func TestSessionOfDemux(t *testing.T) {
	pkt := AppendHeader(nil, Header{Type: MsgData, Session: 0x1234, Counter: 5})
	key, ok := SessionOf(pkt)
	if !ok || key != 0x1234 {
		t.Errorf("SessionOf = (%d, %v), want (0x1234, true)", key, ok)
	}
	if _, ok := SessionOf([]byte("not toy at all")); ok {
		t.Error("SessionOf accepted a non-TOY datagram")
	}
}

// The digest is pinned because SPEC.md documents it as FNV-1a and an
// independent implementation has to agree octet for octet. A change here is a
// wire-format change, and the interop harness would catch it -- but slowly, and
// in a much more confusing way than this.
func TestDigestMatchesSpec(t *testing.T) {
	// FNV-1a/64 of "toy" = 0x56f9c5194465b787, computed independently from the
	// constants in SPEC.md rather than read back out of this implementation:
	//
	//	h = 0xcbf29ce484222325
	//	for b in b"toy": h = ((h ^ b) * 0x100000001b3) % 2**64
	got := digest([]byte("toy"))
	want := [TagLen]byte{0x56, 0xf9, 0xc5, 0x19, 0x44, 0x65, 0xb7, 0x87}
	if got != want {
		t.Errorf("digest(\"toy\") = %x, want %x", got, want)
	}
}
