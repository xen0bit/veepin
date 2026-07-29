package l2tpv3

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"testing"
)

// TestEncodeDecodeRoundTrip: a frame survives encode/decode byte-identically
// across every combination of cookie length and sublayer presence.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		session  uint32
		cookie   []byte
		sublayer bool
		frame    []byte
	}{
		{
			name:    "no cookie, no sublayer",
			session: 1,
			frame:   ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("hello")),
		},
		{
			name:    "4-octet cookie, no sublayer",
			session: 42,
			cookie:  []byte{0xde, 0xad, 0xbe, 0xef},
			frame:   ethernetFrame("aa:bb:cc:dd:ee:ff", "00:01:02:03:04:05", 0x0800, []byte("IP packet")),
		},
		{
			name:     "8-octet cookie, sublayer",
			session:  0xffffffff,
			cookie:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
			sublayer: true,
			frame:    ethernetFrame("00:00:00:00:00:01", "00:00:00:00:00:02", 0x86DD, []byte("IPv6")),
		},
		{
			name:     "no cookie, sublayer",
			session:  7,
			sublayer: true,
			frame:    ethernetFrame("01:02:03:04:05:06", "07:08:09:0a:0b:0c", 0x0806, arpPacket()),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := EncodeData(nil, tc.session, tc.cookie, tc.sublayer, tc.frame)

			sid, frame, err := DecodeData(encoded, tc.cookie, tc.sublayer)
			if err != nil {
				t.Fatalf("DecodeData: %v", err)
			}
			if sid != tc.session {
				t.Errorf("session ID = %d, want %d", sid, tc.session)
			}
			if !bytes.Equal(frame, tc.frame) {
				t.Errorf("frame mismatch:\ngot  %x\nwant %x", frame, tc.frame)
			}
		})
	}
}

// TestDecodeReturnsASubsliceOfItsInput: the inbound path is allocation-free by
// design, so the frame must alias the packet rather than copy it.
func TestDecodeReturnsASubsliceOfItsInput(t *testing.T) {
	orig := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("payload"))
	cookie := []byte{1, 2, 3, 4}
	pkt := EncodeData(nil, 9, cookie, true, orig)

	_, frame, err := DecodeData(pkt, cookie, true)
	if err != nil {
		t.Fatalf("DecodeData: %v", err)
	}
	// Mutating the packet must be visible through the returned frame.
	pkt[len(pkt)-1] ^= 0xff
	if frame[len(frame)-1] != pkt[len(pkt)-1] {
		t.Fatal("DecodeData copied the frame; it must return a subslice of its input")
	}
}

// TestRejectEveryTruncation: every prefix of a valid packet is either rejected
// or decoded without reading out of bounds.
func TestRejectEveryTruncation(t *testing.T) {
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("data"))
	cookie := []byte{1, 2, 3, 4}
	valid := EncodeData(nil, 1, cookie, true, frame)
	hdrLen := DataHeaderLen(len(cookie), true)

	for i := range len(valid) {
		_, _, err := DecodeData(valid[:i], cookie, true)
		if i < hdrLen {
			if err == nil {
				t.Fatalf("prefix of %d octets (header is %d) decoded without error", i, hdrLen)
			}
			continue
		}
		if err != nil {
			t.Fatalf("prefix of %d octets: unexpected error %v", i, err)
		}
	}
}

// TestSublayerZeroIsStillPresent guards against a tidy-up that would treat an
// all-zeros sublayer as absent. Linux emits one even with sequencing off, so
// inferring presence from content mis-frames every packet the kernel sends.
func TestSublayerZeroIsStillPresent(t *testing.T) {
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("test"))
	encoded := EncodeData(nil, 1, nil, true, frame)

	if got := encoded[8:12]; !bytes.Equal(got, make([]byte, 4)) {
		t.Errorf("sublayer = %x, want four zero octets", got)
	}
	// Decoded as a session WITH a sublayer, the frame starts after it...
	_, withSub, err := DecodeData(encoded, nil, true)
	if err != nil {
		t.Fatalf("DecodeData(sublayer=true): %v", err)
	}
	if !bytes.Equal(withSub, frame) {
		t.Errorf("frame mismatch with sublayer:\ngot  %x\nwant %x", withSub, frame)
	}
	// ...and decoding the same bytes as a session WITHOUT one yields a frame
	// shifted by four octets. That is the mis-framing this test exists to name.
	_, noSub, err := DecodeData(encoded, nil, false)
	if err != nil {
		t.Fatalf("DecodeData(sublayer=false): %v", err)
	}
	if bytes.Equal(noSub, frame) {
		t.Error("a sublayer session decoded as sublayer-less produced the same frame; " +
			"presence must be a session property, not inferred")
	}
}

// TestEncodeZeroesTheSublayerOnAReusedBuffer: EncodeData reuses the caller's
// buffer, so the sublayer must be written, not assumed zero. Left unwritten it
// would leak the previous packet's bytes into the header.
func TestEncodeZeroesTheSublayerOnAReusedBuffer(t *testing.T) {
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("second"))
	buf := make([]byte, 0, 2048)
	// Dirty the buffer where the sublayer will land.
	dirty := buf[:32]
	for i := range dirty {
		dirty[i] = 0xff
	}

	out := EncodeData(buf, 1, nil, true, frame)
	if got := out[8:12]; !bytes.Equal(got, make([]byte, 4)) {
		t.Errorf("sublayer on a reused buffer = %x, want four zero octets", got)
	}
}

// TestCookieIsChosenByTheReceiver is the direction guard, written from the
// kernel's point of view.
//
// RFC 3931 makes the cookie a property of the receiver: each end picks what it
// wants to see and tells the peer. If the two cookies are swapped at BOTH ends
// a veepin-to-veepin tunnel still passes -- both halves are wrong the same way
// -- and only a real peer notices. So this test asserts the asymmetric case:
// what the kernel expects on its receive side is what we must put on our send
// side, and a packet bearing the other direction's cookie is rejected.
func TestCookieIsChosenByTheReceiver(t *testing.T) {
	// Two different cookies, one per direction, as `ip l2tp add session` allows.
	kernelExpects := mustHex(t, "aabbccdd") // the kernel's receive side
	weExpect := mustHex(t, "1122334455667788")

	cfg := &SessionConfig{
		LocalSessionID:  10,
		RemoteSessionID: 20,
		LocalCookie:     weExpect,      // verified on what we receive
		RemoteCookie:    kernelExpects, // written on what we send
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("ping"))
	ours := EncodeData(nil, cfg.RemoteSessionID, cfg.RemoteCookie, false, frame)

	// The kernel decodes with the cookie IT chose. This must succeed.
	if _, _, err := DecodeData(ours, kernelExpects, false); err != nil {
		t.Fatalf("the peer rejected our packet: %v; we must send the cookie the RECEIVER chose", err)
	}

	// Decoding with our own cookie must fail -- that is the swapped wiring.
	if _, _, err := DecodeData(ours, weExpect, false); !errors.Is(err, ErrCookie) {
		t.Fatalf("a packet carrying the peer's cookie verified against ours (err=%v); "+
			"the two directions are not interchangeable", err)
	}
}

// TestDecodeRejectsAWrongCookie: the cookie is a check value against
// mis-delivery and blind insertion (RFC 3931 section 4.1.2.1). Accepting any
// cookie makes the field decorative.
func TestDecodeRejectsAWrongCookie(t *testing.T) {
	good := mustHex(t, "0011223344556677")
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("x"))
	pkt := EncodeData(nil, 1, good, false, frame)

	for _, bad := range []string{
		"0011223344556678", // last octet differs
		"8011223344556677", // first octet differs
		"0000000000000000",
	} {
		if _, _, err := DecodeData(pkt, mustHex(t, bad), false); !errors.Is(err, ErrCookie) {
			t.Errorf("cookie %s accepted (err=%v), want ErrCookie", bad, err)
		}
	}
}

// TestDecodeRejectsControlMessages: T=1 means a control message, which has a
// different layout and must never be parsed as data.
func TestDecodeRejectsControlMessages(t *testing.T) {
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("x"))
	pkt := EncodeData(nil, 1, nil, false, frame)
	pkt[0] |= 0x80 // set T

	if _, _, err := DecodeData(pkt, nil, false); !errors.Is(err, ErrControl) {
		t.Fatalf("control message accepted as data (err=%v)", err)
	}
}

// TestVersionIsTheLowNibble pins the first word's layout: the T bit is the MSB
// and the version is the LOW four bits, with eleven unassigned bits between.
// Comparing the whole word against 3 happens to work against Linux, which
// zeroes those bits, and rejects any peer that sets one.
func TestVersionIsTheLowNibble(t *testing.T) {
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("x"))
	pkt := EncodeData(nil, 1, nil, false, frame)

	// Set an unassigned x bit. The version is unchanged, so this must decode.
	pkt[0] |= 0x40
	if _, _, err := DecodeData(pkt, nil, false); err != nil {
		t.Fatalf("an unassigned flag bit was read as part of the version: %v", err)
	}

	// Now corrupt the version nibble itself. This must be rejected.
	pkt[1] = (pkt[1] &^ 0x0f) | 2
	if _, _, err := DecodeData(pkt, nil, false); !errors.Is(err, ErrVersion) {
		t.Fatalf("version 2 accepted (err=%v), want ErrVersion", err)
	}
}

// TestDataHeaderLen pins the header sizes the MTU arithmetic depends on.
func TestDataHeaderLen(t *testing.T) {
	tests := []struct {
		cookieLen int
		sublayer  bool
		want      int
	}{
		{0, false, 8}, {4, false, 12}, {8, false, 16},
		{0, true, 12}, {4, true, 16}, {8, true, 20},
	}
	for _, tc := range tests {
		if got := DataHeaderLen(tc.cookieLen, tc.sublayer); got != tc.want {
			t.Errorf("DataHeaderLen(%d, %v) = %d, want %d", tc.cookieLen, tc.sublayer, got, tc.want)
		}
	}
}

// TestValidateRejectsAnUnrepresentableCookie: RFC 3931 allows 0, 4 or 8 octets
// and nothing else, and the length is not on the wire -- both ends just have to
// agree. A 6-octet cookie would silently mis-frame every packet.
func TestValidateRejectsAnUnrepresentableCookie(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 6, 7, 9, 16} {
		cfg := &SessionConfig{LocalSessionID: 1, RemoteSessionID: 2, LocalCookie: make([]byte, n)}
		if err := cfg.Validate(); !errors.Is(err, ErrCookieLen) {
			t.Errorf("a %d-octet cookie was accepted (err=%v)", n, err)
		}
	}
	for _, n := range []int{0, 4, 8} {
		cfg := &SessionConfig{LocalSessionID: 1, RemoteSessionID: 2, LocalCookie: make([]byte, n)}
		if err := cfg.Validate(); err != nil {
			t.Errorf("a %d-octet cookie was rejected: %v", n, err)
		}
	}
}

// TestValidateRejectsAZeroSessionID: session ID 0 is reserved for control
// messages, so a data session cannot use it (RFC 3931 section 4.1.2.1).
func TestValidateRejectsAZeroSessionID(t *testing.T) {
	if err := (&SessionConfig{RemoteSessionID: 1}).Validate(); err == nil {
		t.Error("a zero local session ID was accepted")
	}
	if err := (&SessionConfig{LocalSessionID: 1}).Validate(); err == nil {
		t.Error("a zero remote session ID was accepted")
	}
}

// TestOverheadMatchesTheEncodedHeader ties the MTU arithmetic to what
// EncodeData actually emits, so the two cannot drift apart.
func TestOverheadMatchesTheEncodedHeader(t *testing.T) {
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("payload"))
	for _, cookieLen := range []int{0, 4, 8} {
		for _, sublayer := range []bool{false, true} {
			cfg := &SessionConfig{
				LocalSessionID: 1, RemoteSessionID: 2,
				RemoteCookie: make([]byte, cookieLen), Sublayer: sublayer,
			}
			pkt := EncodeData(nil, 2, cfg.RemoteCookie, sublayer, frame)
			if got := len(pkt) - len(frame); got != cfg.Overhead() {
				t.Errorf("cookie=%d sublayer=%v: encoded overhead %d, Overhead() reports %d",
					cookieLen, sublayer, got, cfg.Overhead())
			}
		}
	}
}

// helpers

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func ethernetFrame(dstMAC, srcMAC string, etherType uint16, payload []byte) []byte {
	frame := make([]byte, 0, 14+len(payload))
	frame = append(frame, macBytes(dstMAC)...)
	frame = append(frame, macBytes(srcMAC)...)
	frame = append(frame, byte(etherType>>8), byte(etherType))
	return append(frame, payload...)
}

func macBytes(s string) []byte {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}

func arpPacket() []byte {
	pkt := make([]byte, 28)
	binary.BigEndian.PutUint16(pkt[0:], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(pkt[2:], 0x0800) // protocol type: IPv4
	pkt[4], pkt[5] = 6, 4                       // hardware/protocol address sizes
	binary.BigEndian.PutUint16(pkt[6:], 1)      // opcode: request
	return pkt
}
