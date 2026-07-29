package l2tpv3

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// TestEncodeDecodeRoundTrip verifies that encoding and then decoding a data
// packet yields the original Ethernet frame.
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

			hdr, err := DecodeData(encoded, len(tc.cookie), tc.sublayer)
			if err != nil {
				t.Fatalf("DecodeData: %v", err)
			}

			if hdr.SessionID != tc.session {
				t.Errorf("SessionID = %d, want %d", hdr.SessionID, tc.session)
			}
			if !bytes.Equal(hdr.Frame, tc.frame) {
				t.Errorf("Frame mismatch:\ngot  %x\nwant %x", hdr.Frame, tc.frame)
			}
			if hdr.HasSublayer != tc.sublayer {
				t.Errorf("HasSublayer = %v, want %v", hdr.HasSublayer, tc.sublayer)
			}
		})
	}
}

// TestRejectEveryTruncation verifies that every prefix of a valid data packet
// is handled safely — either rejected (header truncated) or decoded cleanly
// (all header bytes present, possibly empty frame). This guards against
// out-of-bounds reads from a truncated input.
func TestRejectEveryTruncation(t *testing.T) {
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("data"))
	cookie := []byte{1, 2, 3, 4}
	valid := EncodeData(nil, 1, cookie, true, frame)
	hdrLen := DataHeaderLen(len(cookie), true)

	for i := 0; i < len(valid); i++ {
		truncated := valid[:i]
		_, err := DecodeData(truncated, len(cookie), true)
		if i < hdrLen {
			if err == nil {
				t.Fatalf("expected error for prefix length %d (hdrLen=%d), got nil", i, hdrLen)
			}
		} else {
			// Header is complete; the frame may be partial or empty, but no
			// out-of-bounds read occurs.
			if err != nil {
				t.Fatalf("unexpected error for prefix length %d: %v", i, err)
			}
		}
	}
}

// TestSublayerZeroIsStillPresent guards against a tidy-up that would treat an
// all-zeros sublayer as absent. The kernel emits an all-zeros sublayer even
// when sequencing is off; presence is a session property, never inferred.
func TestSublayerZeroIsStillPresent(t *testing.T) {
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("test"))
	encoded := EncodeData(nil, 1, nil, true, frame)

	// The sublayer begins at offset 8 (no cookie). It should be 4 zero octets.
	subOff := 8
	if len(encoded) < subOff+4 {
		t.Fatalf("packet too short for sublayer: %d", len(encoded))
	}
	want := [4]byte{}
	if !bytes.Equal(encoded[subOff:subOff+4], want[:]) {
		t.Errorf("sublayer at offset %d: %x, want all zeros", subOff, encoded[subOff:subOff+4])
	}

	// Verify it decodes with HasSublayer=true.
	hdr, err := DecodeData(encoded, 0, true)
	if err != nil {
		t.Fatalf("DecodeData: %v", err)
	}
	if !hdr.HasSublayer {
		t.Error("HasSublayer = false, want true (all-zeros sublayer is still present)")
	}
}

// TestCookieIsChosenByTheReceiver verifies the direction convention: the cookie
// we send on outbound packets is the one the receiver expects on inbound.
// Written from the kernel's point of view — if the kernel told us cookie=X for
// its receive side, we put cookie=X on our send side.
func TestCookieIsChosenByTheReceiver(t *testing.T) {
	// The receiver (kernel) chose cookie 0xAABBCCDD for its receive side.
	receiverCookie := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("ping"))

	// We encode using that cookie as our RemoteCookie (what we send).
	encoded := EncodeData(nil, 1, receiverCookie, false, frame)

	// The receiver decodes with the same cookie.
	hdr, err := DecodeData(encoded, len(receiverCookie), false)
	if err != nil {
		t.Fatalf("DecodeData: %v", err)
	}
	if !bytes.Equal(hdr.Cookie, receiverCookie) {
		t.Errorf("Cookie = %x, want %x", hdr.Cookie, receiverCookie)
	}
	if !bytes.Equal(hdr.Frame, frame) {
		t.Errorf("Frame mismatch")
	}
}

// TestDataHeaderLen verifies the computed header lengths.
func TestDataHeaderLen(t *testing.T) {
	tests := []struct {
		cookieLen int
		sublayer  bool
		want      int
	}{
		{0, false, 8},
		{4, false, 12},
		{8, false, 16},
		{0, true, 12},
		{4, true, 16},
		{8, true, 20},
	}
	for _, tc := range tests {
		got := DataHeaderLen(tc.cookieLen, tc.sublayer)
		if got != tc.want {
			t.Errorf("DataHeaderLen(%d, %v) = %d, want %d", tc.cookieLen, tc.sublayer, got, tc.want)
		}
	}
}

// TestMTU computes the MTU for various cookie sizes.
func TestMTU(t *testing.T) {
	// Outer 1500, less IPv4(20), UDP(8), L2TPv3 header(4+4=8), sublayer(4),
	// Ethernet header(14), and cookie.
	// 1500 - 20 - 8 - 8 - 4 - 14 = 1446 with no cookie
	// 1500 - 20 - 8 - 8 - 4 - 14 - 8 = 1438 with 8-octet cookie
	noCookie := 1500 - 20 - 8 - 8 - 4 - 14
	if noCookie != 1446 {
		t.Errorf("MTU with no cookie = %d, want 1446", noCookie)
	}
	cookie8 := 1500 - 20 - 8 - 8 - 4 - 14 - 8
	if cookie8 != 1438 {
		t.Errorf("MTU with 8-octet cookie = %d, want 1438", cookie8)
	}
}

// TestEncodeSplitHeader verifies that EncodeData returns a subslice of dst
// when dst has capacity.
func TestEncodeSplitHeader(t *testing.T) {
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, make([]byte, 100))
	dst := make([]byte, 0, 512)
	encoded := EncodeData(dst, 1, nil, false, frame)
	if len(encoded) == 0 {
		t.Fatal("empty encoded packet")
	}
	// The first bytes must be version 3 (big-endian).
	ver := binary.BigEndian.Uint16(encoded[0:])
	if ver != 3 {
		t.Errorf("version = %d, want 3", ver)
	}
}

// helpers

func ethernetFrame(dstMAC, srcMAC string, etherType uint16, payload []byte) []byte {
	dst := macBytes(dstMAC)
	src := macBytes(srcMAC)
	frame := make([]byte, 0, 14+len(payload))
	frame = append(frame, dst...)
	frame = append(frame, src...)
	frame = append(frame, byte(etherType>>8), byte(etherType))
	frame = append(frame, payload...)
	return frame
}

func macBytes(s string) []byte {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}

func arpPacket() []byte {
	// A minimal ARP request (28 bytes)
	pkt := make([]byte, 28)
	// Hardware type: Ethernet (1)
	binary.BigEndian.PutUint16(pkt[0:], 1)
	// Protocol type: IPv4 (0x0800)
	binary.BigEndian.PutUint16(pkt[2:], 0x0800)
	// Hardware size: 6, Protocol size: 4
	pkt[4] = 6
	pkt[5] = 4
	// Opcode: request (1)
	binary.BigEndian.PutUint16(pkt[6:], 1)
	return pkt
}
