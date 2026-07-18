package l2tp

import (
	"bytes"
	"testing"
)

func TestControlRoundTrip(t *testing.T) {
	var b avpBuilder
	b.addUint16(avpMessageType, msgSCCRQ)
	b.add(avpProtocolVersion, []byte{1, 0})
	b.addUint32(avpFramingCapabilities, 0x00000003)
	b.add(avpHostName, []byte("veepin"))
	b.addUint16(avpAssignedTunnelID, 0x1234)
	b.addUint16(avpReceiveWindowSize, 4)

	pkt := marshalControl(0, 0, 7, 9, b.bytes())

	h, err := parseHeader(pkt)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if !h.isControl {
		t.Error("expected a control message")
	}
	if !h.hasSeq || h.ns != 7 || h.nr != 9 {
		t.Errorf("seq = (%d,%d), want (7,9)", h.ns, h.nr)
	}

	avps, err := parseAVPs(h.payload)
	if err != nil {
		t.Fatalf("parseAVPs: %v", err)
	}
	if mt, ok := messageType(avps); !ok || mt != msgSCCRQ {
		t.Errorf("messageType = %d (ok=%v), want SCCRQ", mt, ok)
	}
	if tid, ok := findUint16(avps, avpAssignedTunnelID); !ok || tid != 0x1234 {
		t.Errorf("assigned tunnel id = %d (ok=%v), want 0x1234", tid, ok)
	}
	if hn, ok := findAVP(avps, avpHostName); !ok || string(hn) != "veepin" {
		t.Errorf("host name = %q (ok=%v), want veepin", hn, ok)
	}
}

func TestDataRoundTrip(t *testing.T) {
	ppp := []byte{0xff, 0x03, 0x00, 0x21, 0xde, 0xad}
	pkt := marshalData(0xaaaa, 0xbbbb, ppp)

	h, err := parseHeader(pkt)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if h.isControl {
		t.Error("expected a data message")
	}
	if h.tunnelID != 0xaaaa || h.sessionID != 0xbbbb {
		t.Errorf("ids = (%x,%x), want (aaaa,bbbb)", h.tunnelID, h.sessionID)
	}
	if !bytes.Equal(h.payload, ppp) {
		t.Errorf("payload = %x, want %x", h.payload, ppp)
	}
}

func TestParseRejectsHiddenAVP(t *testing.T) {
	// An AVP with the H (hidden) bit set must be rejected, not mis-parsed.
	hidden := []byte{0xc0, 0x08, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22} // M+H, len 8
	if _, err := parseAVPs(hidden); err == nil {
		t.Error("parseAVPs accepted a hidden AVP")
	}
}

func TestParseRejectsShort(t *testing.T) {
	if _, err := parseHeader([]byte{0xc8, 0x02, 0x00}); err == nil {
		t.Error("parseHeader accepted a truncated datagram")
	}
}

func TestSeqLess(t *testing.T) {
	cases := []struct {
		a, b uint16
		want bool
	}{
		{0, 1, true},
		{1, 0, false},
		{5, 5, false},
		{0xffff, 0, true},  // wraps forward
		{0, 0xffff, false}, // wraps backward
	}
	for _, c := range cases {
		if got := seqLess(c.a, c.b); got != c.want {
			t.Errorf("seqLess(%d,%d) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
