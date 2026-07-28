package pulse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	payload := []byte("configuration")
	raw := EncodeMessage(VendorJuniper, TypeConfig, 0x1234, payload)
	if len(raw) != HeaderLen+len(payload) {
		t.Fatalf("message is %d octets, want %d", len(raw), HeaderLen+len(payload))
	}
	if binary.BigEndian.Uint32(raw[8:12]) != uint32(len(raw)) {
		t.Errorf("the length field does not count the header: %d", binary.BigEndian.Uint32(raw[8:12]))
	}

	m, rest, err := ParseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Vendor != VendorJuniper || m.Type != TypeConfig || m.ID != 0x1234 {
		t.Errorf("header = %+v", m)
	}
	if string(m.Payload) != string(payload) {
		t.Errorf("payload = %q", m.Payload)
	}
	if len(rest) != 0 {
		t.Errorf("%d octets left over", len(rest))
	}
}

// TestParseMessageReturnsASubslice pins the property the inbound data path
// depends on: parsing hands back a view of the caller's buffer rather than a
// copy, so a decoded packet costs no allocation.
func TestParseMessageReturnsASubslice(t *testing.T) {
	raw := EncodeData(1, []byte{0x45, 0, 0, 20})
	m, _, err := ParseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[HeaderLen] = 0x60
	if m.Payload[0] != 0x60 {
		t.Error("ParseMessage copied the payload instead of aliasing it")
	}
}

// TestParseMessageStreams proves several messages in one TLS record are
// decoded one after another, which is what the data path relies on: TLS is a
// stream, so a read can land on any number of whole or partial messages.
func TestParseMessageStreams(t *testing.T) {
	var buf []byte
	for i := range 3 {
		buf = append(buf, EncodeData(uint32(i), bytes.Repeat([]byte{byte(i)}, 40))...)
	}
	rest := buf
	for i := range 3 {
		m, next, err := ParseMessage(rest)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if m.ID != uint32(i) || len(m.Payload) != 40 || m.Payload[0] != byte(i) {
			t.Errorf("message %d = %+v", i, m)
		}
		rest = next
	}
	if len(rest) != 0 {
		t.Errorf("%d octets left over", len(rest))
	}
}

// TestParseMessageRejectsTruncated covers every prefix of a valid message: a
// short one must be reported rather than read past, and a length field that
// overruns the buffer must not be trusted.
func TestParseMessageRejectsTruncated(t *testing.T) {
	full := EncodeData(1, bytes.Repeat([]byte{0xab}, 64))
	for i := range len(full) {
		if _, _, err := ParseMessage(full[:i]); err == nil {
			t.Errorf("prefix of %d octets was accepted", i)
		}
	}
	if _, _, err := ParseMessage(full); err != nil {
		t.Fatalf("the whole message was rejected: %v", err)
	}
}

// TestParseMessageRejectsUnderLength: a length field below the header size
// would make the payload slice run backwards.
func TestParseMessageRejectsUnderLength(t *testing.T) {
	raw := EncodeData(1, make([]byte, 32))
	for _, n := range []uint32{0, 1, HeaderLen - 1} {
		binary.BigEndian.PutUint32(raw[8:12], n)
		if _, _, err := ParseMessage(raw); !errors.Is(err, ErrBadLength) {
			t.Errorf("length %d gave %v, want ErrBadLength", n, err)
		}
	}
}

// TestReservedOctetIsMasked: the top octet of the first word is reserved, and a
// peer that sets it is still speaking the protocol.
func TestReservedOctetIsMasked(t *testing.T) {
	raw := EncodeData(1, make([]byte, 8))
	raw[0] = 0xff
	m, _, err := ParseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Vendor != VendorJuniper {
		t.Errorf("vendor = %#x, want %#x", m.Vendor, VendorJuniper)
	}
}

func TestReadMessage(t *testing.T) {
	raw := append(EncodeData(7, []byte("first")), EncodeData(8, []byte("second"))...)
	r := bytes.NewReader(raw)

	for i, want := range []string{"first", "second"} {
		m, err := ReadMessage(r)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if string(m.Payload) != want {
			t.Errorf("message %d payload = %q, want %q", i, m.Payload, want)
		}
	}
	if _, err := ReadMessage(r); !errors.Is(err, io.EOF) {
		t.Errorf("after the last message: %v, want EOF", err)
	}
}

// TestReadMessageBoundsTheLength: the length is peer-supplied and drives an
// allocation, so an absurd one must be refused rather than honoured.
func TestReadMessageBoundsTheLength(t *testing.T) {
	var hdr [HeaderLen]byte
	binary.BigEndian.PutUint32(hdr[8:12], maxMessage+1)
	if _, err := ReadMessage(bytes.NewReader(hdr[:])); err == nil {
		t.Fatal("an oversized message was accepted")
	}

	binary.BigEndian.PutUint32(hdr[8:12], HeaderLen-1)
	if _, err := ReadMessage(bytes.NewReader(hdr[:])); !errors.Is(err, ErrShortMessage) {
		t.Errorf("under-length message gave %v", err)
	}
}

// TestEncodeLineIsNULTerminated pins the shape of the control messages: a real
// client sends "ncmo=1\n\0" and a real server sends its client-information
// line the same way, terminator included.
func TestEncodeLineIsNULTerminated(t *testing.T) {
	raw := EncodeLine(VendorJuniper, TypeControl, 1, "ncmo=1\n")
	m, _, err := ParseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(m.Payload) != "ncmo=1\n\x00" {
		t.Errorf("payload = %q", m.Payload)
	}
}
