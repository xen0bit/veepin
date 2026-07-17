package sshtun

import (
	"bytes"
	"testing"
)

func TestOpenDataRoundTrip(t *testing.T) {
	b := OpenData(ModePointToPoint, TunIDAny)
	mode, unit, ok := ParseOpenData(b)
	if !ok {
		t.Fatal("ParseOpenData reported not ok")
	}
	if mode != ModePointToPoint || unit != TunIDAny {
		t.Errorf("mode/unit = %d/%#x, want %d/%#x", mode, unit, ModePointToPoint, TunIDAny)
	}
	if _, _, ok := ParseOpenData(b[:4]); ok {
		t.Error("ParseOpenData accepted a short buffer")
	}
}

func TestEncodeDecodeIPv4(t *testing.T) {
	pkt := []byte{0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4} // IPv4 (version nibble 4)
	frame := Encode(pkt)
	if frame == nil {
		t.Fatal("Encode returned nil for an IPv4 packet")
	}
	// AF_INET = 2, network byte order.
	if !bytes.Equal(frame[:4], []byte{0, 0, 0, 2}) {
		t.Errorf("IPv4 header = %x, want 00000002", frame[:4])
	}
	got, ok := Decode(frame)
	if !ok || !bytes.Equal(got, pkt) {
		t.Errorf("Decode round trip = %x (ok=%v), want %x", got, ok, pkt)
	}
}

func TestEncodeIPv6(t *testing.T) {
	pkt := []byte{0x60, 0, 0, 0, 0, 0, 0, 0} // IPv6 (version nibble 6)
	frame := Encode(pkt)
	if frame == nil {
		t.Fatal("Encode returned nil for an IPv6 packet")
	}
	if !bytes.Equal(frame[:4], []byte{0, 0, 0, 10}) { // AF_INET6 = 10
		t.Errorf("IPv6 header = %x, want 0000000a", frame[:4])
	}
}

func TestEncodeRejectsNonIP(t *testing.T) {
	if Encode([]byte{0x00}) != nil {
		t.Error("Encode accepted a non-IP packet")
	}
	if Encode(nil) != nil {
		t.Error("Encode accepted an empty packet")
	}
}

func TestDecodeShort(t *testing.T) {
	if _, ok := Decode([]byte{0, 0, 0}); ok {
		t.Error("Decode accepted a frame shorter than the header")
	}
}

func TestReadPacketFramesStream(t *testing.T) {
	// Two IPv4 packets (20-octet header + a byte of payload), encoded back-to-back
	// on a stream, must be recovered individually even though the stream has no
	// message boundaries.
	p1 := make([]byte, 21)
	p1[0] = 0x45
	p1[3] = 21 // total length
	p1[20] = 0xaa
	p2 := make([]byte, 20)
	p2[0] = 0x45
	p2[3] = 20 // total length
	stream := append(append([]byte{}, Encode(p1)...), Encode(p2)...)

	r := bytes.NewReader(stream)
	got1, err := ReadPacket(r)
	if err != nil || !bytes.Equal(got1, p1) {
		t.Fatalf("packet 1 = %x (err %v), want %x", got1, err, p1)
	}
	got2, err := ReadPacket(r)
	if err != nil || !bytes.Equal(got2, p2) {
		t.Fatalf("packet 2 = %x (err %v), want %x", got2, err, p2)
	}
}
