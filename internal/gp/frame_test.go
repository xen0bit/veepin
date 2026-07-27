package gp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestEncodeParseRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		etherType uint16
		payload   []byte
	}{
		{"ipv4", EtherTypeIPv4, []byte{0x45, 0x00, 0x00, 0x14}},
		{"ipv6", EtherTypeIPv6, []byte{0x60, 0x00, 0x00, 0x00}},
		{"empty", EtherTypeIPv4, nil},
		{"mtu-sized", EtherTypeIPv4, bytes.Repeat([]byte{0xab}, 1400)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := EncodeFrame(tc.etherType, tc.payload)
			if len(enc) != frameHeaderLen+len(tc.payload) {
				t.Fatalf("encoded length %d, want %d", len(enc), frameHeaderLen+len(tc.payload))
			}
			f, rest, err := ParseFrame(enc)
			if err != nil {
				t.Fatalf("ParseFrame: %v", err)
			}
			if len(rest) != 0 {
				t.Errorf("rest is %d bytes, want 0", len(rest))
			}
			if f.EtherType != tc.etherType {
				t.Errorf("ethertype %#04x, want %#04x", f.EtherType, tc.etherType)
			}
			if f.Kind != KindData {
				t.Errorf("kind %d, want %d", f.Kind, KindData)
			}
			if !bytes.Equal(f.Payload, tc.payload) {
				t.Errorf("payload %x, want %x", f.Payload, tc.payload)
			}
		})
	}
}

// TestHeaderBytes pins the exact octets, because the reference client checks
// them: the magic and the length are big-endian, and the kind word that follows
// is little-endian.
func TestHeaderBytes(t *testing.T) {
	enc := EncodeFrame(EtherTypeIPv4, []byte{1, 2, 3})
	want := []byte{
		0x1a, 0x2b, 0x3c, 0x4d,
		0x08, 0x00,
		0x00, 0x03,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		1, 2, 3,
	}
	if !bytes.Equal(enc, want) {
		t.Errorf("header is\n%x\nwant\n%x", enc, want)
	}
}

func TestKeepalive(t *testing.T) {
	ka := EncodeKeepalive()
	if len(ka) != frameHeaderLen {
		t.Fatalf("keepalive is %d bytes, want %d", len(ka), frameHeaderLen)
	}
	f, rest, err := ParseFrame(ka)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("rest is %d bytes, want 0", len(rest))
	}
	if !f.IsKeepalive() {
		t.Errorf("keepalive not recognised: kind=%d payload=%d", f.Kind, len(f.Payload))
	}
	// A data packet with a body must not read as a keepalive.
	data, _, err := ParseFrame(EncodeFrame(EtherTypeIPv4, []byte{0x45}))
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if data.IsKeepalive() {
		t.Error("a data packet reads as a keepalive")
	}
}

func TestParseStream(t *testing.T) {
	var buf []byte
	buf = append(buf, EncodeFrame(EtherTypeIPv4, []byte{1})...)
	buf = append(buf, EncodeKeepalive()...)
	buf = append(buf, EncodeFrame(EtherTypeIPv6, []byte{2, 3})...)

	var got [][]byte
	rest := buf
	for len(rest) > 0 {
		var f Frame
		var err error
		f, rest, err = ParseFrame(rest)
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		got = append(got, f.Payload)
	}
	if len(got) != 3 {
		t.Fatalf("parsed %d packets, want 3", len(got))
	}
	if !bytes.Equal(got[0], []byte{1}) || len(got[1]) != 0 || !bytes.Equal(got[2], []byte{2, 3}) {
		t.Errorf("payloads %x", got)
	}
}

// TestParseRejects covers every way a packet can be malformed, and requires the
// "not all here yet" case to be distinguishable from the broken ones.
func TestParseRejects(t *testing.T) {
	full := EncodeFrame(EtherTypeIPv4, []byte{1, 2, 3, 4})

	cases := []struct {
		name string
		buf  []byte
		want error
	}{
		{"empty", nil, ErrShortFrame},
		{"truncated header", full[:frameHeaderLen-1], ErrShortFrame},
		{"truncated body", full[:len(full)-1], ErrShortFrame},
		{"bad magic", func() []byte {
			b := append([]byte(nil), full...)
			b[0] ^= 0xff
			return b
		}(), ErrBadMagic},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseFrame(tc.buf); !errors.Is(err, tc.want) {
				t.Errorf("error %v, want %v", err, tc.want)
			}
		})
	}

	// Every truncation of a valid packet must be rejected, never accepted short.
	for i := range len(full) {
		if _, _, err := ParseFrame(full[:i]); err == nil {
			t.Errorf("truncation to %d bytes was accepted", i)
		}
	}
}

func TestReadFrame(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(EncodeFrame(EtherTypeIPv4, []byte{9, 8, 7}))
	buf.Write(EncodeKeepalive())

	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(f.Payload, []byte{9, 8, 7}) {
		t.Errorf("payload %x, want 090807", f.Payload)
	}
	// The reader must have stopped exactly at the packet boundary.
	f, err = ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame (keepalive): %v", err)
	}
	if !f.IsKeepalive() {
		t.Error("second packet is not the keepalive")
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Errorf("error at end of stream %v, want EOF", err)
	}
}

func TestReadFrameRejectsBadMagic(t *testing.T) {
	bad := EncodeFrame(EtherTypeIPv4, []byte{1})
	bad[3] ^= 0xff
	if _, err := ReadFrame(bytes.NewReader(bad)); !errors.Is(err, ErrBadMagic) {
		t.Errorf("error %v, want %v", err, ErrBadMagic)
	}
}

// TestReadFrameTruncatedBody proves ReadFrame reports a short body rather than
// returning a packet padded with whatever the buffer held.
func TestReadFrameTruncatedBody(t *testing.T) {
	full := EncodeFrame(EtherTypeIPv4, bytes.Repeat([]byte{7}, 40))
	if _, err := ReadFrame(bytes.NewReader(full[:len(full)-10])); err == nil {
		t.Error("a truncated body was accepted")
	}
}

func TestEtherTypeFor(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want uint16
		ok   bool
	}{
		{"ipv4", []byte{0x45, 0, 0, 20}, EtherTypeIPv4, true},
		{"ipv6", []byte{0x60, 0, 0, 0}, EtherTypeIPv6, true},
		{"empty", nil, 0, false},
		{"not ip", []byte{0x00}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := EtherTypeFor(tc.pkt)
			if got != tc.want || ok != tc.ok {
				t.Errorf("EtherTypeFor = %#04x, %v; want %#04x, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestOversizeLengthIsRejected proves the ceiling is enforced from the header
// alone, before any allocation sized by it.
func TestOversizeLengthIsRejected(t *testing.T) {
	// maxFramePayload is the 16-bit ceiling, so a length field cannot exceed it;
	// what must not happen is ReadFrame allocating for a body that never arrives.
	var hdr [frameHeaderLen]byte
	binary.BigEndian.PutUint32(hdr[0:4], frameMagic)
	binary.BigEndian.PutUint16(hdr[4:6], EtherTypeIPv4)
	binary.BigEndian.PutUint16(hdr[6:8], 0xffff)
	binary.LittleEndian.PutUint32(hdr[8:12], KindData)
	if _, err := ReadFrame(bytes.NewReader(hdr[:])); !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Errorf("error %v, want an EOF for the body that never came", err)
	}
}
