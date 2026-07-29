package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// TestTCPLengthIncludesItself is the off-by-two guard.
//
// RFC 8229 section 3 defines the Length as "Length of the IKE packet, including
// the Length field and non-ESP marker" -- so a 4-octet payload is framed as
// length 6, not 4. Getting this wrong puts the stream two octets out of phase
// on the very first message, and does so silently: the next read still returns
// bytes, they are just the wrong ones.
func TestTCPLengthIncludesItself(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	frame := appendTCPFrame(nil, payload)

	if got := binary.BigEndian.Uint16(frame); int(got) != tcpLenSize+len(payload) {
		t.Errorf("Length = %d for a %d-octet payload, want %d (the length counts itself)",
			got, len(payload), tcpLenSize+len(payload))
	}
	if len(frame) != tcpLenSize+len(payload) {
		t.Errorf("frame is %d octets, want %d", len(frame), tcpLenSize+len(payload))
	}
}

// TestTCPIKEFrameCarriesTheNonESPMarker: inside the stream an IKE message is
// distinguished from ESP by the same 4-octet zero marker used on UDP 4500, and
// the length counts it.
func TestTCPIKEFrameCarriesTheNonESPMarker(t *testing.T) {
	ike := []byte{0xaa, 0xbb}
	frame := appendTCPIKE(nil, ike)

	want := tcpLenSize + len(nonESPMarker) + len(ike)
	if got := binary.BigEndian.Uint16(frame); int(got) != want {
		t.Errorf("Length = %d, want %d (length + marker + message)", got, want)
	}
	payload := frame[tcpLenSize:]
	if !tcpFrameIsIKE(payload) {
		t.Error("an IKE frame's payload was not recognised as IKE")
	}
	if !bytes.Equal(payload[len(nonESPMarker):], ike) {
		t.Errorf("message after the marker = %x, want %x", payload[len(nonESPMarker):], ike)
	}
}

// TestTCPFrameIsIKEDistinguishesESP: an ESP packet begins with a non-zero SPI
// and carries no marker, so it must not be taken for IKE.
func TestTCPFrameIsIKEDistinguishesESP(t *testing.T) {
	esp := []byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1}
	if tcpFrameIsIKE(esp) {
		t.Error("an ESP packet was taken for an IKE message")
	}
	if tcpFrameIsIKE([]byte{0, 0, 0}) {
		t.Error("a 3-octet payload cannot carry a 4-octet marker but was called IKE")
	}
}

// TestTCPReaderSplitsAStream: several frames written back to back come out one
// at a time, byte-identical.
func TestTCPReaderSplitsAStream(t *testing.T) {
	msgs := [][]byte{
		{1},
		bytes.Repeat([]byte{0x5a}, 300),
		{0, 0, 0, 0, 'i', 'k', 'e'},
	}
	var stream []byte
	for _, m := range msgs {
		stream = appendTCPFrame(stream, m)
	}

	r := newTCPReader(bytes.NewReader(stream))
	for i, want := range msgs {
		got, err := r.Next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("frame %d:\ngot  %x\nwant %x", i, got, want)
		}
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("after the last frame: err = %v, want EOF", err)
	}
}

// TestTCPReaderReassemblesAcrossReads: a stream is a stream, so a frame may
// arrive in arbitrarily small pieces. The reader must not assume one read
// yields one frame.
func TestTCPReaderReassemblesAcrossReads(t *testing.T) {
	want := bytes.Repeat([]byte{0x42}, 500)
	stream := appendTCPFrame(nil, want)

	r := newTCPReader(&drip{data: stream, n: 1}) // one octet per Read
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("reassembled frame differs:\ngot  %d octets\nwant %d", len(got), len(want))
	}
}

// TestTCPReaderHandlesTwoFramesInOneRead: the converse -- one read may carry
// several frames, and none may be lost.
func TestTCPReaderHandlesTwoFramesInOneRead(t *testing.T) {
	a, b := []byte("first"), []byte("second")
	stream := appendTCPFrame(appendTCPFrame(nil, a), b)

	r := newTCPReader(bytes.NewReader(stream))
	got1, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	cp := append([]byte(nil), got1...) // Next invalidates the previous slice
	got2, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cp, a) || !bytes.Equal(got2, b) {
		t.Errorf("got %q and %q, want %q and %q", cp, got2, a, b)
	}
}

// TestTCPReaderRejectsAnUndersizedLength: a length below its own size, or one
// naming an empty payload, would leave the reader spinning.
func TestTCPReaderRejectsAnUndersizedLength(t *testing.T) {
	for _, n := range []uint16{0, 1, 2} {
		var stream []byte
		stream = binary.BigEndian.AppendUint16(stream, n)
		stream = append(stream, 0xff, 0xff)

		r := newTCPReader(bytes.NewReader(stream))
		if _, err := r.Next(); err == nil {
			t.Errorf("length %d was accepted", n)
		}
	}
}

// TestTCPPrefixIsSentByTheOriginatorOnly pins who sends what. RFC 8229: the
// prefix is "only sent once, by the TCP Originator only". A responder that
// echoed one would corrupt the first frame its peer reads.
func TestTCPPrefixIsSentByTheOriginatorOnly(t *testing.T) {
	if tcpStreamPrefix != "IKETCP" {
		t.Errorf("prefix = %q, want %q", tcpStreamPrefix, "IKETCP")
	}

	// A responder consumes the prefix, then frames.
	stream := append([]byte(tcpStreamPrefix), appendTCPFrame(nil, []byte("hello"))...)
	r := newTCPReader(bytes.NewReader(stream))
	if err := r.expectPrefix(); err != nil {
		t.Fatalf("expectPrefix: %v", err)
	}
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Errorf("frame after the prefix = %q, want %q", got, "hello")
	}
}

// TestTCPReaderRejectsAWrongPrefix: anything but IKETCP means we are not
// talking to an RFC 8229 peer, and guessing would misframe everything after.
func TestTCPReaderRejectsAWrongPrefix(t *testing.T) {
	r := newTCPReader(bytes.NewReader([]byte("HTTP/1.1 200 OK\r\n")))
	if err := r.expectPrefix(); !errors.Is(err, errTCPBadPrefix) {
		t.Fatalf("a non-IKETCP stream was accepted (err=%v)", err)
	}
}

// TestTCPReaderSurvivesManyFrames exercises the buffer's compaction: a
// long-lived stream must not walk its window rightwards forever.
func TestTCPReaderSurvivesManyFrames(t *testing.T) {
	msg := bytes.Repeat([]byte{7}, 200)
	var stream []byte
	for range 500 {
		stream = appendTCPFrame(stream, msg)
	}

	r := newTCPReader(bytes.NewReader(stream))
	for i := range 500 {
		got, err := r.Next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if len(got) != len(msg) {
			t.Fatalf("frame %d is %d octets, want %d", i, len(got), len(msg))
		}
	}
	if cap(r.buf) > 1<<20 {
		t.Errorf("reader buffer grew to %d octets over 500 frames; it is not compacting", cap(r.buf))
	}
}

// drip is an io.Reader that yields at most n octets per Read, so a test can
// force reassembly across reads.
type drip struct {
	data []byte
	n    int
	off  int
}

func (d *drip) Read(p []byte) (int, error) {
	if d.off >= len(d.data) {
		return 0, io.EOF
	}
	n := min(min(d.n, len(p)), len(d.data)-d.off)
	copy(p, d.data[d.off:d.off+n])
	d.off += n
	return n, nil
}
