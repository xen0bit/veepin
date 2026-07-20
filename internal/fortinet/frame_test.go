package fortinet

import (
	"bytes"
	"testing"
)

// Byte-exact against openconnect's PPP_ENCAP_FORTINET: a 6-octet header of
// [total BE16][0x5050][plen BE16], then the bare PPP frame. A round-trip test
// alone would not catch the two length fields being swapped or the magic being
// wrong-endian; the fixed vector does.
func TestEncodeFrameLayout(t *testing.T) {
	ppp := []byte{0xff, 0x03, 0xc0, 0x21, 0x01} // an LCP frame, ACFC + protocol
	got := EncodeFrame(ppp)
	want := []byte{
		0x00, 0x0b, // total length = 5 + 6 = 11
		0x50, 0x50, // magic
		0x00, 0x05, // payload length = 5
		0xff, 0x03, 0xc0, 0x21, 0x01,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeFrame = % x, want % x", got, want)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	for _, payload := range [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0xab}, 1500),
	} {
		rec := EncodeFrame(payload)
		got, rest, err := ParseFrame(rec)
		if err != nil {
			t.Fatalf("ParseFrame(% x): %v", rec[:8], err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("payload round trip differs: got %d octets, want %d", len(got), len(payload))
		}
		if len(rest) != 0 {
			t.Errorf("ParseFrame left %d trailing octets", len(rest))
		}
	}
}

// Two records back to back must parse one at a time, since the transport is a
// byte stream and the peer may coalesce them.
func TestParseFrameStream(t *testing.T) {
	a := EncodeFrame([]byte{0x01, 0x02})
	b := EncodeFrame([]byte{0x03, 0x04, 0x05})
	buf := append(append([]byte{}, a...), b...)

	first, rest, err := ParseFrame(buf)
	if err != nil || !bytes.Equal(first, []byte{0x01, 0x02}) {
		t.Fatalf("first frame = % x (%v)", first, err)
	}
	second, rest, err := ParseFrame(rest)
	if err != nil || !bytes.Equal(second, []byte{0x03, 0x04, 0x05}) {
		t.Fatalf("second frame = % x (%v)", second, err)
	}
	if len(rest) != 0 {
		t.Errorf("stream left %d trailing octets", len(rest))
	}
}

func TestParseFrameRejects(t *testing.T) {
	good := EncodeFrame([]byte{0xaa, 0xbb})
	for _, tc := range []struct {
		name string
		rec  []byte
		want error
	}{
		{"short header", []byte{0x00, 0x0b, 0x50}, ErrShortFrame},
		{"bad magic", []byte{0x00, 0x08, 0x51, 0x51, 0x00, 0x02, 0xaa, 0xbb}, ErrBadMagic},
		{"length mismatch", []byte{0x00, 0x09, 0x50, 0x50, 0x00, 0x02, 0xaa, 0xbb}, ErrLengthMismatch},
		{"truncated payload", good[:len(good)-1], ErrShortFrame},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseFrame(tc.rec); err != tc.want {
				t.Errorf("ParseFrame err = %v, want %v", err, tc.want)
			}
		})
	}
}

// ReadFrame must consume exactly one record and leave the reader positioned at
// the next, which a stream carrier depends on.
func TestReadFrameStream(t *testing.T) {
	a := EncodeFrame([]byte{0x11, 0x22})
	b := EncodeFrame([]byte{0x33})
	r := bytes.NewReader(append(append([]byte{}, a...), b...))

	got, err := ReadFrame(r)
	if err != nil || !bytes.Equal(got, []byte{0x11, 0x22}) {
		t.Fatalf("first ReadFrame = % x (%v)", got, err)
	}
	got, err = ReadFrame(r)
	if err != nil || !bytes.Equal(got, []byte{0x33}) {
		t.Fatalf("second ReadFrame = % x (%v)", got, err)
	}
}
