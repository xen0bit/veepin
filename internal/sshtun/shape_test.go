package sshtun

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// shapeIPv4 builds a minimal well-formed IPv4 packet with Total Length set.
func shapeIPv4(payload string) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 253
	copy(pkt[12:16], []byte{10, 200, 0, 1})
	copy(pkt[16:20], []byte{10, 200, 0, 2})
	copy(pkt[20:], payload)
	return pkt
}

// TestFillerIsSkippedAndTheStreamStaysInSync is the claim the whole SSH shaping
// design rests on, and the reason it needed a framing change rather than a
// padding call.
//
// An SSH channel is a byte stream with no packet delimiter, so ReadPacket
// recovers boundaries from the IP length. Trailing filler would therefore be
// read as the NEXT packet's address-family header and the stream would
// desynchronise from that point on -- a corrupt tunnel rather than a padding
// bug, and one that only shows up on the second packet.
//
// Several padded packets back to back is what catches it: each one only parses
// if the previous one's filler was consumed exactly.
func TestFillerIsSkippedAndTheStreamStaysInSync(t *testing.T) {
	want := []string{"first", "second", "third", "fourth"}
	var stream []byte
	for i, p := range want {
		// Deliberately uneven targets, so no two frames pad by the same amount.
		stream = append(stream, EncodePadded(shapeIPv4(p), 200+i*97)...)
	}

	r := bytes.NewReader(stream)
	for i, p := range want {
		got, err := ReadPacket(r)
		if err != nil {
			t.Fatalf("packet %d: %v", i+1, err)
		}
		if !bytes.Equal(got, shapeIPv4(p)) {
			t.Fatalf("packet %d came back wrong; the previous frame's filler was not consumed exactly", i+1)
		}
	}
	// What is left is the LAST frame's filler, and that is correct rather than a
	// leak: filler is consumed by the read that follows it, so the final frame's
	// trails until the next packet arrives or the channel closes. It must be
	// nothing but zeros, and reading again must report the stream ended rather
	// than manufacturing a packet out of it.
	rest := make([]byte, r.Len())
	if _, err := io.ReadFull(bytes.NewReader(stream[len(stream)-len(rest):]), rest); err != nil {
		t.Fatal(err)
	}
	for i, b := range rest {
		if b != 0 {
			t.Fatalf("octet %d of the trailing remainder is %#x, so it is not filler", i, b)
		}
	}
	if _, err := ReadPacket(r); err != io.EOF {
		t.Errorf("reading past the last packet gave %v, want EOF", err)
	}
}

// TestUnpaddedFramesStillParse: the reader change must not cost anything in the
// unshaped case, which is every existing deployment and every stock OpenSSH
// peer. A frame with no filler is one word of header and then the packet, and
// the loop must land on it directly.
func TestUnpaddedFramesStillParse(t *testing.T) {
	for _, p := range []string{"a", "bb", "ccc"} {
		pkt := shapeIPv4(p)
		got, err := ReadPacket(bytes.NewReader(Encode(pkt)))
		if err != nil {
			t.Fatalf("ReadPacket: %v", err)
		}
		if !bytes.Equal(got, pkt) {
			t.Error("an unpadded frame did not round-trip")
		}
	}
}

// TestEncodePaddedRoundsFillerDownToAWord. The filler has to be a whole number
// of 4-octet words or ReadPacket cannot tell it from a header, and it rounds
// DOWN rather than up because the shaper's target is an MTU -- overshooting is
// the one direction that costs something.
func TestEncodePaddedRoundsFillerDownToAWord(t *testing.T) {
	pkt := shapeIPv4("x") // 21 octets; framed, 25
	for target := 25; target < 45; target++ {
		got := len(EncodePadded(pkt, target))
		if got > target {
			t.Errorf("target %d produced %d octets; padding must never overshoot", target, got)
		}
		if (got-25)%headerLen != 0 {
			t.Errorf("target %d produced %d octets of filler, not a whole number of words", target, got-25)
		}
	}
}

// TestEncodePaddedNeverShrinks: a target at or below the framed length pads
// nothing rather than truncating.
func TestEncodePaddedNeverShrinks(t *testing.T) {
	pkt := shapeIPv4("some payload")
	plain := Encode(pkt)
	for _, target := range []int{0, 1, len(plain) - 1, len(plain)} {
		if got := EncodePadded(pkt, target); !bytes.Equal(got, plain) {
			t.Errorf("target %d changed an unpaddable frame", target)
		}
	}
}

// TestPaddedFrameIsInertToALengthDelimitedReceiver stands in for the stock
// OpenSSH peer, which writes the whole channel message to its tun in one call
// and lets the kernel delimit the packet. Everything after the header, trimmed
// by Total Length, must be the original packet.
func TestPaddedFrameIsInertToALengthDelimitedReceiver(t *testing.T) {
	pkt := shapeIPv4("what OpenSSH hands to the kernel")
	frame := EncodePadded(pkt, 1400)
	if len(frame) > 1400 {
		t.Fatalf("frame is %d octets, over the 1400 target", len(frame))
	}

	body, ok := Decode(frame)
	if !ok {
		t.Fatal("Decode rejected a padded frame")
	}
	total := int(binary.BigEndian.Uint16(body[2:4]))
	if total != len(pkt) {
		t.Fatalf("Total Length = %d, want %d; the filler has been made part of the packet", total, len(pkt))
	}
	if !bytes.Equal(body[:total], pkt) {
		t.Error("trimming by Total Length did not recover the original packet")
	}
}

// TestFillerAloneIsNotAPacket: a stream of nothing but filler must block for
// more input rather than inventing a packet out of zeros.
func TestFillerAloneIsNotAPacket(t *testing.T) {
	if _, err := ReadPacket(bytes.NewReader(make([]byte, 64))); err != io.EOF {
		t.Errorf("64 octets of filler gave err = %v, want EOF", err)
	}
}
