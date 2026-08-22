package masque

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// shapeIPv4 builds a minimal well-formed IPv4 packet with Total Length set,
// which is the field the whole shaping argument rests on.
func shapeIPv4(payload string) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 253 // an experimental protocol number; nothing parses it further
	copy(pkt[12:16], []byte{10, 30, 0, 1})
	copy(pkt[16:20], []byte{10, 30, 0, 2})
	copy(pkt[20:], payload)
	return pkt
}

// TestEncodePaddedRoundTripsToTheOriginalPacket is the property the whole
// mechanism depends on: the capsule's own length field covers the filler, so
// the receiver's DecodeDatagramPayload hands the TUN the packet plus filler,
// and the kernel delimits the real packet by the inner header's Total Length.
//
// Asserting the recovered prefix rather than equality is the point. A decoder
// that returned exactly the original would mean the filler had been stripped
// somewhere, which is not what happens on the wire and would hide a bug in the
// length arithmetic.
func TestEncodePaddedRoundTripsToTheOriginalPacket(t *testing.T) {
	orig := shapeIPv4("the real payload")
	var enc DatagramEncoder
	capsule := enc.EncodePadded(orig, 1350)

	var cr CapsuleReader
	got, err := cr.Read(bytes.NewReader(capsule))
	if err != nil {
		t.Fatalf("reading the padded capsule: %v", err)
	}
	if got.Type != CapsuleDatagram {
		t.Fatalf("capsule type = %d, want DATAGRAM", got.Type)
	}
	ip, ok, err := DecodeDatagramPayload(got.Value)
	if err != nil || !ok {
		t.Fatalf("DecodeDatagramPayload: ok=%v err=%v", ok, err)
	}
	if len(ip) != 1350 {
		t.Fatalf("payload after the context ID is %d octets, want the padded 1350", len(ip))
	}
	if !bytes.Equal(ip[:len(orig)], orig) {
		t.Error("the inner packet did not survive padding")
	}
	if total := int(binary.BigEndian.Uint16(ip[2:4])); total != len(orig) {
		t.Errorf("Total Length = %d after padding, want %d; the filler has been made part of "+
			"the packet and the inner transport will see garbage", total, len(orig))
	}
	for i, b := range ip[len(orig):] {
		if b != 0 {
			t.Fatalf("filler octet %d = %#x, want zero", i, b)
		}
	}
}

// TestEncodePaddedNeverShrinks: a minInner at or below the packet's own size is
// a shaper asking for nothing, and Encode itself passes zero.
func TestEncodePaddedNeverShrinks(t *testing.T) {
	orig := shapeIPv4("small")
	var enc DatagramEncoder
	for _, minInner := range []int{0, 1, len(orig) - 1, len(orig)} {
		padded := append([]byte(nil), enc.EncodePadded(orig, minInner)...)
		plain := append([]byte(nil), enc.Encode(orig)...)
		if !bytes.Equal(padded, plain) {
			t.Errorf("EncodePadded(minInner=%d) differs from Encode; it padded when it should not", minInner)
		}
	}
}

// TestPaddedCapsuleLengthFieldCoversTheFiller. The capsule's length is a varint
// written before the value, so padding the value without updating it produces a
// stream the peer resynchronises on the wrong octet -- a failure that would look
// like a corrupt tunnel rather than a padding bug. Two capsules back to back is
// what catches it: the second only parses if the first's length was right.
func TestPaddedCapsuleLengthFieldCoversTheFiller(t *testing.T) {
	first := shapeIPv4("first")
	second := shapeIPv4("second")
	var enc DatagramEncoder
	var stream []byte
	stream = append(stream, enc.EncodePadded(first, 900)...)
	stream = append(stream, enc.EncodePadded(second, 400)...)

	var cr CapsuleReader
	r := bytes.NewReader(stream)
	for i, want := range [][]byte{first, second} {
		c, err := cr.Read(r)
		if err != nil {
			t.Fatalf("capsule %d: %v", i+1, err)
		}
		ip, ok, err := DecodeDatagramPayload(c.Value)
		if err != nil || !ok {
			t.Fatalf("capsule %d payload: ok=%v err=%v", i+1, ok, err)
		}
		if !bytes.Equal(ip[:len(want)], want) {
			t.Errorf("capsule %d carried the wrong packet; the previous length field was short", i+1)
		}
	}
	if r.Len() != 0 {
		t.Errorf("%d octets left over after two capsules", r.Len())
	}
}
