package masque

import (
	"bytes"
	"net/netip"
	"testing"
)

// Capsules written back-to-back must read back one at a time from the byte
// stream, since the peer is free to pack or split them across DATA frames.
func TestCapsuleStreamRoundTrip(t *testing.T) {
	var buf bytes.Buffer

	assign := EncodeAddresses([]AddressEntry{{RequestID: 1, Prefix: netip.MustParsePrefix("10.0.0.2/32")}})
	route := EncodeRoutes([]RouteEntry{{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: 0}})
	dgram := EncodeDatagramPayload([]byte{0x45, 0x00, 0x00, 0x1c})

	for _, c := range []struct {
		typ   uint64
		value []byte
	}{
		{CapsuleAddressAssign, assign},
		{CapsuleRouteAdvertisement, route},
		{CapsuleDatagram, dgram},
	} {
		if err := WriteCapsule(&buf, c.typ, c.value); err != nil {
			t.Fatalf("WriteCapsule: %v", err)
		}
	}

	wantTypes := []uint64{CapsuleAddressAssign, CapsuleRouteAdvertisement, CapsuleDatagram}
	wantVals := [][]byte{assign, route, dgram}
	for i := range wantTypes {
		c, err := ReadCapsule(&buf)
		if err != nil {
			t.Fatalf("ReadCapsule %d: %v", i, err)
		}
		if c.Type != wantTypes[i] {
			t.Errorf("capsule %d type = %#x, want %#x", i, c.Type, wantTypes[i])
		}
		if !bytes.Equal(c.Value, wantVals[i]) {
			t.Errorf("capsule %d value = % x, want % x", i, c.Value, wantVals[i])
		}
	}
}

// A capsule advertising a value larger than the ceiling is refused before the
// length is allocated, so a hostile header cannot force a huge allocation.
func TestReadCapsuleRejectsOversize(t *testing.T) {
	var buf bytes.Buffer
	// type 0, then a length varint well past maxCapsuleValue, then nothing.
	buf.Write([]byte{0x00})
	buf.Write([]byte{0x80, 0x20, 0x00, 0x00}) // 4-byte varint = 0x200000 = 2 MiB
	if _, err := ReadCapsule(&buf); err == nil {
		t.Error("accepted an oversize capsule length")
	}
}

// The reusable encoder must produce exactly what the straightforward path
// produces. It is a performance change, so the thing to prove is that nothing
// about the wire changed -- a byte of difference here is a protocol break that
// no throughput number would excuse.
func TestDatagramEncoderMatchesWriteCapsule(t *testing.T) {
	var enc DatagramEncoder
	for _, size := range []int{0, 1, 62, 63, 64, 1400, 16383, 16384, 20000} {
		packet := bytes.Repeat([]byte{0xab}, size)

		var want bytes.Buffer
		if err := WriteCapsule(&want, CapsuleDatagram, EncodeDatagramPayload(packet)); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if got := enc.Encode(packet); !bytes.Equal(got, want.Bytes()) {
			t.Errorf("size %d: encoder produced %d octets, WriteCapsule produced %d\n got %x\nwant %x",
				size, len(got), want.Len(), got, want.Bytes())
		}
	}
}

// The reusable reader must decode exactly what the straightforward one decodes,
// including back-to-back capsules on one stream.
func TestCapsuleReaderMatchesReadCapsule(t *testing.T) {
	var stream bytes.Buffer
	sizes := []int{0, 1, 63, 64, 1400, 16384}
	for _, size := range sizes {
		if err := WriteCapsule(&stream, CapsuleDatagram, EncodeDatagramPayload(bytes.Repeat([]byte{0xcd}, size))); err != nil {
			t.Fatal(err)
		}
	}
	raw := bytes.NewReader(stream.Bytes())
	reused := bytes.NewReader(stream.Bytes())

	var cr CapsuleReader
	for _, size := range sizes {
		want, err := ReadCapsule(raw)
		if err != nil {
			t.Fatalf("size %d: ReadCapsule: %v", size, err)
		}
		got, err := cr.Read(reused)
		if err != nil {
			t.Fatalf("size %d: CapsuleReader: %v", size, err)
		}
		if got.Type != want.Type || !bytes.Equal(got.Value, want.Value) {
			t.Errorf("size %d: reader disagreed with ReadCapsule", size)
		}
	}
}

// The data path must not allocate per packet. This is the whole point of the
// reusable forms, and without a test the next refactor quietly loses it.
func TestDataPathIsAllocationFree(t *testing.T) {
	packet := bytes.Repeat([]byte{0x45}, 1400)
	var enc DatagramEncoder
	var sink int

	if n := testing.AllocsPerRun(100, func() { sink += len(enc.Encode(packet)) }); n != 0 {
		t.Errorf("DatagramEncoder.Encode allocated %v times per packet, want 0", n)
	}

	stream := &repeatReader{data: enc.Encode(packet)}
	var cr CapsuleReader
	if n := testing.AllocsPerRun(100, func() {
		c, err := cr.Read(stream)
		if err != nil {
			t.Fatal(err)
		}
		sink += len(c.Value)
	}); n != 0 {
		t.Errorf("CapsuleReader.Read allocated %v times per packet, want 0", n)
	}
	if sink == 0 {
		t.Fatal("the benchmark work was optimised away")
	}
}
