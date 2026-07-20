package masque

import (
	"bytes"
	"io"
	"testing"
)

// The capsule data path is the hot loop: every tunnelled packet is encoded into
// a DATAGRAM capsule, written, and decoded on the far side. These benchmarks
// exist to keep that path allocation-free -- in capsule mode there is no QUIC
// DATAGRAM frame to fall back on, so what this loop costs is what the tunnel
// costs.

// benchPacket is a typical inner packet: a full-MTU TCP segment.
var benchPacket = bytes.Repeat([]byte{0x45}, 1400)

// nullWriter accepts bytes and counts them, standing in for a QUIC stream
// without measuring the QUIC stack.
type nullWriter struct{ n int }

func (w *nullWriter) Write(p []byte) (int, error) { w.n += len(p); return len(p), nil }

func BenchmarkDatagramSend(b *testing.B) {
	var w nullWriter
	b.SetBytes(int64(len(benchPacket)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := WriteCapsule(&w, CapsuleDatagram, EncodeDatagramPayload(benchPacket)); err != nil {
			b.Fatal(err)
		}
	}
}

// repeatReader replays one capsule forever, so the benchmark measures decoding
// rather than the source.
type repeatReader struct {
	data []byte
	off  int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.off == len(r.data) {
		r.off = 0
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func benchCapsuleBytes(b *testing.B) []byte {
	b.Helper()
	var buf bytes.Buffer
	if err := WriteCapsule(&buf, CapsuleDatagram, EncodeDatagramPayload(benchPacket)); err != nil {
		b.Fatal(err)
	}
	return buf.Bytes()
}

func BenchmarkDatagramReceive(b *testing.B) {
	r := &repeatReader{data: benchCapsuleBytes(b)}
	b.SetBytes(int64(len(benchPacket)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		c, err := ReadCapsule(r)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := DecodeDatagramPayload(c.Value); err != nil {
			b.Fatal(err)
		}
	}
}

var _ io.Reader = (*repeatReader)(nil)

// The reusable forms the data path actually uses. These are the numbers that
// matter: they should allocate nothing per packet once warm.
func BenchmarkDatagramSendReused(b *testing.B) {
	var w nullWriter
	var enc DatagramEncoder
	b.SetBytes(int64(len(benchPacket)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := w.Write(enc.Encode(benchPacket)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDatagramReceiveReused(b *testing.B) {
	r := &repeatReader{data: benchCapsuleBytes(b)}
	var cr CapsuleReader
	b.SetBytes(int64(len(benchPacket)))
	b.ReportAllocs()
	for b.Loop() {
		c, err := cr.Read(r)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := DecodeDatagramPayload(c.Value); err != nil {
			b.Fatal(err)
		}
	}
}
