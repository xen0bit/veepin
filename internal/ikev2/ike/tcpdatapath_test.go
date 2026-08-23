package ike

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// discardConn is a net.Conn that swallows writes and never reads, so the write
// path can be measured without a peer.
type discardConn struct{ net.Conn }

func (discardConn) Write(p []byte) (int, error) { return len(p), nil }
func (discardConn) Read([]byte) (int, error)    { return 0, io.EOF }

// TestTheStreamWritePathAllocatesNothingPerPacket is the RFC 8229 half of the
// allocation contract the datagram path keeps.
//
// A stream needs one buffer to assemble the length prefix in front of the
// payload, because a stream write must be one call — two writes would put the
// header and body in separate segments and, worse, would race another writer
// between them. The buffer is therefore reused under the write mutex. If this
// starts allocating, every ESP packet over TCP costs a garbage-collected
// allocation, which is exactly what the UDP path is careful never to do.
func TestTheStreamWritePathAllocatesNothingPerPacket(t *testing.T) {
	st := newTCPStream(discardConn{})
	esp := bytes.Repeat([]byte{0xab}, 1400)
	// One warm-up pass so the reused buffer has grown to its working size; the
	// first write legitimately allocates it.
	if err := st.WriteESP(esp); err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(100, func() { _ = st.WriteESP(esp) }); n > 0 {
		t.Errorf("WriteESP allocates %.0f times per packet, want 0", n)
	}

	batch := [][]byte{esp, esp, esp, esp}
	if err := st.WriteESPBatch(batch); err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(100, func() { _ = st.WriteESPBatch(batch) }); n > 0 {
		t.Errorf("WriteESPBatch allocates %.0f times per burst, want 0", n)
	}
}

// TestTheStreamReadPathAllocatesNothingPerFrame: tcpReader slides within one
// buffer and returns subslices of it, the same borrowed-buffer contract the
// datagram parsers keep. A reader that copied would cost one allocation per
// inbound ESP packet.
func TestTheStreamReadPathAllocatesNothingPerFrame(t *testing.T) {
	frame := appendTCPFrame(nil, bytes.Repeat([]byte{0xcd}, 1400))
	src := &repeatReader{frame: frame}
	r := newTCPReader(src)
	if _, err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(100, func() {
		if _, err := r.Next(); err != nil {
			t.Fatal(err)
		}
	}); n > 0 {
		t.Errorf("tcpReader.Next allocates %.0f times per frame, want 0", n)
	}
}

// repeatReader hands out one frame's octets over and over, so the reader under
// test sees an endless stream without the test holding one.
type repeatReader struct {
	frame []byte
	off   int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		c := copy(p[n:], r.frame[r.off:])
		n += c
		r.off += c
		if r.off == len(r.frame) {
			r.off = 0
		}
	}
	return n, nil
}

func BenchmarkTCPStreamWriteESP(b *testing.B) {
	for _, size := range []int{64, 576, 1400} {
		b.Run(sizeName(size), func(b *testing.B) {
			st := newTCPStream(discardConn{})
			esp := bytes.Repeat([]byte{0xab}, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := st.WriteESP(esp); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTCPReaderNext(b *testing.B) {
	for _, size := range []int{64, 576, 1400} {
		b.Run(sizeName(size), func(b *testing.B) {
			r := newTCPReader(&repeatReader{frame: appendTCPFrame(nil, bytes.Repeat([]byte{0xcd}, size))})
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := r.Next(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func sizeName(n int) string {
	switch n {
	case 64:
		return "64"
	case 576:
		return "576"
	default:
		return "1400"
	}
}
