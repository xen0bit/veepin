package ike

import (
	"bytes"
	"testing"
)

// FuzzTCPReader drives the RFC 8229 stream reassembler with arbitrary bytes. A
// TCP responder accepts connections from anyone, so this parser is reached
// before any authentication -- it must never panic, never loop forever, and
// never return a frame longer than the stream it came from.
func FuzzTCPReader(f *testing.F) {
	f.Add(appendTCPFrame(nil, []byte{1, 2, 3}))
	f.Add(appendTCPIKE(nil, []byte{0xaa}))
	f.Add(append([]byte(tcpStreamPrefix), appendTCPFrame(nil, []byte("x"))...))
	f.Add([]byte{0, 0})
	f.Add([]byte{0xff, 0xff, 1})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, stream []byte) {
		r := newTCPReader(bytes.NewReader(stream))
		// Bounded: a stream of n octets cannot yield more than n frames, since
		// every frame consumes at least three (two length octets plus payload).
		for range len(stream) + 1 {
			frame, err := r.Next()
			if err != nil {
				return
			}
			if len(frame) > len(stream) {
				t.Fatalf("a %d-octet stream yielded a %d-octet frame", len(stream), len(frame))
			}
			// Whatever it is, classifying it must not panic.
			_ = tcpFrameIsIKE(frame)
		}
		t.Fatal("reader produced more frames than the stream can contain; it is not consuming input")
	})
}
