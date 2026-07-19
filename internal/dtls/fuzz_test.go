package dtls

import (
	"testing"
)

// Fuzz targets for the DTLS parsing surface.
//
// Everything here runs on unauthenticated input. A DTLS server reads records and
// peeks at a ClientHello before it has any key, and handshake fragments are
// reassembled before the Finished message proves anything — so a panic in this
// code is a remote crash triggered by anyone who can send a datagram.
//
// The reassembler is the target most worth having. It does offset arithmetic on
// attacker-supplied fragment offsets and lengths, which is the classic shape for
// a slice bounds fault, and it is the one piece here that holds state across
// several datagrams.

func FuzzParseRecord(f *testing.F) {
	f.Add(appendRecordHeader(nil, recordHandshake, 0, 0, 0, 16))
	f.Add([]byte{})
	f.Add([]byte{0x16, 0xfe, 0xfd})

	f.Fuzz(func(t *testing.T, data []byte) {
		// A datagram can carry several records, which is how a real flight
		// arrives; walk them the way the connection does.
		buf := data
		for len(buf) > 0 {
			_, n, err := parseRecord(buf)
			if err != nil {
				return
			}
			if n <= 0 || n > len(buf) {
				t.Fatalf("parseRecord consumed %d of %d bytes", n, len(buf))
			}
			buf = buf[n:]
		}
	})
}

func FuzzClientHelloSessionID(f *testing.F) {
	f.Add([]byte{})
	f.Add(appendRecordHeader(nil, recordHandshake, 0, 0, 0, 16))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Unauthenticated by construction: this runs to pick a session before a
		// key exists. It must never panic and never be trusted.
		_, _ = ClientHelloSessionID(data)
	})
}

func FuzzParseFragment(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 12))

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := parseFragment(data)
		if err != nil {
			return
		}
		// A fragment that parsed must describe a range inside itself.
		if h.offset+h.fragLen > h.length {
			t.Fatalf("accepted a fragment claiming offset %d + %d beyond message length %d",
				h.offset, h.fragLen, h.length)
		}
		if int(h.fragLen) != len(h.body) {
			t.Fatalf("fragment claims %d body octets but carries %d", h.fragLen, len(h.body))
		}
	})
}

// The reassembler is stateful, so it is fuzzed as a sequence rather than a
// single message: the input is chopped into fragments and fed in order, which is
// what a peer sending an overlapping or contradictory flight would do.
func FuzzReassembler(f *testing.F) {
	f.Add([]byte{}, uint8(1))
	f.Add(make([]byte, 64), uint8(3))

	f.Fuzz(func(t *testing.T, data []byte, chunks uint8) {
		if chunks == 0 {
			chunks = 1
		}
		r := newReassembler()

		size := len(data)/int(chunks) + 1
		for off := 0; off < len(data); off += size {
			end := min(off+size, len(data))
			h, err := parseFragment(data[off:end])
			if err != nil {
				continue
			}
			msgs, err := r.accept(h)
			if err != nil {
				continue
			}
			for _, m := range msgs {
				// A completed message must re-marshal, which is what the layer
				// above does with it; a body inconsistent with its header would
				// fault there rather than here.
				if got := m.marshal(); len(got) < handshakeHeaderLen {
					t.Fatalf("reassembled message marshalled to %d octets", len(got))
				}
			}
		}
	})
}

func FuzzParseHandshakeMessages(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 40))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Each of these is reached from an unauthenticated flight.
		_, _ = parseClientHello(data)
		_, _ = parseHelloVerifyRequest(data)
		_, _ = parseServerHello(data)
		_, _ = parsePSKClientKeyExchange(data)
	})
}
