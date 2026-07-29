package aggfrag

import "testing"

// FuzzReassemblerFeed drives the AGGFRAG parser with arbitrary payloads. It
// must never panic and never return a packet longer than the payload it came
// from, whatever a hostile peer puts in BlockOffset or a block's length field.
func FuzzReassemblerFeed(f *testing.F) {
	p := NewPacker()
	one, _ := p.Pack([][]byte{ipv4(64, 1)}, 200)
	f.Add(one)
	many, _ := NewPacker().Pack([][]byte{ipv4(64, 1), ipv4(80, 2)}, 400)
	f.Add(many)
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0, 0}) // congestion-controlled sub-type

	f.Fuzz(func(t *testing.T, payload []byte) {
		r := NewReassembler()
		// Fed twice, because reassembly is stateful and the interesting
		// crashes are the ones that need a pending fragment to reach.
		for range 2 {
			pkts, err := r.Feed(payload)
			if err != nil {
				continue
			}
			for _, pkt := range pkts {
				if len(pkt) > len(payload)+len(payload) {
					t.Fatalf("a %d-octet payload yielded a %d-octet packet", len(payload), len(pkt))
				}
			}
		}
	})
}

// FuzzParseHeader checks the fixed header parser against arbitrary input.
func FuzzParseHeader(f *testing.F) {
	f.Add(AppendHeader(nil, 0))
	f.Add(AppendHeader(nil, 1400))
	f.Add([]byte{0, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		hdr, err := ParseHeader(b)
		if err != nil {
			return
		}
		got := AppendHeader(nil, hdr.BlockOffset)
		if len(got) != HeaderLen {
			t.Fatalf("re-encoded header is %d octets, want %d", len(got), HeaderLen)
		}
		// Only the sub-type and BlockOffset are compared. The Reserved octet is
		// deliberately excluded: RFC 9347 says to send it as zero and IGNORE it
		// on receipt, so a peer that sets it must still be understood and the
		// header does not round-trip octet for octet. (The fuzzer found this
		// exact case against an earlier version of this test, which asserted a
		// full round trip and was simply wrong about the format.)
		if got[0] != b[0] {
			t.Fatalf("sub-type octet: encoded %#x, parsed from %#x", got[0], b[0])
		}
		if got[2] != b[2] || got[3] != b[3] {
			t.Fatalf("BlockOffset: encoded %#x%#x, parsed from %#x%#x", got[2], got[3], b[2], b[3])
		}
	})
}
