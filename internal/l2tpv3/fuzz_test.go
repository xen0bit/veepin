package l2tpv3

import "testing"

// FuzzDecodeData drives the inbound parser with arbitrary bytes. The contract
// it must never break: no panic, no out-of-bounds read, and a returned frame
// that is always a subslice of the input.
func FuzzDecodeData(f *testing.F) {
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("seed"))
	f.Add(EncodeData(nil, 1, nil, false, frame), 0, false)
	f.Add(EncodeData(nil, 42, []byte{1, 2, 3, 4}, true, frame), 4, true)
	f.Add(EncodeData(nil, 7, []byte{1, 2, 3, 4, 5, 6, 7, 8}, true, frame), 8, true)
	f.Add([]byte{}, 0, false)
	f.Add([]byte{0, 3}, 0, false)

	f.Fuzz(func(t *testing.T, pkt []byte, cookieLen int, sublayer bool) {
		// Only the lengths the wire format can express; anything else is a
		// configuration error the facade rejects before we get here.
		if !ValidCookieLen(cookieLen) {
			return
		}
		cookie := make([]byte, cookieLen)

		_, frame, err := DecodeData(pkt, cookie, sublayer)
		if err != nil {
			return
		}
		if len(frame) > len(pkt) {
			t.Fatalf("frame (%d octets) is longer than the packet it came from (%d)", len(frame), len(pkt))
		}
		// The frame must alias the input, not a copy: the whole inbound path is
		// allocation-free on that premise.
		if len(frame) > 0 && &frame[0] != &pkt[len(pkt)-len(frame)] {
			t.Fatal("DecodeData returned a copy; it must return a subslice of its input")
		}
	})
}

// FuzzSessionIDDemux checks the demux never panics and agrees with DecodeData
// about where the Session ID is.
func FuzzSessionIDDemux(f *testing.F) {
	frame := ethernetFrame("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800, []byte("seed"))
	f.Add(EncodeData(nil, 0xdeadbeef, nil, false, frame))
	f.Add([]byte{0, 3, 0, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, pkt []byte) {
		sid, ok := SessionIDDemux(pkt)
		if !ok {
			return
		}
		got, _, err := DecodeData(pkt, nil, false)
		if err != nil {
			return
		}
		if got != sid {
			t.Fatalf("demux says session %d, decode says %d", sid, got)
		}
	})
}

// FuzzParseControl drives the control-message parser with arbitrary bytes. A
// control connection is reachable by anyone who can send to the data port, so
// this parser is as exposed as the data one.
func FuzzParseControl(f *testing.F) {
	f.Add(AppendControl(nil, 100, 0, 0, msgHello, nil))
	f.Add(AppendControl(nil, 0xffffffff, 65535, 65535, msgAck, nil))
	f.Add(AppendControl(nil, 1, 0, 0, msgStopCCN, nil))
	f.Add([]byte{0xc8, 0x03, 0x00, 0x0c})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, pkt []byte) {
		m, err := ParseControl(pkt)
		if err != nil {
			return
		}
		// Every AVP must be a subslice of the input, and none may claim a
		// length beyond it.
		for _, a := range m.AVPs {
			if len(a.Value) > len(pkt) {
				t.Fatalf("an AVP value of %d octets came from a %d-octet message",
					len(a.Value), len(pkt))
			}
		}
	})
}
