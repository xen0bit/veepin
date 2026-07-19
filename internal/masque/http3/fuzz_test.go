package http3

import "testing"

// Fuzz targets for the HTTP/3 substrate. These parsers read bytes off a QUIC
// stream from a peer that may be hostile or simply broken; a panic on malformed
// input is a denial of service regardless of what rides above. The invariant in
// each case is the same: reject cleanly or round-trip, never crash.

func FuzzConsumeVarint(f *testing.F) {
	f.Add([]byte{0x25})
	f.Add([]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c})
	f.Add([]byte{})
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		v, rest, err := ConsumeVarint(data)
		if err != nil {
			return
		}
		// A decoded varint must re-encode to a prefix of the input, and the
		// remainder must be exactly what is left.
		enc := AppendVarint(nil, v)
		if len(enc) > len(data) || len(rest) != len(data)-len(enc) {
			t.Fatalf("varint %d: encoded %d, input %d, rest %d", v, len(enc), len(data), len(rest))
		}
	})
}

func FuzzParseSettings(f *testing.F) {
	f.Add(DefaultSettings().Encode())
	f.Add([]byte{})
	f.Add([]byte{0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		if s, err := ParseSettings(data); err == nil {
			// A parsed SETTINGS frame re-encodes; the result must itself parse.
			if _, err := ParseSettings(s.Encode()); err != nil {
				t.Fatalf("re-parse of encoded settings failed: %v", err)
			}
		}
	})
}

func FuzzDecodeFieldSection(f *testing.F) {
	f.Add(EncodeFieldSection([]Field{{":method", "CONNECT"}, {":protocol", "connect-ip"}}))
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		// The only requirement is that it does not panic on arbitrary input.
		_, _ = DecodeFieldSection(data)
	})
}
