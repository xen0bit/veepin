package toy

import (
	"net/netip"
	"testing"
)

// Fuzz targets for the TOY wire format.
//
// TOY provides no security, so "an attacker can read this traffic" is not a
// finding here — it is the documented design. What still matters is that a
// malformed datagram cannot crash the process: a panic is a denial of service
// regardless of how weak the cryptography above it is, and this parser is the
// example other protocols are meant to be modelled on.

func FuzzParseHeader(f *testing.F) {
	f.Add(AppendHeader(nil, Header{Type: MsgData, Session: 7, Counter: 3}))
	f.Add([]byte{})
	f.Add([]byte("TOY"))

	f.Fuzz(func(t *testing.T, data []byte) {
		h, body, err := ParseHeader(data)
		if err != nil {
			return
		}
		if len(body) != len(data)-HeaderLen {
			t.Fatalf("body is %d octets, want %d", len(body), len(data)-HeaderLen)
		}
		// A parsed header must re-encode to exactly the bytes it came from.
		if got := AppendHeader(nil, h); string(got) != string(data[:HeaderLen]) {
			t.Errorf("header round trip differs:\n got: %x\nwant: %x", got, data[:HeaderLen])
		}
	})
}

func FuzzParseBodies(f *testing.F) {
	f.Add(AppendHello(nil, Hello{User: "alice"}))
	f.Add(AppendWelcome(nil, Welcome{
		AssignedIP: netip.MustParseAddr("10.9.0.2"),
		Netmask:    netip.MustParseAddr("255.255.255.0"),
		Gateway:    netip.MustParseAddr("10.9.0.1"),
		MTU:        1400,
		DNS:        []netip.Addr{netip.MustParseAddr("1.1.1.1")},
	}))
	f.Add(AppendReject(nil, "authentication failed"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Every body parser sees the same untrusted bytes; none may panic, and
		// anything that parses must survive being re-encoded.
		if h, err := ParseHello(data); err == nil {
			_ = AppendHello(nil, h)
		}
		if w, err := ParseWelcome(data); err == nil {
			_ = AppendWelcome(nil, w)
		}
		if r, err := ParseReject(data); err == nil {
			_ = AppendReject(nil, r)
		}
		_, _ = ParseFixed(data, TagLen)
		_, _ = SessionOf(data)
	})
}

// The sealed path is fuzzed against a real session, so the fuzzer exercises tag
// verification and the replay window rather than stopping at the header.
func FuzzSessionOpen(f *testing.F) {
	f.Add([]byte{})
	f.Add(AppendHeader(nil, Header{Type: MsgData, Session: 7, Counter: 3}))

	f.Fuzz(func(t *testing.T, data []byte) {
		k := DeriveKey("secret", make([]byte, NonceLen), make([]byte, NonceLen))
		s := NewSession(7, k, nil, nil)

		// Both entry points a server reaches from an unauthenticated datagram.
		_, _ = s.Decapsulate(data)
		_, _, _ = s.OpenAny(data)
	})
}
