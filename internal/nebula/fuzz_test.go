package nebula

import (
	"net/netip"
	"testing"
	"time"
)

// Fuzz targets for everything that parses bytes off the wire.
//
// All of it runs before anything is authenticated: a certificate arrives inside
// a handshake from a peer whose identity has not yet been established, and the
// header and lighthouse messages are read straight out of a datagram. The
// property under test is therefore the weakest possible one — the parser must
// return, not panic — because a panic in this code is a remote crash triggered
// by an unauthenticated peer.
//
// The seeds matter more than the target count. Real certificates from the
// reference nebula-cert give the fuzzer valid structure to mutate, which is what
// gets it past the length checks and into the interesting arithmetic.

func FuzzUnmarshalCertificate(f *testing.F) {
	// Seed with real reference output, so mutations start from valid protobuf.
	for _, name := range []string{"ca.crt", "host-a.crt", "host-b.crt"} {
		if c, _, err := UnmarshalCertificatePEM(readFixture(f, name)); err == nil {
			f.Add(c.Marshal())
			f.Add(c.MarshalForHandshakes())
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := UnmarshalCertificate(data)
		if err != nil {
			return
		}
		// Anything that parsed must survive the operations the handshake path
		// performs on it, none of which may panic either.
		_ = c.Marshal()
		_ = c.MarshalForHandshakes()
		_ = c.Fingerprint()
		_, _ = c.Address()
		_ = c.Expired(time.Unix(0, 0))
		_ = c.CheckSignature(make([]byte, 32))
	})
}

// A certificate that round-trips must re-marshal to the same bytes. This is the
// property the whole certificate implementation rests on -- nebula verifies
// signatures by re-marshalling -- so it is worth asserting against arbitrary
// input rather than only against the three fixtures.
func FuzzCertificateMarshalIsStable(f *testing.F) {
	for _, name := range []string{"ca.crt", "host-a.crt"} {
		if c, _, err := UnmarshalCertificatePEM(readFixture(f, name)); err == nil {
			f.Add(c.Marshal())
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, err := UnmarshalCertificate(data)
		if err != nil {
			return
		}
		encoded := first.Marshal()
		second, err := UnmarshalCertificate(encoded)
		if err != nil {
			t.Fatalf("re-parsing our own encoding failed: %v", err)
		}
		if got := second.Marshal(); string(got) != string(encoded) {
			t.Errorf("marshal is not stable across a round trip:\n first: %x\nsecond: %x",
				encoded, got)
		}
	})
}

func FuzzParseHeader(f *testing.F) {
	f.Add(header{Version: headerVersion, Type: typeMessage, Subtype: subTypeNone, RemoteIndex: 7, MessageCounter: 3}.encode(nil))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := parseHeader(data)
		if err != nil {
			return
		}
		// A parsed header must re-encode to the same bytes it came from.
		if got := h.encode(nil); string(got) != string(data[:headerLen]) {
			t.Errorf("header round trip differs:\n got: %x\nwant: %x", got, data[:headerLen])
		}
	})
}

func FuzzParseHandshakePayload(f *testing.F) {
	f.Add(handshakePayload{
		Cert:           []byte("cert"),
		InitiatorIndex: 1,
		ResponderIndex: 2,
		Time:           3,
		CertVersion:    1,
	}.marshal())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := parseHandshakePayload(data)
		if err != nil {
			return
		}
		_ = p.marshal()
	})
}

func FuzzParseMetaMessage(f *testing.F) {
	f.Add(metaMessage{
		Type:      metaHostQueryReply,
		VpnAddr:   netip.MustParseAddr("10.42.0.9"),
		AddrPorts: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:4242")},
		Counter:   5,
	}.marshal())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := parseMetaMessage(data)
		if err != nil {
			return
		}
		_ = m.marshal()
	})
}

// The protobuf primitives are fuzzed directly as well: they are the shared
// foundation under every message above, so a fault here would surface as three
// different-looking bugs.
func FuzzProtoPrimitives(f *testing.F) {
	f.Add([]byte{0x08, 0x96, 0x01})
	f.Add([]byte{0x12, 0x03, 'a', 'b', 'c'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f})

	f.Fuzz(func(t *testing.T, data []byte) {
		b := data
		for len(b) > 0 {
			field, wire, rest, err := consumeTag(b)
			if err != nil {
				return
			}
			_ = field
			switch wire {
			case wireVarint:
				if _, rest, err = consumeVarint(rest); err != nil {
					return
				}
			case wireBytes:
				body, r, err := consumeBytes(rest)
				if err != nil {
					return
				}
				_, _ = consumePackedUint32(body)
				rest = r
			default:
				if rest, err = skipField(wire, rest); err != nil {
					return
				}
			}
			// A parser that does not consume input would spin forever; catching
			// that here is cheaper than discovering it as a hung fuzz worker.
			if len(rest) >= len(b) {
				t.Fatalf("consuming a field made no progress: %d -> %d bytes", len(b), len(rest))
			}
			b = rest
		}
	})
}
