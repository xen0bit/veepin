package masque

import (
	"bytes"
	"net/netip"
	"testing"
)

// Fuzz targets for the CONNECT-IP capsule parsers. A proxy or client on the
// other end of the request stream can send any bytes; these must reject or
// round-trip, never panic.

func FuzzReadCapsule(f *testing.F) {
	var seed bytes.Buffer
	_ = WriteCapsule(&seed, CapsuleDatagram, EncodeDatagramPayload([]byte{0x45, 0, 0, 20}))
	f.Add(seed.Bytes())
	f.Add([]byte{})
	f.Add([]byte{0x00, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		for {
			c, err := ReadCapsule(r)
			if err != nil {
				return
			}
			if uint64(len(c.Value)) > maxCapsuleValue {
				t.Fatalf("capsule value %d exceeds the ceiling", len(c.Value))
			}
		}
	})
}

func FuzzParseAddresses(f *testing.F) {
	f.Add(EncodeAddresses([]AddressEntry{{RequestID: 1, Prefix: netip.MustParsePrefix("10.0.0.1/32")}}))
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x04, 0x0a})

	f.Fuzz(func(t *testing.T, data []byte) {
		if entries, err := ParseAddresses(data); err == nil {
			// A parsed list re-encodes and must parse back identically.
			back, err := ParseAddresses(EncodeAddresses(entries))
			if err != nil || len(back) != len(entries) {
				t.Fatalf("re-parse changed %d entries to %d (%v)", len(entries), len(back), err)
			}
		}
	})
}

func FuzzParseRoutes(f *testing.F) {
	f.Add(EncodeRoutes([]RouteEntry{{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: 0}}))
	f.Add([]byte{})
	f.Add([]byte{0x04, 0x0a})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseRoutes(data)
	})
}

func FuzzDecodeDatagramPayload(f *testing.F) {
	f.Add(EncodeDatagramPayload([]byte{0x45, 0, 0, 20}))
	f.Add([]byte{})
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeDatagramPayload(data)
	})
}

// The CONNECT-UDP target parser reads an attacker-influenced request path and
// hands the result to a UDP dial, so it must never panic and must never accept a
// path it did not fully understand.
func FuzzParseConnectUDPTarget(f *testing.F) {
	f.Add(ConnectUDPPath("1.1.1.1", 53))
	f.Add("/.well-known/masque/udp/example.com/443/")
	f.Add("")
	f.Add("/.well-known/masque/udp//0/")

	f.Fuzz(func(t *testing.T, path string) {
		host, port, ok := ParseConnectUDPTarget(path)
		if !ok {
			return
		}
		// An accepted target must be usable: a non-empty host and a port in range.
		if host == "" || port < 1 || port > 65535 {
			t.Fatalf("accepted target %q:%d from %q", host, port, path)
		}
	})
}
