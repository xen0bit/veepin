package anyconnect

import "testing"

// Fuzz targets for the AnyConnect framing.
//
// The CSTP header and the DTLS type byte are read off the wire on every packet;
// the config-auth XML is parsed from a server response before the tunnel exists.

func FuzzParseHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{'S', 'T', 'F', 1, 0, 4, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = parseHeader(data)
	})
}

func FuzzParseDTLS(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 'x'})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = parseDTLS(data)
	})
}

func FuzzParseConfigAuth(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte(`<?xml version="1.0"?><config-auth><auth id="main"/></config-auth>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseConfigAuth(data)
	})
}
