package l2tp

import "testing"

// Fuzz targets for the RFC 2661 codec.
//
// L2TP rides inside ESP, so this input is authenticated by the time it arrives —
// which makes it lower risk than the IKE parsers, but not zero: the peer on the
// far side of a valid SA is still a peer, and a malformed AVP from it should not
// crash the tunnel it shares with every other client.

func FuzzParseHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 12))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseHeader(data)
	})
}

func FuzzParseAVPs(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseAVPs(data)
	})
}
