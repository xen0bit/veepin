package wire

import "testing"

// Fuzz targets for the WireGuard message codec.
//
// All three message types are fixed-size, which makes them the least likely
// place in the tree for a bounds fault -- but they are also the first thing a
// responder touches on an unauthenticated datagram, so the cost of being sure is
// a few lines.

func FuzzParseMessages(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 148)) // initiation-sized
	f.Add(make([]byte, 92))  // response-sized

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseHandshakeInitiation(data)
		_, _ = ParseHandshakeResponse(data)
		_, _ = ParseCookieReply(data)
	})
}
