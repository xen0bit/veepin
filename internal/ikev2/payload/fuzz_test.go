package payload

import (
	"testing"
)

// Fuzz targets for the IKEv2 message codec.
//
// This is the largest unauthenticated parsing surface in the tree. An IKE
// responder parses the header, then walks a chained list of payloads, each
// carrying its own length — all of it from an unauthenticated initiator, before
// any signature or MAC has been checked. Payload chaining is exactly the shape
// that produces slice faults: a length field that lies about how far the next
// payload starts.
//
// ParseMessage is the real entry point and covers the chain walk; the individual
// body parsers are fuzzed too, because a responder reaches them directly once
// the chain has been split.

func FuzzParseMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 28)) // a bare header's worth of zeroes
	// A header with a plausible length field, so the fuzzer starts inside the
	// chain walk rather than bouncing off the first bounds check.
	hdr := make([]byte, 28)
	hdr[16] = 33 // next payload: SA
	hdr[17] = 0x20
	hdr[18] = 34 // IKE_SA_INIT
	hdr[24], hdr[25], hdr[26], hdr[27] = 0, 0, 0, 28
	f.Add(hdr)

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseMessage(data)
		if err != nil {
			return
		}
		// Anything that parsed is walked by the exchange handlers, which hand
		// each body straight to the matching parser. Doing the same here means
		// the chain walk and the body parsers are fuzzed as one path, which is
		// how a responder actually reaches them.
		for _, p := range msg.Payloads {
			switch p.Type {
			case TypeSA:
				_, _ = ParseSA(p.Body)
			case TypeKE:
				_, _ = ParseKE(p.Body)
			case TypeNotify:
				_, _ = ParseNotify(p.Body)
			case TypeIDi, TypeIDr:
				_, _ = ParseID(p.Body)
			case TypeAUTH:
				_, _ = ParseAuth(p.Body)
			case TypeTSi, TypeTSr:
				_, _ = ParseTS(p.Body)
			case TypeDelete:
				_, _ = ParseDelete(p.Body)
			case TypeCP:
				_, _ = ParseCP(p.Body)
			}
		}
	})
}

func FuzzParseHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 28))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseHeader(data)
	})
}

// Every payload body a responder can be handed before authentication. They are
// fuzzed together because they all see the same untrusted bytes, and a single
// corpus exercises whichever one has the weakest bound.
func FuzzParseBodies(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 8))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseKE(data)
		_ = ParseNonce(data)
		_, _ = ParseNotify(data)
		_, _ = ParseID(data)
		_, _ = ParseAuth(data)
		_, _ = ParseTS(data)
		_, _ = ParseDelete(data)
		_, _ = ParseCP(data)
		_, _ = ParseSA(data)
	})
}
