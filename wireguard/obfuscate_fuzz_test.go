package wireguard

import (
	"bytes"
	"testing"

	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// FuzzDeobfuscate feeds arbitrary datagrams to the receive path. The invariant
// is not that they parse — most will not — but that deobfuscateRecv never
// panics and never returns something longer than what it was given. It runs on
// the wire, so anything it accepts from an unauthenticated source must be
// bounded by its input.
func FuzzDeobfuscate(f *testing.F) {
	cfg := awgTestConfig()
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0, 0})
	f.Add(make([]byte, wire.SizeHandshakeInitiation+cfg.PadInitiation))
	f.Add(make([]byte, wire.SizeHandshakeResponse+cfg.PadResponse))
	f.Add(obfuscateSend(stockMessage(wire.TypeTransportData, 200), cfg))

	f.Fuzz(func(t *testing.T, data []byte) {
		got := deobfuscateRecv(append([]byte(nil), data...), cfg)
		if got != nil && len(got) > len(data) {
			t.Fatalf("deobfuscateRecv grew its input: %d > %d", len(got), len(data))
		}
	})
}

// FuzzObfuscateRoundTrip checks the property that matters for interoperability:
// whatever a peer configured identically sends, we recover exactly. The body is
// constrained to well-formed messages, since that is the only thing the send
// path is ever handed.
func FuzzObfuscateRoundTrip(f *testing.F) {
	cfg := awgTestConfig()
	f.Add(uint8(wire.TypeTransportData), 64)
	f.Add(uint8(wire.TypeHandshakeInitiation), wire.SizeHandshakeInitiation)

	f.Fuzz(func(t *testing.T, typ uint8, size int) {
		switch typ {
		case wire.TypeHandshakeInitiation:
			size = wire.SizeHandshakeInitiation
		case wire.TypeHandshakeResponse:
			size = wire.SizeHandshakeResponse
		case wire.TypeCookieReply:
			size = wire.SizeCookieReply
		case wire.TypeTransportData:
			if size < wire.MinTransportData || size > 4096 {
				return
			}
		default:
			return
		}
		orig := stockMessage(typ, size)
		want := append([]byte(nil), orig...)

		got := deobfuscateRecv(obfuscateSend(orig, cfg), cfg)
		if got == nil {
			t.Fatalf("type %d size %d did not survive the round trip", typ, size)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("type %d size %d changed in transit", typ, size)
		}
	})
}
