package wireguard

import (
	"bytes"
	"testing"

	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// awgTestConfig is a representative AmneziaWG parameter set: every message kind
// padded by a different amount and retyped, so a test that passes cannot be
// relying on two kinds sharing a value.
func awgTestConfig() ObfuscationConfig {
	return ObfuscationConfig{
		TypeInitiation: 0x71, TypeResponse: 0x72, TypeCookie: 0x73, TypeTransport: 0x74,
		PadInitiation: 17, PadResponse: 23, PadCookie: 5, PadTransport: 11,
	}
}

func stockMessage(typ uint8, size int) []byte {
	m := make([]byte, size)
	m[0] = typ
	for i := 4; i < size; i++ {
		m[i] = byte(i)
	}
	return m
}

// TestZeroConfigIsStockWireGuardByteForByte is the compatibility claim: an
// unconfigured ObfuscationConfig must leave every packet untouched, or plain
// `veepin connect wireguard` stops interoperating with wg(8).
func TestZeroConfigIsStockWireGuardByteForByte(t *testing.T) {
	var zero ObfuscationConfig
	for _, size := range []int{wire.SizeHandshakeInitiation, wire.SizeHandshakeResponse, wire.SizeCookieReply, 128} {
		pkt := stockMessage(wire.TypeTransportData, size)
		want := append([]byte(nil), pkt...)
		if got := obfuscateSend(pkt, zero); !bytes.Equal(got, want) {
			t.Fatalf("size %d: obfuscateSend changed a packet under the zero config", size)
		}
		if got := deobfuscateRecv(pkt, zero); !bytes.Equal(got, want) {
			t.Fatalf("size %d: deobfuscateRecv changed a packet under the zero config", size)
		}
	}
}

// TestObfuscationRoundTripsEveryMessageKind is the core claim. Each kind must
// come back byte-identical, including the restored stock type byte — the
// receiver has to recover the original, not merely strip padding.
func TestObfuscationRoundTripsEveryMessageKind(t *testing.T) {
	cfg := awgTestConfig()
	for _, tc := range []struct {
		name string
		typ  uint8
		size int
	}{
		{"initiation", wire.TypeHandshakeInitiation, wire.SizeHandshakeInitiation},
		{"response", wire.TypeHandshakeResponse, wire.SizeHandshakeResponse},
		{"cookie", wire.TypeCookieReply, wire.SizeCookieReply},
		{"transport-small", wire.TypeTransportData, wire.MinTransportData},
		{"transport-1400", wire.TypeTransportData, 1400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := stockMessage(tc.typ, tc.size)
			want := append([]byte(nil), orig...)

			onWire := obfuscateSend(append([]byte(nil), orig...), cfg)
			if len(onWire) != tc.size+cfg.padFor(tc.typ) {
				t.Fatalf("on-wire length %d, want %d", len(onWire), tc.size+cfg.padFor(tc.typ))
			}
			if onWire[cfg.padFor(tc.typ)] != cfg.typeFor(tc.typ) {
				t.Fatalf("on-wire type byte %#x, want %#x", onWire[cfg.padFor(tc.typ)], cfg.typeFor(tc.typ))
			}

			got := deobfuscateRecv(onWire, cfg)
			if got == nil {
				t.Fatal("deobfuscateRecv rejected a packet it had just produced")
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("round trip changed the packet\n got %x\nwant %x", got, want)
			}
		})
	}
}

// TestObfuscationHidesTheStockSignature states the whole purpose: after the
// transform, neither the fixed type constant nor the fixed length is visible.
// If this fails the protocol is doing nothing an observer would notice.
func TestObfuscationHidesTheStockSignature(t *testing.T) {
	cfg := awgTestConfig()
	init := stockMessage(wire.TypeHandshakeInitiation, wire.SizeHandshakeInitiation)
	onWire := obfuscateSend(init, cfg)

	if len(onWire) == wire.SizeHandshakeInitiation {
		t.Error("the initiation is still 148 bytes on the wire")
	}
	if onWire[0] == wire.TypeHandshakeInitiation {
		t.Error("the initiation still starts with the stock type constant")
	}
}

// TestDeobfuscateRejectsJunk: junk packets are unparseable by construction, and
// the receiver must drop them rather than hand them to the parser. Before this,
// deobfuscateRecv could not return nil at all and every caller's nil check was
// dead code.
func TestDeobfuscateRejectsJunk(t *testing.T) {
	cfg := awgTestConfig()
	for _, n := range []int{1, 8, 40, 200} {
		junk := make([]byte, n)
		for i := range junk {
			junk[i] = 0xff // matches no configured type byte
		}
		if got := deobfuscateRecv(junk, cfg); got != nil {
			t.Errorf("a %d-byte junk datagram was accepted as %x", n, got)
		}
	}
}

// TestDeobfuscateDoesNotCorruptOnAFailedCandidate. The first implementation
// wrote the restored type byte into the buffer while still guessing which kind
// it held, so a wrong guess corrupted the packet for every later one. Feed it a
// transport packet whose length collides with a control message and require the
// payload to survive.
func TestDeobfuscateDoesNotCorruptOnAFailedCandidate(t *testing.T) {
	cfg := awgTestConfig()
	// Length chosen to collide with the padded cookie reply (5 + 64 = 69).
	collide := wire.SizeCookieReply + cfg.PadCookie - cfg.PadTransport
	orig := stockMessage(wire.TypeTransportData, collide)
	want := append([]byte(nil), orig...)

	onWire := obfuscateSend(append([]byte(nil), orig...), cfg)
	got := deobfuscateRecv(onWire, cfg)
	if got == nil {
		t.Fatal("a transport packet colliding with the cookie length was dropped")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the colliding-length candidate corrupted the packet\n got %x\nwant %x", got, want)
	}
}

// TestTypeOnlyObfuscationDoesNotAllocate. Retyping is the configuration that can
// stay on the allocation-free data path, and it must: with S4 unset, the only
// change is one byte, in place.
func TestTypeOnlyObfuscationDoesNotAllocate(t *testing.T) {
	cfg := ObfuscationConfig{TypeTransport: 0x74}
	pkt := stockMessage(wire.TypeTransportData, 1400)
	if n := testing.AllocsPerRun(100, func() { obfuscateSend(pkt, cfg) }); n != 0 {
		t.Fatalf("obfuscateSend allocated %v times per run with padding disabled", n)
	}
}

// TestJunkPacketsRespectTheConfiguredRange. Jc datagrams, each within
// [Jmin, Jmax]. A junk packet outside the range is a signature of its own.
func TestJunkPacketsRespectTheConfiguredRange(t *testing.T) {
	cfg := ObfuscationConfig{JunkCount: 8, JunkMin: 40, JunkMax: 70}
	pkts := junkPackets(cfg)
	if len(pkts) != cfg.JunkCount {
		t.Fatalf("got %d junk packets, want %d", len(pkts), cfg.JunkCount)
	}
	for i, p := range pkts {
		if len(p) < cfg.JunkMin || len(p) > cfg.JunkMax {
			t.Errorf("junk packet %d is %d bytes, outside [%d, %d]", i, len(p), cfg.JunkMin, cfg.JunkMax)
		}
	}
}

// TestJunkPacketsAreDisabledByDefault: the zero config must emit none, or every
// stock WireGuard session starts spraying random datagrams.
func TestJunkPacketsAreDisabledByDefault(t *testing.T) {
	if got := junkPackets(ObfuscationConfig{}); got != nil {
		t.Fatalf("the zero config produced %d junk packets", len(got))
	}
}

// TestJunkPacketsAreNotIdentical: fixed-content junk would itself be a
// signature, which defeats the purpose.
func TestJunkPacketsAreNotIdentical(t *testing.T) {
	cfg := ObfuscationConfig{JunkCount: 6, JunkMin: 64, JunkMax: 64}
	pkts := junkPackets(cfg)
	for i := 1; i < len(pkts); i++ {
		if bytes.Equal(pkts[0], pkts[i]) {
			t.Fatal("two junk packets are byte-identical; the content is not random")
		}
	}
}

// TestMismatchedConfigsDoNotSilentlyPass. There is no negotiation, so a peer
// configured differently must fail closed rather than half-parse.
func TestMismatchedConfigsDoNotSilentlyPass(t *testing.T) {
	send := awgTestConfig()
	recv := awgTestConfig()
	recv.PadInitiation++ // one byte of drift

	onWire := obfuscateSend(stockMessage(wire.TypeHandshakeInitiation, wire.SizeHandshakeInitiation), send)
	if got := deobfuscateRecv(onWire, recv); got != nil {
		t.Fatalf("a mismatched receiver accepted the packet as %d bytes", len(got))
	}
}
