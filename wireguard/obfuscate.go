// AmneziaWG wire obfuscation. The cryptography is untouched — this is stock
// Noise IK with stock ChaCha20-Poly1305 — and only the *shape* of each datagram
// changes, to defeat the signature that makes WireGuard trivially classifiable:
// a fixed one-byte message type followed by three zero bytes, and three fixed
// message lengths (148, 92, 64).
//
//	stock:      [ 04 00 00 00 | receiver | counter | ciphertext ]
//	obfuscated: [ <-- S4 random bytes --> | H4 00 00 00 | ... ]
//
// Both peers must be configured identically; there is no negotiation, because a
// negotiation would itself be a signature.
//
// The receive side does not guess. WireGuard's three control messages have fixed
// lengths, so a datagram's total length identifies which one it is (given the
// configured padding), and anything else is transport data. That is how
// amneziawg-go does it, and it is why the padding sizes must match on both ends.
package wireguard

import (
	"crypto/rand"
	"math/big"

	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// ObfuscationConfig parameterises the AmneziaWG wire format. The zero value is
// stock WireGuard, byte for byte.
type ObfuscationConfig struct {
	// TypeInitiation/Response/Cookie/Transport (H1..H4) replace the four fixed
	// message-type constants. Zero leaves the stock value (1, 2, 3, 4).
	TypeInitiation uint8
	TypeResponse   uint8
	TypeCookie     uint8
	TypeTransport  uint8

	// PadInitiation/Response/Cookie/Transport (S1..S4) are bytes of random
	// padding prepended to each message kind, breaking the fixed-length
	// signature.
	PadInitiation int
	PadResponse   int
	PadCookie     int
	PadTransport  int

	// JunkCount (Jc) is how many junk datagrams to emit before the handshake,
	// each of a random size in [JunkMin, JunkMax]. They are unparseable by
	// design: a peer discards them, and a classifier watching for a 148-byte
	// first packet sees noise instead. Zero disables them.
	JunkCount int
	JunkMin   int
	JunkMax   int
}

// enabled reports whether any transform applies. The zero config takes every
// fast path unchanged, which is what keeps stock WireGuard's data path
// allocation-free.
func (o ObfuscationConfig) enabled() bool { return o != ObfuscationConfig{} }

// typeFor returns the on-wire type byte for a stock message type.
func (o ObfuscationConfig) typeFor(stock uint8) uint8 {
	switch stock {
	case wire.TypeHandshakeInitiation:
		if o.TypeInitiation != 0 {
			return o.TypeInitiation
		}
	case wire.TypeHandshakeResponse:
		if o.TypeResponse != 0 {
			return o.TypeResponse
		}
	case wire.TypeCookieReply:
		if o.TypeCookie != 0 {
			return o.TypeCookie
		}
	case wire.TypeTransportData:
		if o.TypeTransport != 0 {
			return o.TypeTransport
		}
	}
	return stock
}

// padFor returns the padding prepended to a stock message type.
func (o ObfuscationConfig) padFor(stock uint8) int {
	switch stock {
	case wire.TypeHandshakeInitiation:
		return o.PadInitiation
	case wire.TypeHandshakeResponse:
		return o.PadResponse
	case wire.TypeCookieReply:
		return o.PadCookie
	case wire.TypeTransportData:
		return o.PadTransport
	}
	return 0
}

// obfuscateSend applies the outbound transforms. It returns pkt itself when
// nothing applies — the common case, and the one the AllocsPerRun guard in
// datapath_test.go covers. When padding is configured for this message kind a
// new slice is unavoidable, since the padding goes in front of bytes the caller
// already built.
func obfuscateSend(pkt []byte, cfg ObfuscationConfig) []byte {
	if !cfg.enabled() || len(pkt) < 4 {
		return pkt
	}
	stock := pkt[0]
	pad := cfg.padFor(stock)
	newType := cfg.typeFor(stock)

	if pad == 0 {
		// Type-only rewrite: in place, no allocation. The three bytes after the
		// type are WireGuard's reserved zeroes and stay zero — amneziawg-go does
		// not touch them, and filling them would make veepin distinguishable
		// from the very implementation it has to look like.
		if newType != stock {
			pkt[0] = newType
		}
		return pkt
	}

	out := make([]byte, pad+len(pkt))
	randFill(out[:pad])
	copy(out[pad:], pkt)
	out[pad] = newType
	return out
}

// deobfuscateRecv reverses the outbound transforms, returning a subslice of pkt.
// It identifies the message kind by total length: WireGuard's three control
// messages are fixed-size, so length plus the configured padding is decisive.
// Anything that matches none of them is transport data.
//
// Returns nil for a datagram that cannot be any valid message — a junk packet,
// or a stray — so the caller drops it rather than feeding the parser garbage.
func deobfuscateRecv(pkt []byte, cfg ObfuscationConfig) []byte {
	if !cfg.enabled() {
		return pkt
	}
	for _, k := range [...]struct {
		stock uint8
		size  int
	}{
		{wire.TypeHandshakeInitiation, wire.SizeHandshakeInitiation},
		{wire.TypeHandshakeResponse, wire.SizeHandshakeResponse},
		{wire.TypeCookieReply, wire.SizeCookieReply},
	} {
		pad := cfg.padFor(k.stock)
		if len(pkt) != pad+k.size {
			continue
		}
		out := pkt[pad:]
		if out[0] != cfg.typeFor(k.stock) {
			// Right length, wrong type byte: not this message after all. A
			// transport packet can collide with a control message's length, so
			// fall through rather than rejecting outright.
			continue
		}
		out[0] = k.stock
		return out
	}

	// Transport data: variable length, so only the padding can be stripped.
	pad := cfg.padFor(wire.TypeTransportData)
	if len(pkt) < pad+wire.MinTransportData {
		return nil
	}
	out := pkt[pad:]
	if out[0] != cfg.typeFor(wire.TypeTransportData) {
		return nil
	}
	out[0] = wire.TypeTransportData
	return out
}

// junkPackets builds the Jc datagrams sent before a handshake. Each is uniform
// random of a random length in [JunkMin, JunkMax], which is what makes them
// unparseable: a peer's Type check rejects them, and they cost it nothing.
func junkPackets(cfg ObfuscationConfig) [][]byte {
	if cfg.JunkCount <= 0 || cfg.JunkMax <= 0 || cfg.JunkMin > cfg.JunkMax {
		return nil
	}
	out := make([][]byte, 0, cfg.JunkCount)
	span := cfg.JunkMax - cfg.JunkMin + 1
	for range cfg.JunkCount {
		n := cfg.JunkMin
		if span > 1 {
			if r, err := rand.Int(rand.Reader, big.NewInt(int64(span))); err == nil {
				n = cfg.JunkMin + int(r.Int64())
			}
		}
		if n <= 0 {
			continue
		}
		p := make([]byte, n)
		randFill(p)
		out = append(out, p)
	}
	return out
}

// randFill fills b with cryptographic randomness. crypto/rand.Read is
// documented never to fail; if the platform's entropy source is broken there is
// nothing sensible to send, and emitting predictable padding would silently
// defeat the obfuscation this file exists to provide.
func randFill(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("wireguard: crypto/rand failed: " + err.Error())
	}
}
