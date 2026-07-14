package payload

import (
	"net"
	"testing"
)

// buildSAInitMessage assembles a representative IKE_SA_INIT message for codec
// benchmarks: header + SA + KE + Nonce + two Notify payloads.
func buildSAInitMessage() []byte {
	sa := SAPayload{Proposals: []Proposal{{
		Num:      1,
		Protocol: ProtoIKE,
		Transforms: []Transform{
			{Type: TransformENCR, ID: ENCR_AES_GCM_16, KeyLen: 256},
			{Type: TransformPRF, ID: PRF_HMAC_SHA2_256},
			{Type: TransformDH, ID: DH_CURVE25519},
		},
	}}}
	b := NewBuilder()
	b.Add(TypeSA, false, MarshalSA(sa))
	b.Add(TypeKE, false, MarshalKE(KEPayload{Group: DH_CURVE25519, KeyData: make([]byte, 32)}))
	b.Add(TypeNonce, false, MarshalNonce(make([]byte, 32)))
	b.Add(TypeNotify, false, MarshalNotify(NotifyPayload{Type: NATDetectionSourceIP, Data: make([]byte, 20)}))
	b.Add(TypeNotify, false, MarshalNotify(NotifyPayload{Type: NATDetectionDestinationIP, Data: make([]byte, 20)}))
	chain := b.Bytes()
	h := Header{
		NextPayload:  b.FirstType(),
		Version:      0x20,
		ExchangeType: IKE_SA_INIT,
		Length:       uint32(HeaderLen + len(chain)),
	}
	return append(h.Marshal(nil), chain...)
}

// BenchmarkParseMessage measures decoding a full IKE_SA_INIT message.
func BenchmarkParseMessage(b *testing.B) {
	msg := buildSAInitMessage()
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseMessage(msg); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBuildMessage measures assembling an IKE_SA_INIT payload chain.
func BenchmarkBuildMessage(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = buildSAInitMessage()
	}
}

// BenchmarkMarshalParseSA isolates SA proposal encode+decode, the most complex
// payload structure.
func BenchmarkMarshalParseSA(b *testing.B) {
	sa := SAPayload{Proposals: []Proposal{{
		Num:      1,
		Protocol: ProtoESP,
		SPI:      []byte{1, 2, 3, 4},
		Transforms: []Transform{
			{Type: TransformENCR, ID: ENCR_AES_GCM_16, KeyLen: 256},
			{Type: TransformINTEG, ID: AUTH_HMAC_SHA2_256_128},
			{Type: TransformESN, ID: ESN_NONE},
		},
	}}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseSA(MarshalSA(sa)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMarshalParseTS isolates traffic-selector encode+decode.
func BenchmarkMarshalParseTS(b *testing.B) {
	ts := TSPayload{Selectors: []TrafficSelector{{
		Type:      TSIPv4AddrRange,
		StartPort: 0, EndPort: 65535,
		StartAddr: net.IPv4zero.To4(),
		EndAddr:   net.IP{255, 255, 255, 255},
	}}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseTS(MarshalTS(ts)); err != nil {
			b.Fatal(err)
		}
	}
}
