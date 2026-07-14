package eap

import "testing"

// BenchmarkNTPasswordHash measures the NT hash (MD4 of UTF-16LE password),
// computed once per authentication.
func BenchmarkNTPasswordHash(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ntPasswordHash("s3cr3t-password")
	}
}

// BenchmarkGenerateNTResponse measures the DES-based challenge response, the
// core of MSCHAPv2 verification.
func BenchmarkGenerateNTResponse(b *testing.B) {
	var authCh, peerCh [16]byte
	for i := range authCh {
		authCh[i] = byte(i)
		peerCh[i] = byte(255 - i)
	}
	ntHash := ntPasswordHash("s3cr3t-password")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		generateNTResponse(authCh, peerCh, "alice", ntHash)
	}
}

// BenchmarkDeriveMSK measures the MSK derivation (RFC 3079), run once on
// successful authentication.
func BenchmarkDeriveMSK(b *testing.B) {
	ntHash := ntPasswordHash("s3cr3t-password")
	var ntResp [24]byte
	for i := range ntResp {
		ntResp[i] = byte(i)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		deriveMSK(ntHash, ntResp)
	}
}

// BenchmarkFullMSCHAPv2Auth measures a complete server-side authentication:
// challenge generation, response verification and MSK derivation. This is the
// per-login CPU cost for username/password auth.
func BenchmarkFullMSCHAPv2Auth(b *testing.B) {
	lookup := func(u string) (string, bool) { return "wonderland", u == "alice" }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		srv := NewServer(lookup, "vpn.example")
		challenge, err := srv.Begin(1)
		if err != nil {
			b.Fatal(err)
		}
		ch, ok := ParseChallenge(challenge.Data)
		if !ok {
			b.Fatal("bad challenge")
		}
		respData, _ := ch.BuildResponse("alice", "wonderland")
		resp := Packet{Code: CodeResponse, Identifier: challenge.Identifier, Type: TypeMSCHAPv2, Data: respData}
		if _, _, err := srv.HandlePeer(resp); err != nil {
			b.Fatal(err)
		}
		if !srv.Outcome().Success {
			b.Fatal("auth should have succeeded")
		}
	}
}
