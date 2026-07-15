package ike

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/ikennkt/internal/payload"
)

// BenchmarkSKSeal measures building an encrypted (SK) IKE message: padding,
// AEAD seal and framing. This runs for every protected message sent.
func BenchmarkSKSeal(b *testing.B) {
	suite := buildTestSuite(b, payload.ENCR_AES_GCM_16)
	keys := randomKeys(suite)
	inner := makeInnerChain()
	hdr := payload.Header{
		InitiatorSPI: 0x1111, ResponderSPI: 0x2222,
		ExchangeType: payload.IKE_AUTH, Flags: payload.FlagResponse, MessageID: 1,
	}
	b.SetBytes(int64(len(inner)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := buildEncryptedMessage(hdr, suite, keys, dirResponderToInitiator,
			payload.TypeIDr, inner); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSKOpen measures decrypting and verifying a received SK message.
func BenchmarkSKOpen(b *testing.B) {
	suite := buildTestSuite(b, payload.ENCR_AES_GCM_16)
	keys := randomKeys(suite)
	inner := makeInnerChain()
	hdr := payload.Header{
		InitiatorSPI: 0x1111, ResponderSPI: 0x2222,
		ExchangeType: payload.IKE_AUTH, Flags: payload.FlagResponse, MessageID: 1,
	}
	pkt, err := buildEncryptedMessage(hdr, suite, keys, dirResponderToInitiator, payload.TypeIDr, inner)
	if err != nil {
		b.Fatal(err)
	}
	msg, err := payload.ParseMessage(pkt)
	if err != nil {
		b.Fatal(err)
	}
	sk := msg.Find(payload.TypeSK)
	b.SetBytes(int64(len(inner)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := decryptSK(pkt, msg.Header, *sk, suite, keys, dirResponderToInitiator); err != nil {
			b.Fatal(err)
		}
	}
}

// makeInnerChain builds a representative IKE_AUTH inner payload chain.
func makeInnerChain() []byte {
	b := payload.NewBuilder()
	b.Add(payload.TypeIDr, false, payload.MarshalID(payload.IDPayload{Type: payload.IDFQDN, Data: []byte("vpn.example")}))
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{Method: payload.AuthSharedKeyMIC, Data: make([]byte, 32)}))
	return b.Bytes()
}

// BenchmarkFullHandshakePSK measures end-to-end handshake latency (IKE_SA_INIT +
// IKE_AUTH with PSK) over real UDP loopback against the live server. This is the
// per-client connection setup cost including all asymmetric crypto and I/O.
func BenchmarkFullHandshakePSK(b *testing.B) {
	psk := []byte("bench-psk")
	p500 := freeUDPPortB(b)
	p4500 := freeUDPPortB(b)

	cfg := Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		PSK:      psk,
		LocalID:  FQDNIdentity("vpn.example"),
		PublicIP: net.ParseIP("127.0.0.1"),
		Logger:   log.New(io.Discard, "", 0),
		AssignAddr: func() (net.IP, net.IP, []net.IP, error) {
			return net.IPv4(10, 0, 0, 2), net.IPv4(255, 255, 255, 0), nil, nil
		},
	}
	srv, err := NewServer(cfg)
	if err != nil {
		b.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer srv.Close()
	time.Sleep(50 * time.Millisecond)

	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p500}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.DialUDP("udp", nil, serverAddr)
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		it := &initiator{tb: b, conn: conn, psk: psk, id: FQDNIdentity("client")}
		it.doSAInit()
		it.doAuth()
		conn.Close()
	}
}

// freeUDPPortB is the *testing.B analogue of freeUDPPort.
func freeUDPPortB(b *testing.B) int {
	b.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return p
}
