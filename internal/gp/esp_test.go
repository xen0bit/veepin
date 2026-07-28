package gp

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

func TestSelectESPAlgos(t *testing.T) {
	cases := []struct {
		name             string
		enc, hmac        []string
		wantEnc, wantMAC string
	}{
		{"nothing offered", nil, nil, "aes-128-cbc", "sha1"},
		{"strongest first", []string{"aes-256-cbc", "aes-128-cbc"}, []string{"sha256", "sha1"}, "aes-256-cbc", "sha256"},
		{"weakest only", []string{"aes-128-cbc"}, []string{"sha1"}, "aes-128-cbc", "sha1"},
		{
			// A client advertising GCM ahead of CBC still gets a working tunnel:
			// the unsupported offer is skipped, not refused.
			"unsupported first",
			[]string{"aes-256-gcm", "aes-128-gcm", "aes-128-cbc"},
			[]string{"md5", "sha1"},
			"aes-128-cbc", "sha1",
		},
		{"nothing in common", []string{"des-cbc"}, []string{"md5"}, "aes-128-cbc", "sha1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, mac := SelectESPAlgos(tc.enc, tc.hmac)
			if enc != tc.wantEnc || mac != tc.wantMAC {
				t.Errorf("SelectESPAlgos = %q/%q, want %q/%q", enc, mac, tc.wantEnc, tc.wantMAC)
			}
		})
	}
}

func TestGenerateESPKeySizes(t *testing.T) {
	cases := []struct {
		enc, hmac      string
		encLen, macLen int
	}{
		{"aes-128-cbc", "sha1", 16, 20},
		{"aes-256-cbc", "sha1", 32, 20},
		{"aes-128-cbc", "sha256", 16, 32},
		{"aes-256-cbc", "sha256", 32, 32},
	}
	for _, tc := range cases {
		t.Run(tc.enc+"/"+tc.hmac, func(t *testing.T) {
			e, err := GenerateESP(tc.enc, tc.hmac)
			if err != nil {
				t.Fatalf("GenerateESP: %v", err)
			}
			if len(e.EKeyC2S) != tc.encLen || len(e.EKeyS2C) != tc.encLen {
				t.Errorf("encryption keys are %d/%d octets, want %d", len(e.EKeyC2S), len(e.EKeyS2C), tc.encLen)
			}
			if len(e.AKeyC2S) != tc.macLen || len(e.AKeyS2C) != tc.macLen {
				t.Errorf("authentication keys are %d/%d octets, want %d", len(e.AKeyC2S), len(e.AKeyS2C), tc.macLen)
			}
			if e.C2SSPI == e.S2CSPI {
				t.Error("both directions got the same SPI")
			}
			// The two directions must not share key material.
			if bytes.Equal(e.EKeyC2S, e.EKeyS2C) || bytes.Equal(e.AKeyC2S, e.AKeyS2C) {
				t.Error("the two directions share a key")
			}
		})
	}
}

// TestGenerateESPRejectsUnsupported: GCM is advertised by real clients but has
// nowhere in this document to carry the RFC 4106 salt, so it is refused with a
// clear error rather than keyed wrongly.
func TestGenerateESPRejectsUnsupported(t *testing.T) {
	for _, tc := range []struct{ enc, hmac string }{
		{"aes-128-gcm", "sha1"},
		{"des-cbc", "sha1"},
		{"aes-128-cbc", "md5"},
		{"", "sha1"},
		{"aes-128-cbc", ""},
	} {
		if _, err := GenerateESP(tc.enc, tc.hmac); err == nil {
			t.Errorf("GenerateESP(%q, %q) was accepted", tc.enc, tc.hmac)
		}
	}
}

// TestSAsInterop is the one that matters: the keying block the gateway generated
// must key a client SA and a server SA that talk to each other, in both
// directions, with the c2s/s2c naming read correctly from each side.
func TestSAsInterop(t *testing.T) {
	for _, algo := range []struct{ enc, hmac string }{
		{"aes-128-cbc", "sha1"},
		{"aes-256-cbc", "sha256"},
	} {
		t.Run(algo.enc+"/"+algo.hmac, func(t *testing.T) {
			e, err := GenerateESP(algo.enc, algo.hmac)
			if err != nil {
				t.Fatalf("GenerateESP: %v", err)
			}
			clientSA, err := e.NewSA(true)
			if err != nil {
				t.Fatalf("client SA: %v", err)
			}
			serverSA, err := e.NewSA(false)
			if err != nil {
				t.Fatalf("server SA: %v", err)
			}

			inner := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 50, 0, 7, 10, 50, 0, 1}

			// Client to gateway.
			pkt, err := clientSA.Encapsulate(inner, 4)
			if err != nil {
				t.Fatalf("client Encapsulate: %v", err)
			}
			if spi := binary.BigEndian.Uint32(pkt[:4]); spi != e.C2SSPI {
				t.Errorf("client sent on SPI %#x, want the c2s SPI %#x", spi, e.C2SSPI)
			}
			got, nh, err := serverSA.Decapsulate(pkt)
			if err != nil {
				t.Fatalf("gateway Decapsulate: %v", err)
			}
			if nh != 4 || !bytes.Equal(got[:len(inner)], inner) {
				t.Errorf("gateway recovered %x (next-header %d), want %x", got, nh, inner)
			}

			// Gateway to client.
			pkt, err = serverSA.Encapsulate(inner, 4)
			if err != nil {
				t.Fatalf("gateway Encapsulate: %v", err)
			}
			if spi := binary.BigEndian.Uint32(pkt[:4]); spi != e.S2CSPI {
				t.Errorf("gateway sent on SPI %#x, want the s2c SPI %#x", spi, e.S2CSPI)
			}
			if _, _, err := clientSA.Decapsulate(pkt); err != nil {
				t.Fatalf("client Decapsulate: %v", err)
			}
		})
	}
}

func TestNewSARejectsBadKeys(t *testing.T) {
	good, err := GenerateESP("aes-128-cbc", "sha1")
	if err != nil {
		t.Fatalf("GenerateESP: %v", err)
	}

	short := *good
	short.EKeyC2S = short.EKeyC2S[:8]
	if _, err := short.NewSA(true); err == nil {
		t.Error("a short encryption key was accepted")
	}

	zeroSPI := *good
	zeroSPI.C2SSPI = 0
	if _, err := zeroSPI.NewSA(true); err == nil {
		t.Error("a zero SPI was accepted")
	}

	unknown := *good
	unknown.EncAlgo = "rot13"
	if _, err := unknown.NewSA(true); err == nil {
		t.Error("an unknown algorithm was accepted")
	}
}

func TestTunnelRoundTrip(t *testing.T) {
	e, err := GenerateESP("aes-128-cbc", "sha1")
	if err != nil {
		t.Fatalf("GenerateESP: %v", err)
	}
	clientSA, _ := e.NewSA(true)
	serverSA, _ := e.NewSA(false)

	peer := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: DefaultESPPort}
	ct := NewTunnel(clientSA, e.S2CSPI, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, peer)
	st := NewTunnel(serverSA, e.C2SSPI, nil, nil)

	if ct.InboundKey() != e.S2CSPI {
		t.Errorf("client inbound key %#x, want %#x", ct.InboundKey(), e.S2CSPI)
	}
	if len(ct.Routes()) != 1 {
		t.Errorf("client routes %v", ct.Routes())
	}
	if ct.PeerAddr() != peer {
		t.Error("the client tunnel lost its peer address")
	}

	inner := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 50, 0, 7, 10, 50, 0, 1}
	pkt, err := ct.Encapsulate(inner)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	got, err := st.Decapsulate(pkt)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(got, inner) {
		t.Errorf("recovered %x, want %x", got, inner)
	}

	// Padded encapsulation must still recover exactly the original packet: the
	// inner IP header's own length is what delimits it.
	padded, err := ct.EncapsulatePadded(inner, 600)
	if err != nil {
		t.Fatalf("EncapsulatePadded: %v", err)
	}
	if len(padded) <= len(pkt) {
		t.Errorf("padded packet is %d octets, not longer than the unpadded %d", len(padded), len(pkt))
	}
	got, err = st.Decapsulate(padded)
	if err != nil {
		t.Fatalf("Decapsulate (padded): %v", err)
	}
	if !bytes.Equal(got, inner) {
		t.Errorf("recovered %x from a padded packet, want %x", got, inner)
	}
}

func TestTunnelSetPeerAddr(t *testing.T) {
	e, _ := GenerateESP("aes-128-cbc", "sha1")
	sa, _ := e.NewSA(false)
	first := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	tun := NewTunnel(sa, e.C2SSPI, nil, first)

	tun.SetPeerAddr(nil)
	if tun.PeerAddr() != first {
		t.Error("a nil address unset the peer")
	}
	same := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	tun.SetPeerAddr(same)
	if tun.PeerAddr() != first {
		t.Error("an unchanged address was stored again")
	}
	moved := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 4321}
	tun.SetPeerAddr(moved)
	if tun.PeerAddr() != moved {
		t.Error("a changed address was not followed")
	}
}

func TestActivationPing(t *testing.T) {
	src := net.ParseIP("10.50.0.7")
	dst := net.ParseIP("198.51.100.1")
	pkt, err := BuildActivationPing(src, dst, 1)
	if err != nil {
		t.Fatalf("BuildActivationPing: %v", err)
	}
	if !IsActivationPing(pkt) {
		t.Fatal("the ping this code built is not recognised by this code")
	}
	if got := onesComplement(pkt[:ipv4HeaderLen]); got != 0 {
		t.Errorf("IPv4 header checksum does not verify (residual %#04x)", got)
	}
	if got := onesComplement(pkt[ipv4HeaderLen:]); got != 0 {
		t.Errorf("ICMP checksum does not verify (residual %#04x)", got)
	}
	if !net.IP(pkt[12:16]).Equal(src.To4()) || !net.IP(pkt[16:20]).Equal(dst.To4()) {
		t.Errorf("addresses are %v -> %v", net.IP(pkt[12:16]), net.IP(pkt[16:20]))
	}
	// The marker must be exactly where a gateway looks for it.
	body := pkt[ipv4HeaderLen+icmpEchoHeadLen:]
	if !bytes.HasPrefix(body, magicPing) {
		t.Errorf("payload starts %q, want the marker", body[:len(magicPing)])
	}
}

func TestActivationPingRejectsIPv6(t *testing.T) {
	if _, err := BuildActivationPing(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 1); err == nil {
		t.Error("an IPv6 activation ping was built")
	}
}

func TestIsActivationPingRejects(t *testing.T) {
	good, err := BuildActivationPing(net.ParseIP("10.50.0.7"), net.ParseIP("198.51.100.1"), 1)
	if err != nil {
		t.Fatalf("BuildActivationPing: %v", err)
	}

	wrongPayload := append([]byte(nil), good...)
	copy(wrongPayload[ipv4HeaderLen+icmpEchoHeadLen:], "not the marker!!")
	notICMP := append([]byte(nil), good...)
	notICMP[9] = 6 // TCP
	reply := append([]byte(nil), good...)
	reply[ipv4HeaderLen] = icmpEchoReply

	cases := []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"too short", good[:20]},
		{"not ipv4", append([]byte{0x60}, good[1:]...)},
		{"not icmp", notICMP},
		{"echo reply", reply},
		{"wrong payload", wrongPayload},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if IsActivationPing(tc.pkt) {
				t.Error("a packet that is not an activation ping was accepted")
			}
		})
	}

	// Every truncation must be rejected rather than read past its end.
	for i := range len(good) {
		if IsActivationPing(good[:i]) {
			t.Errorf("a ping truncated to %d octets was accepted", i)
		}
	}
}

func TestActivationReply(t *testing.T) {
	src := net.ParseIP("10.50.0.7")
	dst := net.ParseIP("198.51.100.1")
	req, err := BuildActivationPing(src, dst, 7)
	if err != nil {
		t.Fatalf("BuildActivationPing: %v", err)
	}
	before := append([]byte(nil), req...)

	reply, err := ActivationReply(req)
	if err != nil {
		t.Fatalf("ActivationReply: %v", err)
	}
	if !bytes.Equal(req, before) {
		t.Error("ActivationReply modified its input")
	}
	if !net.IP(reply[12:16]).Equal(dst.To4()) || !net.IP(reply[16:20]).Equal(src.To4()) {
		t.Errorf("reply addresses are %v -> %v, want them swapped", net.IP(reply[12:16]), net.IP(reply[16:20]))
	}
	if reply[ipv4HeaderLen] != icmpEchoReply {
		t.Errorf("reply ICMP type is %d, want %d", reply[ipv4HeaderLen], icmpEchoReply)
	}
	if got := onesComplement(reply[:ipv4HeaderLen]); got != 0 {
		t.Errorf("reply IPv4 checksum does not verify (residual %#04x)", got)
	}
	if got := onesComplement(reply[ipv4HeaderLen:]); got != 0 {
		t.Errorf("reply ICMP checksum does not verify (residual %#04x)", got)
	}
	// The echoed body must come back unchanged, which is what makes it an echo.
	if !bytes.Equal(reply[ipv4HeaderLen+icmpEchoHeadLen:], req[ipv4HeaderLen+icmpEchoHeadLen:]) {
		t.Error("the reply did not echo the request body")
	}

	if _, err := ActivationReply([]byte{0x45}); err == nil {
		t.Error("ActivationReply accepted a packet that is not an activation ping")
	}
}
