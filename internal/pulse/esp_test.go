package pulse

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestESPPacketRoundTrip(t *testing.T) {
	k, err := GenerateKeys(EncAES256CBC, HMACSHA256)
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildESPPacket(k)
	if err != nil {
		t.Fatal(err)
	}
	got, block, err := ParseESPPacket(p, EncAES256CBC, HMACSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if got.SPI != k.SPI {
		t.Errorf("SPI = %#x, want %#x", got.SPI, k.SPI)
	}
	if !bytes.Equal(got.EncKey, k.EncKey) || !bytes.Equal(got.HMACKey, k.HMACKey) {
		t.Error("the keys did not round-trip")
	}
	if len(block) != 6+SecretsLen {
		t.Errorf("keying block is %d octets, want %d", len(block), 6+SecretsLen)
	}
}

// TestSPIIsLittleEndian is the point of this test file. Every other length,
// identifier and address in this protocol is big-endian; the ESP SPI is not,
// and a server that got it right in every other respect would hand a client an
// SPI it never matches.
func TestSPIIsLittleEndian(t *testing.T) {
	k := &Keys{
		SPI:      0x01020304,
		EncKey:   make([]byte, 32),
		HMACKey:  make([]byte, 32),
		Encr:     EncAES256CBC,
		Integrit: HMACSHA256,
	}
	p, err := BuildESPPacket(k)
	if err != nil {
		t.Fatal(err)
	}
	if got := p[espSPIAt : espSPIAt+4]; !bytes.Equal(got, []byte{0x04, 0x03, 0x02, 0x01}) {
		t.Fatalf("SPI on the wire = % x, want 04 03 02 01", got)
	}
	// And the big-endian reading is deliberately *not* what comes back.
	if binary.BigEndian.Uint32(p[espSPIAt:]) == k.SPI {
		t.Error("the SPI was written big-endian")
	}
}

// TestKeysAreContiguous pins the layout the keys occupy: the HMAC key follows
// the encryption key immediately, whatever the latter's size, with the block
// zero-padded out to the fixed secrets length.
func TestKeysAreContiguous(t *testing.T) {
	for _, tc := range []struct {
		name             string
		encr, integ      uint16
		encLen, integLen int
	}{
		{"aes128-sha1", EncAES128CBC, HMACSHA1, 16, 20},
		{"aes256-sha256", EncAES256CBC, HMACSHA256, 32, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &Keys{
				SPI:      1,
				EncKey:   bytes.Repeat([]byte{0xaa}, tc.encLen),
				HMACKey:  bytes.Repeat([]byte{0xbb}, tc.integLen),
				Encr:     tc.encr,
				Integrit: tc.integ,
			}
			p, err := BuildESPPacket(k)
			if err != nil {
				t.Fatal(err)
			}
			secrets := p[espSecretsAt : espSecretsAt+SecretsLen]
			for i := range tc.encLen {
				if secrets[i] != 0xaa {
					t.Fatalf("encryption key octet %d = %#x", i, secrets[i])
				}
			}
			for i := range tc.integLen {
				if secrets[tc.encLen+i] != 0xbb {
					t.Fatalf("HMAC key octet %d = %#x", i, secrets[tc.encLen+i])
				}
			}
			for i := tc.encLen + tc.integLen; i < SecretsLen; i++ {
				if secrets[i] != 0 {
					t.Fatalf("padding octet %d = %#x, want zero", i, secrets[i])
				}
			}
		})
	}
}

// TestESPResponseCarriesBothBlocks: the client answers with its own keying
// block followed by a verbatim copy of the server's, which is how the server
// learns the keys it sent were accepted.
func TestESPResponseCarriesBothBlocks(t *testing.T) {
	server, err := GenerateKeys(EncAES256CBC, HMACSHA256)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := BuildESPPacket(server)
	if err != nil {
		t.Fatal(err)
	}
	_, serverBlock, err := ParseESPPacket(sp, EncAES256CBC, HMACSHA256)
	if err != nil {
		t.Fatal(err)
	}

	client, err := GenerateKeys(EncAES256CBC, HMACSHA256)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := BuildESPResponse(client, serverBlock)
	if err != nil {
		t.Fatal(err)
	}

	// The server reads the client's block off the front.
	got, _, err := ParseESPPacket(resp, EncAES256CBC, HMACSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if got.SPI != client.SPI || !bytes.Equal(got.EncKey, client.EncKey) {
		t.Error("the client's own block did not come first")
	}
	// The server's own block is echoed after it, unchanged.
	echo := resp[espSPIAt+len(serverBlock) : espSPIAt+2*len(serverBlock)]
	if !bytes.Equal(echo, serverBlock) {
		t.Error("the server's block was not echoed verbatim")
	}
	// Both length fields still describe the longer packet.
	if got := binary.BigEndian.Uint32(resp[espPayloadLenAt:]); int(got) != len(resp) {
		t.Errorf("payload length = %#x, want %#x", got, len(resp))
	}
	if got := binary.BigEndian.Uint32(resp[espInnerLenAt:]); int(got) != len(resp)-espInnerLenAt {
		t.Errorf("inner length = %#x", got)
	}
}

func TestParseESPPacketRejectsGarbage(t *testing.T) {
	k, err := GenerateKeys(EncAES256CBC, HMACSHA256)
	if err != nil {
		t.Fatal(err)
	}
	full, err := BuildESPPacket(k)
	if err != nil {
		t.Fatal(err)
	}
	for i := range len(full) {
		if _, _, err := ParseESPPacket(full[:i], EncAES256CBC, HMACSHA256); err == nil {
			t.Errorf("prefix of %d octets was accepted", i)
		}
	}
	for _, tc := range []struct {
		name string
		off  int
		val  uint32
	}{
		{"signature", espSigOffset, 0xdeadbeef},
		{"payload length", espPayloadLenAt, 0xffff},
		{"inner length", espInnerLenAt, 0xffff},
		{"constant", espConstAt, 0},
	} {
		bad := append([]byte(nil), full...)
		binary.BigEndian.PutUint32(bad[tc.off:], tc.val)
		if _, _, err := ParseESPPacket(bad, EncAES256CBC, HMACSHA256); err == nil {
			t.Errorf("a packet with a wrong %s was accepted", tc.name)
		}
	}
	bad := append([]byte(nil), full...)
	binary.BigEndian.PutUint16(bad[espSecretsLenAt:], 0x20)
	if _, _, err := ParseESPPacket(bad, EncAES256CBC, HMACSHA256); err == nil {
		t.Error("a packet with a non-standard secrets length was accepted")
	}
}

// TestUnsupportedSuitesAreRefused: HMAC-MD5 is one of the three values this
// protocol can name and veepin will not carry it. Refusing with a clear message
// beats silently keying something weaker than the peer thinks.
func TestUnsupportedSuitesAreRefused(t *testing.T) {
	if _, err := GenerateKeys(EncAES256CBC, HMACMD5); err == nil {
		t.Error("HMAC-MD5 was accepted")
	}
	if _, err := GenerateKeys(0x9999, HMACSHA256); err == nil {
		t.Error("an unknown cipher was accepted")
	}
}

func TestNewSAMirrors(t *testing.T) {
	a, err := GenerateKeys(EncAES256CBC, HMACSHA256)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKeys(EncAES256CBC, HMACSHA256)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewSA(a, b)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSA(b, a)
	if err != nil {
		t.Fatal(err)
	}
	if client.SPIOut != server.SPIIn || client.SPIIn != server.SPIOut {
		t.Fatal("the two ends' SPIs do not mirror")
	}

	pkt, err := client.Encapsulate([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}, 4)
	if err != nil {
		t.Fatal(err)
	}
	inner, nh, err := server.Decapsulate(pkt)
	if err != nil {
		t.Fatalf("the peer could not open what we sealed: %v", err)
	}
	if nh != 4 || inner[0] != 0x45 {
		t.Errorf("inner = %x (next header %d)", inner[:4], nh)
	}
}

// TestKeyBlocksNameTheirOwnInboundDirection pins the rule that a mutually
// consistent mistake hides: each keying block describes the direction its
// *sender* will be received on. The server's block is what the client stamps on
// packets to the server; the client's block is what the server stamps on packets
// back.
//
// Wiring both ends the other way round produces two SAs that still agree with
// each other, so veepin<->veepin passes and only a real peer notices. This test
// is that peer: it builds the SAs the two ends build and checks that the SPI a
// client sends with is the one the server's block named.
func TestKeyBlocksNameTheirOwnInboundDirection(t *testing.T) {
	serverKeys, err := GenerateKeys(EncAES256CBC, HMACSHA256)
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, err := GenerateKeys(EncAES256CBC, HMACSHA256)
	if err != nil {
		t.Fatal(err)
	}

	// Built exactly as internal/pulse's two roles build them.
	clientSA, err := NewSA(serverKeys, clientKeys)
	if err != nil {
		t.Fatal(err)
	}
	serverSA, err := NewSA(clientKeys, serverKeys)
	if err != nil {
		t.Fatal(err)
	}

	if clientSA.SPIOut != serverKeys.SPI {
		t.Errorf("the client sends with SPI %#x, want the server block's %#x", clientSA.SPIOut, serverKeys.SPI)
	}
	if serverSA.SPIIn != serverKeys.SPI {
		t.Errorf("the server receives on SPI %#x, want its own block's %#x", serverSA.SPIIn, serverKeys.SPI)
	}
	if serverSA.SPIOut != clientKeys.SPI {
		t.Errorf("the server sends with SPI %#x, want the client block's %#x", serverSA.SPIOut, clientKeys.SPI)
	}
	if clientSA.SPIIn != clientKeys.SPI {
		t.Errorf("the client receives on SPI %#x, want its own block's %#x", clientSA.SPIIn, clientKeys.SPI)
	}

	// And the probe survives a round trip both ways, which is what the two ends
	// actually exchange first.
	probe, err := clientSA.Encapsulate([]byte{0}, 4)
	if err != nil {
		t.Fatal(err)
	}
	inner, _, err := serverSA.Decapsulate(probe)
	if err != nil {
		t.Fatalf("the server could not open the client's probe: %v", err)
	}
	echo, err := serverSA.Encapsulate(inner, 4)
	if err != nil {
		t.Fatal(err)
	}
	if back, _, derr := clientSA.Decapsulate(echo); derr != nil || len(back) != 1 || back[0] != 0 {
		t.Fatalf("the client could not open the echo: %v (%x)", derr, back)
	}
}
