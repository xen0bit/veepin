package sstp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/sstp/wire"
)

func TestPRFPlusKnownAnswer(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	seed := []byte("test seed")
	n := 32

	got := prfPlus(key, seed, n)
	if len(got) != n {
		t.Fatalf("len = %d, want %d", len(got), n)
	}

	lenLE := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenLE, uint16(n))
	h := hmac.New(sha256.New, key)
	h.Write(seed)
	h.Write(lenLE)
	h.Write([]byte{1})
	t1 := h.Sum(nil)

	if !bytes.Equal(got[:32], t1) {
		t.Error("T1 mismatch")
	}
}

func TestPRFPlusMultipleIterations(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	seed := []byte("longer seed value for testing")
	n := 64

	got := prfPlus(key, seed, n)
	if len(got) != n {
		t.Fatalf("len = %d, want %d", len(got), n)
	}

	lenLE := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenLE, uint16(n))

	h := hmac.New(sha256.New, key)
	h.Write(seed)
	h.Write(lenLE)
	h.Write([]byte{1})
	t1 := h.Sum(nil)

	h.Reset()
	h.Write(t1)
	h.Write(seed)
	h.Write(lenLE)
	h.Write([]byte{2})
	t2 := h.Sum(nil)

	if !bytes.Equal(got[:32], t1) {
		t.Error("T1 mismatch")
	}
	if !bytes.Equal(got[32:], t2) {
		t.Error("T2 mismatch")
	}
}

func TestDeriveCMKLength(t *testing.T) {
	var hlak [mschap.HLAKLen]byte
	for i := range hlak {
		hlak[i] = byte(i)
	}
	cmk := DeriveCMK(hlak)
	if len(cmk) != 32 {
		t.Errorf("CMK length = %d, want 32", len(cmk))
	}
}

func TestExtractAndZeroMAC(t *testing.T) {
	nonce := make([]byte, wire.NonceLen)
	certHash := make([]byte, wire.CertHashLen)
	mac := bytes.Repeat([]byte{0xbb}, wire.CompoundMACLen)

	val := BuildCBValue(nonce, certHash, mac)
	attrs := []wire.Attribute{{ID: wire.AttrCryptoBinding, Value: val}}
	pkt, err := wire.EncodeControl(wire.MsgCallConnected, attrs)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := wire.ReadPacket(bytes.NewReader(pkt))
	if err != nil {
		t.Fatal(err)
	}

	bodyCopy := append([]byte(nil), body...)
	extracted, extractedMAC, err := extractAndZeroMAC(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(extractedMAC, mac) {
		t.Error("extracted MAC mismatch")
	}
	if !bytes.Equal(extracted[68:100], make([]byte, 32)) {
		t.Error("MAC was not zeroed")
	}

	copy(bodyCopy[76:108], make([]byte, 32))
	if !bytes.Equal(body, bodyCopy) {
		t.Error("body modification doesn't match expected zeroing")
	}
}

func TestVerifyCryptoBinding(t *testing.T) {
	vecPassword := "clientPass"
	vecAuthCh := mustHex("5B5D7C7D7B3F2F3E3C2C602132262628")
	vecPeerCh := mustHex("21402324255E262A28295F2B3A337C7E")

	ntResp := mschap.GenerateNTResponse(vecAuthCh, vecPeerCh, "User", vecPassword)
	hlak := mschap.ClientHLAK(vecPassword, ntResp)

	serverCert := []byte("fake-der-encoded-server-certificate-data")
	nonce := bytes.Repeat([]byte{0xcc}, wire.NonceLen)

	// The client builds the CALL_CONNECTED packet (signing the whole packet); the
	// server verifies it. A round trip proves the two agree on the HLAK, the CMK
	// derivation and the exact bytes the compound MAC covers.
	pkt, err := buildCallConnected(nonce, serverCert, hlak)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := wire.ReadPacket(bytes.NewReader(pkt))
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyCryptoBinding(body, hlak, serverCert); err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	// A tampered cert hash must be rejected.
	if err := VerifyCryptoBinding(body, hlak, []byte("different-cert")); err == nil {
		t.Error("verification accepted a wrong certificate")
	}
}

func TestVerifyCryptoBindingWrongCert(t *testing.T) {
	var hlak [32]byte
	hlak[0] = 1
	err := VerifyCryptoBinding(make([]byte, 200), hlak, []byte("wrong-cert"))
	if err == nil {
		t.Fatal("expected error for wrong cert hash")
	}
}

func TestVerifyCryptoBindingShortBody(t *testing.T) {
	var hlak [32]byte
	err := VerifyCryptoBinding([]byte{0, 0, 0, 1}, hlak, []byte("cert"))
	if err == nil {
		t.Fatal("expected error for short body")
	}
}

func mustHex(s string) [16]byte {
	var out [16]byte
	n, err := hexDecode(out[:], []byte(s))
	if err != nil || n != 16 {
		panic("bad hex: " + s)
	}
	return out
}

func hexDecode(dst, src []byte) (int, error) {
	for i := 0; i < len(src)/2; i++ {
		hi := unhex(src[i*2])
		lo := unhex(src[i*2+1])
		if hi < 0 || lo < 0 {
			return i, fmt.Errorf("invalid hex")
		}
		dst[i] = byte(hi<<4) | byte(lo)
	}
	return len(src) / 2, nil
}

func unhex(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c - 'a' + 10)
	case 'A' <= c && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}
