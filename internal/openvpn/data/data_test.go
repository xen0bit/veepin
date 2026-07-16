package data

import (
	"bytes"
	"testing"

	"github.com/xen0bit/veepin/internal/openvpn/keys"
)

// cipherPair builds a client and server Cipher with crossed keys, so packets one
// seals the other opens, mirroring how key derivation hands each side opposite
// slots.
func cipherPair(t *testing.T) (client, server *Cipher) {
	t.Helper()
	var kA, kB [keys.GCMKeyLen]byte
	var ivA, ivB [keys.ImplicitIVLen]byte
	for i := range kA {
		kA[i] = byte(i + 1)
		kB[i] = byte(i + 100)
	}
	for i := range ivA {
		ivA[i] = byte(i + 8)
		ivB[i] = byte(i + 200)
	}
	clientKeys := keys.DataKeys{EncryptKey: kA, DecryptKey: kB, EncryptIV: ivA, DecryptIV: ivB}
	serverKeys := keys.DataKeys{EncryptKey: kB, DecryptKey: kA, EncryptIV: ivB, DecryptIV: ivA}

	var err error
	client, err = New(clientKeys, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err = New(serverKeys, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestSealOpenRoundTrip(t *testing.T) {
	client, server := cipherPair(t)
	msg := []byte("an inner IP packet's worth of bytes goes here")
	sealed, err := client.Seal(msg)
	if err != nil {
		t.Fatal(err)
	}
	// The wire packet should be exactly Overhead longer than the plaintext.
	if len(sealed) != len(msg)+Overhead {
		t.Errorf("sealed len = %d, want %d", len(sealed), len(msg)+Overhead)
	}
	// Opcode byte names P_DATA_V2.
	if sealed[0]>>opcodeShift != PDataV2 {
		t.Errorf("opcode = %d, want P_DATA_V2", sealed[0]>>opcodeShift)
	}
	got, err := server.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("round trip = %q, want %q", got, msg)
	}
}

func TestPacketIDsIncrement(t *testing.T) {
	client, server := cipherPair(t)
	for i := range 5 {
		sealed, err := client.Seal([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		id := uint32(sealed[4])<<24 | uint32(sealed[5])<<16 | uint32(sealed[6])<<8 | uint32(sealed[7])
		if id != uint32(i+1) {
			t.Errorf("packet %d has ID %d, want %d", i, id, i+1)
		}
		if _, err := server.Open(sealed); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
}

func TestPingRoundTrips(t *testing.T) {
	client, server := cipherPair(t)
	sealed, err := client.Seal(Ping)
	if err != nil {
		t.Fatal(err)
	}
	got, err := server.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !IsPing(got) {
		t.Error("keepalive ping not recognised after round trip")
	}
	if IsPing([]byte("not a ping")) {
		t.Error("IsPing matched a non-ping payload")
	}
}

func TestOpenRejectsReplay(t *testing.T) {
	client, server := cipherPair(t)
	sealed, err := client.Seal([]byte("once"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Open(sealed); err != nil {
		t.Fatal(err)
	}
	// The exact same packet again must be rejected as a replay.
	if _, err := server.Open(sealed); err != errReplay {
		t.Errorf("replay accepted: %v, want errReplay", err)
	}
}

func TestOpenAcceptsReorderWithinWindow(t *testing.T) {
	client, server := cipherPair(t)
	var packets [][]byte
	for i := range 4 {
		p, err := client.Seal([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, p)
	}
	// Deliver out of order: 3, 1, 0, 2. All are within the window and fresh.
	for _, i := range []int{3, 1, 0, 2} {
		if _, err := server.Open(packets[i]); err != nil {
			t.Errorf("reordered open of packet %d failed: %v", i, err)
		}
	}
	// Re-delivering any is now a replay.
	if _, err := server.Open(packets[1]); err != errReplay {
		t.Errorf("reordered replay accepted: %v", err)
	}
}

func TestOpenRejectsTamper(t *testing.T) {
	client, server := cipherPair(t)
	sealed, err := client.Seal([]byte("authentic"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the peer-id header (authenticated but not encrypted): the
	// AEAD tag must reject it.
	tampered := append([]byte(nil), sealed...)
	tampered[1] ^= 0x01
	if _, err := server.Open(tampered); err == nil {
		t.Error("tampered header accepted")
	}
	// Flip a ciphertext bit too.
	tampered = append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := server.Open(tampered); err == nil {
		t.Error("tampered ciphertext accepted")
	}
}

func TestReplayWindowTooOld(t *testing.T) {
	var w replayWindow
	if !w.accept(100) {
		t.Fatal("first packet rejected")
	}
	// A packet far below the window is rejected.
	if w.accept(1) {
		t.Error("packet older than the window accepted")
	}
	// One just inside is accepted.
	if !w.accept(100 - 63) {
		t.Error("packet at the window edge rejected")
	}
	if w.accept(0) {
		t.Error("packet ID 0 accepted")
	}
}
