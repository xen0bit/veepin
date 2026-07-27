package data

import (
	"bytes"
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/xen0bit/veepin/internal/openvpn/keys"
)

// cbcPair builds a client and server CBCCipher with crossed keys, so packets one
// seals the other opens, for the given --auth digest.
func cbcPair(t *testing.T, newHash func() hash.Hash, size int) (client, server *CBCCipher) {
	t.Helper()
	var encKey, decKey [keys.GCMKeyLen]byte
	var encMAC, decMAC [64]byte
	for i := range encKey {
		encKey[i] = byte(i + 1)
		decKey[i] = byte(i + 100)
	}
	for i := range encMAC {
		encMAC[i] = byte(i + 3)
		decMAC[i] = byte(i + 200)
	}
	clientKeys := keys.CBCKeys{EncryptKey: encKey, DecryptKey: decKey, EncryptHMAC: encMAC, DecryptHMAC: decMAC}
	serverKeys := keys.CBCKeys{EncryptKey: decKey, DecryptKey: encKey, EncryptHMAC: decMAC, DecryptHMAC: encMAC}

	var err error
	client, err = NewCBC(clientKeys, newHash, size, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewCBC(serverKeys, newHash, size, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestCBCRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  func() hash.Hash
		size int
	}{
		{"SHA1", sha1.New, sha1.Size},
		{"SHA256", sha256.New, sha256.Size},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := cbcPair(t, tc.new, tc.size)
			// Exercise several lengths, including a block-aligned one (full pad block)
			// and an empty payload.
			for _, n := range []int{0, 1, 15, 16, 28, 45, 1400} {
				msg := bytes.Repeat([]byte{byte(n)}, n)
				sealed, err := client.Seal(msg)
				if err != nil {
					t.Fatalf("seal %d: %v", n, err)
				}
				if sealed[0]>>opcodeShift != PDataV2 {
					t.Errorf("opcode = %d, want P_DATA_V2", sealed[0]>>opcodeShift)
				}
				got, err := server.Open(append([]byte(nil), sealed...))
				if err != nil {
					t.Fatalf("open %d: %v", n, err)
				}
				if !bytes.Equal(got, msg) {
					t.Errorf("round trip %d = %x, want %x", n, got, msg)
				}
			}
		})
	}
}

func TestCBCPacketIDsIncrement(t *testing.T) {
	client, server := cbcPair(t, sha256.New, sha256.Size)
	for i := range 5 {
		sealed, err := client.Seal([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.Open(append([]byte(nil), sealed...)); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
	// A replay of the last packet is rejected.
	sealed, _ := client.Seal([]byte("x"))
	if _, err := server.Open(append([]byte(nil), sealed...)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Open(append([]byte(nil), sealed...)); err != errReplay {
		t.Errorf("replay: %v, want errReplay", err)
	}
}

func TestCBCRejectsTamper(t *testing.T) {
	client, server := cbcPair(t, sha256.New, sha256.Size)
	sealed, err := client.Seal([]byte("authentic data here, longer than a block"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a ciphertext bit: the HMAC must reject it before any decryption.
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := server.Open(tampered); err != errAuth {
		t.Errorf("tampered ciphertext: %v, want errAuth", err)
	}
	// Flip an IV bit.
	tampered = append([]byte(nil), sealed...)
	tampered[headerLen+sha256.Size] ^= 0x01
	if _, err := server.Open(tampered); err != errAuth {
		t.Errorf("tampered IV: %v, want errAuth", err)
	}
}

func TestCBCPingRoundTrips(t *testing.T) {
	client, server := cbcPair(t, sha1.New, sha1.Size)
	sealed, err := client.Seal(Ping)
	if err != nil {
		t.Fatal(err)
	}
	got, err := server.Open(append([]byte(nil), sealed...))
	if err != nil {
		t.Fatal(err)
	}
	if !IsPing(got) {
		t.Error("keepalive ping not recognised after CBC round trip")
	}
}

func TestCBCRejectsShort(t *testing.T) {
	_, server := cbcPair(t, sha256.New, sha256.Size)
	if _, err := server.Open(make([]byte, headerLen+sha256.Size)); err != errShort {
		t.Errorf("short packet: %v, want errShort", err)
	}
}

func TestPKCS7Unpad(t *testing.T) {
	// A full padding block.
	block := make([]byte, aes.BlockSize)
	for i := range block {
		block[i] = aes.BlockSize
	}
	out, err := pkcs7Unpad(block)
	if err != nil || len(out) != 0 {
		t.Errorf("full pad block: out=%x err=%v", out, err)
	}
	// A bad pad byte.
	block[len(block)-1] = 0
	if _, err := pkcs7Unpad(block); err != errShort {
		t.Errorf("zero pad: %v, want errShort", err)
	}
}

// TestCBCSealPaddedRoundTrip covers the shaper's vehicle on the CBC data
// channel. The filler sits between the inner packet and the PKCS#7 trailer, so
// the trailer stays valid and the real packet is still delimited by the inner IP
// header — which is what the receiver trims by.
func TestCBCSealPaddedRoundTrip(t *testing.T) {
	client, server := cbcPair(t, sha1.New, sha1.Size)
	for _, size := range []int{20, 64, 576} {
		msg := ipv4(size)
		sealed, err := client.SealPadded(msg, 1400)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		// A padded small packet must be the same size on the wire as a genuine
		// full one. CBC rounds both up to the same block boundary.
		full, err := client.Seal(ipv4(1400))
		if err != nil {
			t.Fatal(err)
		}
		if len(sealed) != len(full) {
			t.Errorf("size %d: padded %d != genuine full %d", size, len(sealed), len(full))
		}
		got, err := server.Open(sealed)
		if err != nil {
			t.Fatalf("size %d: open: %v", size, err)
		}
		if len(got) != 1400 {
			t.Errorf("size %d: opened %d octets, want 1400", size, len(got))
		}
		if !bytes.Equal(got[:size], msg) {
			t.Errorf("size %d: inner packet corrupted", size)
		}
		for i, b := range got[size:] {
			if b != 0 {
				t.Fatalf("size %d: filler byte %d = %#x, want 0", size, i+size, b)
			}
		}
	}
}

// A target at or below the packet's own size must leave it alone.
func TestCBCSealPaddedIsAFloor(t *testing.T) {
	client, _ := cbcPair(t, sha1.New, sha1.Size)
	msg := ipv4(1400)
	padded, err := client.SealPadded(msg, 576)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := client.Seal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(padded) != len(plain) {
		t.Errorf("padded %d != plain %d (a target below the packet must not change it)", len(padded), len(plain))
	}
}
