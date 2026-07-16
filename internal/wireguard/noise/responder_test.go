package noise

import (
	"testing"

	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// handshake runs a full Initiator <-> Responder exchange with the real types on
// both sides (unlike the mirror testResponder, which only checks the initiator).
// It returns both keypairs and the peer static key the responder recovered.
func handshake(t *testing.T, initStatic, respStatic [KeySize]byte, initPSK, respPSK [KeySize]byte) (iKeys, rKeys *Keypair, seenStatic [KeySize]byte) {
	t.Helper()

	respPub, err := PublicKey(respStatic)
	if err != nil {
		t.Fatal(err)
	}

	i, err := NewInitiator(Config{LocalStatic: initStatic, RemoteStatic: respPub, PresharedKey: initPSK})
	if err != nil {
		t.Fatal(err)
	}
	initPkt, err := i.Initiation()
	if err != nil {
		t.Fatal(err)
	}

	r, err := NewResponder(respStatic)
	if err != nil {
		t.Fatal(err)
	}
	seenStatic, _, err = r.Consume(initPkt)
	if err != nil {
		t.Fatalf("responder Consume: %v", err)
	}
	respPkt, rk, err := r.Response(respPSK)
	if err != nil {
		t.Fatalf("responder Response: %v", err)
	}

	ik, err := i.Consume(respPkt)
	if err != nil {
		t.Fatalf("initiator Consume: %v", err)
	}
	return ik, rk, seenStatic
}

// TestResponderAgreesWithInitiator is the core property from the responder's
// side: after a full real exchange the two derive mirrored transport keys, the
// responder recovers the initiator's static key, and the indices line up.
func TestResponderAgreesWithInitiator(t *testing.T) {
	for _, tc := range []struct {
		name string
		psk  [KeySize]byte
	}{
		{"without psk", [KeySize]byte{}},
		{"with psk", [KeySize]byte{9, 8, 7, 6, 5, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initStatic, initPriv := genKey(t)
			respStatic, _ := genKey(t)

			ik, rk, seen := handshake(t, initStatic, respStatic, tc.psk, tc.psk)

			if ik.Send != rk.Recv || ik.Recv != rk.Send {
				t.Error("transport keys are not mirrored between the two sides")
			}
			if ik.Send == ik.Recv {
				t.Error("sending and receiving keys are identical")
			}
			if ik.Local != rk.Remote || ik.Remote != rk.Local {
				t.Errorf("indices do not cross: i(%#x/%#x) r(%#x/%#x)",
					ik.Local, ik.Remote, rk.Local, rk.Remote)
			}
			var wantStatic [KeySize]byte
			copy(wantStatic[:], initPriv.PublicKey().Bytes())
			if seen != wantStatic {
				t.Error("responder recovered the wrong initiator static key")
			}
		})
	}
}

// TestResponderRejectsWrongPSK checks that a preshared-key mismatch makes the
// initiator reject the response — the PSK is bound into the transport keys.
func TestResponderRejectsWrongPSK(t *testing.T) {
	initStatic, _ := genKey(t)
	respStatic, _ := genKey(t)
	respPub, _ := PublicKey(respStatic)

	i, _ := NewInitiator(Config{LocalStatic: initStatic, RemoteStatic: respPub, PresharedKey: [KeySize]byte{0xaa}})
	initPkt, _ := i.Initiation()

	r, _ := NewResponder(respStatic)
	if _, _, err := r.Consume(initPkt); err != nil {
		t.Fatal(err)
	}
	respPkt, _, _ := r.Response([KeySize]byte{0xbb}) // different PSK

	if _, err := i.Consume(respPkt); err != ErrDecrypt {
		t.Fatalf("wrong PSK gave %v, want ErrDecrypt", err)
	}
}

// TestResponderRejectsWrongMAC1 checks the cheap DoS filter: an initiation whose
// mac1 is not for our static key is rejected before any DH work.
func TestResponderRejectsWrongMAC1(t *testing.T) {
	initStatic, _ := genKey(t)
	respStatic, _ := genKey(t)
	otherStatic, _ := genKey(t)

	// The initiator addresses a *different* responder's key, so mac1 will not
	// match the one that actually receives it.
	otherPub, _ := PublicKey(otherStatic)
	i, _ := NewInitiator(Config{LocalStatic: initStatic, RemoteStatic: otherPub})
	initPkt, _ := i.Initiation()

	r, _ := NewResponder(respStatic)
	if _, _, err := r.Consume(initPkt); err != ErrMAC1 {
		t.Fatalf("mismatched mac1 gave %v, want ErrMAC1", err)
	}
}

// TestResponderRejectsTamperedStatic checks that flipping a bit in the encrypted
// static is caught as a decryption failure (after mac1, which covers only the
// header). mac1 is recomputed so the tamper reaches the AEAD.
func TestResponderRejectsTamperedStatic(t *testing.T) {
	initStatic, _ := genKey(t)
	respStatic, _ := genKey(t)
	respPub, _ := PublicKey(respStatic)

	i, _ := NewInitiator(Config{LocalStatic: initStatic, RemoteStatic: respPub})
	initPkt, _ := i.Initiation()
	initPkt[45] ^= 0x01 // inside encrypted_static (offset 40..88)
	// Re-stamp mac1 so the packet still authenticates to the responder and the
	// tamper is judged by the AEAD, not the MAC.
	mac1Key := hashOf([]byte(labelMAC1), mustPub(t, respStatic))
	m1 := mac128(mac1Key[:], initPkt[:wire.SizeHandshakeInitiation-2*wire.MACSize])
	copy(initPkt[wire.SizeHandshakeInitiation-2*wire.MACSize:], m1[:])

	r, _ := NewResponder(respStatic)
	if _, _, err := r.Consume(initPkt); err != ErrDecrypt {
		t.Fatalf("tampered static gave %v, want ErrDecrypt", err)
	}
}

// TestResponseBeforeConsume rejects an out-of-order Response.
func TestResponseBeforeConsume(t *testing.T) {
	respStatic, _ := genKey(t)
	r, _ := NewResponder(respStatic)
	if _, _, err := r.Response([KeySize]byte{}); err == nil {
		t.Fatal("Response before Consume was allowed")
	}
}

func mustPub(t *testing.T, priv [KeySize]byte) []byte {
	t.Helper()
	pub, err := PublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub[:]
}
