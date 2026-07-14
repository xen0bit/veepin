package eap

import (
	"encoding/hex"
	"testing"
)

func TestMSCHAPv2Vectors(t *testing.T) {
	// From draft-ietf-pppext-mschapv2-keys-02 (password "clientPass").
	pw := "clientPass"
	ntHash := ntPasswordHash(pw)
	if got := hex.EncodeToString(ntHash); got != "44ebba8d5312b8d611474411f56989ae" {
		t.Fatalf("NtPasswordHash=%s", got)
	}
	hh := ntPasswordHashHash(ntHash)
	if got := hex.EncodeToString(hh); got != "41c00c584bd2d91c4017a2a12fa59f3f" {
		t.Fatalf("PasswordHashHash=%s", got)
	}
	// NT-Response = 82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF
	ntResp, _ := hex.DecodeString("82309ecd8d708b5ea08faa3981cd8354423311 4a3d85d6df"[:0] + "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df")
	var nr [24]byte
	copy(nr[:], ntResp)
	mk := getMasterKey(hh, nr)
	if got := hex.EncodeToString(mk); got != "fdece3717a8c838cb388e527ae3cdd31" {
		t.Fatalf("MasterKey=%s want fdece3717a8c838cb388e527ae3cdd31", got)
	}
	sendKey := getAsymmetricStartKey(mk, 16, true, true)
	if got := hex.EncodeToString(sendKey); got != "8b7cdc149b993a1ba118cb153f56dccb" {
		t.Fatalf("SendStartKey=%s want 8b7cdc149b993a1ba118cb153f56dccb", got)
	}
	t.Logf("all MSCHAPv2 key-derivation vectors match")
}
