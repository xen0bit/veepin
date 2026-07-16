package ike

import (
	"encoding/binary"

	"github.com/xen0bit/veepin/internal/cryptoutil"
)

// SAKeys holds the derived IKE SA keying material (RFC 7296 section 2.14).
type SAKeys struct {
	SKd  []byte // used to derive Child SA keys
	SKai []byte // integrity, initiator->responder
	SKar []byte // integrity, responder->initiator
	SKei []byte // encryption, initiator->responder
	SKer []byte // encryption, responder->initiator
	SKpi []byte // AUTH generation, initiator
	SKpr []byte // AUTH generation, responder
}

// DeriveIKEKeys computes SKEYSEED and the seven SK_* values.
//
//	SKEYSEED = prf(Ni | Nr, g^ir)
//	{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
//	    = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
//
// encKeyLen and integKeyLen are per-direction key lengths in bytes. For AEAD
// ciphers integKeyLen is 0.
func DeriveIKEKeys(prf *cryptoutil.PRF, sharedSecret, ni, nr []byte, spiI, spiR uint64,
	encKeyLen, integKeyLen int) (skeyseed []byte, keys SAKeys) {

	nonces := append(append([]byte(nil), ni...), nr...)
	skeyseed = prf.Apply(nonces, sharedSecret)

	seed := make([]byte, 0, len(ni)+len(nr)+16)
	seed = append(seed, ni...)
	seed = append(seed, nr...)
	var spi [8]byte
	binary.BigEndian.PutUint64(spi[:], spiI)
	seed = append(seed, spi[:]...)
	binary.BigEndian.PutUint64(spi[:], spiR)
	seed = append(seed, spi[:]...)

	total := prf.Size + 2*integKeyLen + 2*encKeyLen + 2*prf.Size
	km := prf.Plus(skeyseed, seed, total)

	off := 0
	take := func(n int) []byte {
		b := km[off : off+n]
		off += n
		return b
	}
	keys.SKd = take(prf.Size)
	keys.SKai = take(integKeyLen)
	keys.SKar = take(integKeyLen)
	keys.SKei = take(encKeyLen)
	keys.SKer = take(encKeyLen)
	keys.SKpi = take(prf.Size)
	keys.SKpr = take(prf.Size)
	return skeyseed, keys
}

// DeriveChildKeys computes the Child SA keying material (RFC 7296 2.17):
//
//	KEYMAT = prf+(SK_d, [g^ir (new)] | Ni | Nr)
//
// When there is no new DH exchange for the child (the common case), the DH
// output is empty. The caller slices the result per the negotiated ESP
// suite: encr_i | integ_i | encr_r | integ_r.
func DeriveChildKeys(prf *cryptoutil.PRF, skd, dhSecret, ni, nr []byte, total int) []byte {
	seed := make([]byte, 0, len(dhSecret)+len(ni)+len(nr))
	seed = append(seed, dhSecret...)
	seed = append(seed, ni...)
	seed = append(seed, nr...)
	return prf.Plus(skd, seed, total)
}

// AuthOctets computes the data signed/MAC'd by an endpoint's AUTH payload
// (RFC 7296 section 2.15):
//
//	InitiatorSignedOctets = RealMessage1 | NonceRData | prf(SK_pi, IDi')
//	ResponderSignedOctets = RealMessage2 | NonceIData | prf(SK_pr, IDr')
//
// realMessage is the first message this endpoint sent (the full IKE_SA_INIT
// request for the initiator, or response for the responder). peerNonce is the
// other side's nonce. idPayload is the ID payload body (type + reserved +
// data), i.e. everything after the generic payload header, hashed with the
// endpoint's own SK_p.
func AuthOctets(prf *cryptoutil.PRF, realMessage, peerNonce, skp, idPayload []byte) []byte {
	idPrime := prf.Apply(skp, idPayload)
	out := make([]byte, 0, len(realMessage)+len(peerNonce)+len(idPrime))
	out = append(out, realMessage...)
	out = append(out, peerNonce...)
	out = append(out, idPrime...)
	return out
}

// PSKAuth computes the AUTH payload value for shared-key authentication
// (RFC 7296 section 2.15):
//
//	AUTH = prf(prf(Shared Secret, "Key Pad for IKEv2"), <signed octets>)
func PSKAuth(prf *cryptoutil.PRF, psk, signedOctets []byte) []byte {
	const keyPad = "Key Pad for IKEv2"
	inner := prf.Apply(psk, []byte(keyPad))
	return prf.Apply(inner, signedOctets)
}
