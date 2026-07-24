package ike

import (
	"fmt"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// Suite is a fully-resolved IKE cipher suite ready for key derivation and SK
// protection.
type Suite struct {
	EncrID    uint16
	EncrKeyLn uint16 // bits; 0 if fixed
	PRFID     uint16
	IntegID   uint16 // 0 for AEAD
	DHID      uint16

	Cipher cryptoutil.SKCipher
	PRF    *cryptoutil.PRF
	Integ  *cryptoutil.Integrity // nil for AEAD
}

// DefaultIKEProposal returns the proposal this server offers/accepts for the
// IKE SA. Order signals preference. AEAD suites are listed first.
// DefaultIKEProposal returns the proposal this server offers/accepts for the
// IKE SA. Transforms are ordered by preference: AEAD ciphers first (AES-GCM,
// fastest and integrity-combined), then AES-CBC for older clients; SHA2 PRFs;
// and elliptic-curve DH groups before MODP-2048 (which is ~75x slower per the
// benchmarks). Offering both 128- and 256-bit AES lets a client negotiate the
// faster 128-bit variant when its policy allows.
func DefaultIKEProposal() payload.Proposal {
	return payload.Proposal{
		Num:      1,
		Protocol: payload.ProtoIKE,
		Transforms: []payload.Transform{
			{Type: payload.TransformENCR, ID: payload.ENCR_AES_GCM_16, KeyLen: 256},
			{Type: payload.TransformENCR, ID: payload.ENCR_AES_GCM_16, KeyLen: 128},
			// ChaCha20-Poly1305 (RFC 7634) carries no key-length attribute (the
			// key is always 256-bit), hence KeyLen 0. Offered after AES-GCM, which
			// is faster where the CPU has AES-NI, and ahead of AES-CBC.
			{Type: payload.TransformENCR, ID: payload.ENCR_CHACHA20_P},
			{Type: payload.TransformENCR, ID: payload.ENCR_AES_CBC, KeyLen: 256},
			{Type: payload.TransformPRF, ID: payload.PRF_HMAC_SHA2_256},
			{Type: payload.TransformPRF, ID: payload.PRF_HMAC_SHA2_384},
			{Type: payload.TransformPRF, ID: payload.PRF_HMAC_SHA2_512},
			{Type: payload.TransformINTEG, ID: payload.AUTH_HMAC_SHA2_256_128},
			{Type: payload.TransformDH, ID: payload.DH_CURVE25519},
			{Type: payload.TransformDH, ID: payload.DH_ECP_256},
			{Type: payload.TransformDH, ID: payload.DH_ECP_384},
			{Type: payload.TransformDH, ID: payload.DH_MODP_2048},
		},
	}
}

// DefaultESPProposal returns the Child SA (ESP) proposal offered/accepted.
// DefaultESPProposal returns the Child SA (ESP) proposal offered/accepted.
// AES-GCM is offered first (dramatically faster than AES-CBC+HMAC on the data
// path — see the benchmarks), in both 256- and 128-bit variants, with AES-CBC
// as a fallback for older clients.
func DefaultESPProposal(spi []byte) payload.Proposal {
	return payload.Proposal{
		Num:      1,
		Protocol: payload.ProtoESP,
		SPI:      spi,
		Transforms: []payload.Transform{
			{Type: payload.TransformENCR, ID: payload.ENCR_AES_GCM_16, KeyLen: 256},
			{Type: payload.TransformENCR, ID: payload.ENCR_AES_GCM_16, KeyLen: 128},
			// ChaCha20-Poly1305 (RFC 7634): AEAD, no key-length attribute.
			{Type: payload.TransformENCR, ID: payload.ENCR_CHACHA20_P},
			{Type: payload.TransformENCR, ID: payload.ENCR_AES_CBC, KeyLen: 256},
			{Type: payload.TransformINTEG, ID: payload.AUTH_HMAC_SHA2_256_128},
			{Type: payload.TransformESN, ID: payload.ESN_NONE},
		},
	}
}

// isAEAD reports whether an ENCR transform is an AEAD cipher (no separate
// integrity transform is used).
func isAEAD(encrID uint16) bool {
	switch encrID {
	case payload.ENCR_AES_GCM_16, payload.ENCR_CHACHA20_P:
		return true
	default:
		return false
	}
}

// supportedENCR / supportedPRF / etc. gate what we will accept from a peer.
func supportedENCR(id uint16) bool {
	return id == payload.ENCR_AES_GCM_16 || id == payload.ENCR_CHACHA20_P || id == payload.ENCR_AES_CBC
}
func supportedPRF(id uint16) bool {
	switch id {
	case payload.PRF_HMAC_SHA1, payload.PRF_HMAC_SHA2_256, payload.PRF_HMAC_SHA2_384, payload.PRF_HMAC_SHA2_512:
		return true
	}
	return false
}
func supportedInteg(id uint16) bool {
	switch id {
	case payload.AUTH_HMAC_SHA1_96, payload.AUTH_HMAC_SHA2_256_128,
		payload.AUTH_HMAC_SHA2_384_192, payload.AUTH_HMAC_SHA2_512_256:
		return true
	}
	return false
}
func supportedDH(id uint16) bool {
	switch id {
	case payload.DH_CURVE25519, payload.DH_ECP_256, payload.DH_ECP_384,
		payload.DH_ECP_521, payload.DH_MODP_2048:
		return true
	}
	return false
}

// chosenTransform picks, for one transform category, the first entry in the
// peer proposal that we support. Returns the transform and whether found.
func chosenTransform(p payload.Proposal, tt payload.TransformType, ok func(uint16) bool) (payload.Transform, bool) {
	for _, tr := range p.Transforms {
		if tr.Type == tt && ok(tr.ID) {
			return tr, true
		}
	}
	return payload.Transform{}, false
}

// SelectIKESuite examines a peer's IKE SA payload and returns the first
// proposal we can fully satisfy, along with the resolved Suite and the
// accepted proposal (to echo back). needDH controls whether a DH group is
// required (true for IKE_SA_INIT).
func SelectIKESuite(sa payload.SAPayload) (Suite, payload.Proposal, error) {
	for _, p := range sa.Proposals {
		if p.Protocol != payload.ProtoIKE {
			continue
		}
		encr, ok := chosenTransform(p, payload.TransformENCR, supportedENCR)
		if !ok {
			continue
		}
		prf, ok := chosenTransform(p, payload.TransformPRF, supportedPRF)
		if !ok {
			continue
		}
		dh, ok := chosenTransform(p, payload.TransformDH, supportedDH)
		if !ok {
			continue
		}
		var integ payload.Transform
		if !isAEAD(encr.ID) {
			integ, ok = chosenTransform(p, payload.TransformINTEG, supportedInteg)
			if !ok {
				continue
			}
		}
		suite, err := buildSuite(encr, prf, integ, dh)
		if err != nil {
			continue
		}
		accepted := payload.Proposal{
			Num:      p.Num,
			Protocol: payload.ProtoIKE,
			Transforms: []payload.Transform{
				{Type: payload.TransformENCR, ID: encr.ID, KeyLen: encr.KeyLen},
				{Type: payload.TransformPRF, ID: prf.ID},
			},
		}
		if !isAEAD(encr.ID) {
			accepted.Transforms = append(accepted.Transforms,
				payload.Transform{Type: payload.TransformINTEG, ID: integ.ID})
		}
		accepted.Transforms = append(accepted.Transforms,
			payload.Transform{Type: payload.TransformDH, ID: dh.ID})
		return suite, accepted, nil
	}
	return Suite{}, payload.Proposal{}, fmt.Errorf("ike: no acceptable IKE proposal")
}

func buildSuite(encr, prf, integ, dh payload.Transform) (Suite, error) {
	c, err := transform.Cipher(encr.ID, int(encr.KeyLen))
	if err != nil {
		return Suite{}, err
	}
	pf, err := transform.PRF(prf.ID)
	if err != nil {
		return Suite{}, err
	}
	s := Suite{
		EncrID: encr.ID, EncrKeyLn: encr.KeyLen, PRFID: prf.ID, DHID: dh.ID,
		Cipher: c, PRF: pf,
	}
	if !isAEAD(encr.ID) {
		ig, err := transform.Integrity(integ.ID)
		if err != nil {
			return Suite{}, err
		}
		s.IntegID = integ.ID
		s.Integ = ig
	}
	return s, nil
}

// encKeyLen returns the per-direction encryption key length in bytes.
func (s *Suite) encKeyLen() int { return s.Cipher.KeyLen() }

// integKeyLen returns the per-direction integrity key length in bytes (0 for AEAD).
func (s *Suite) integKeyLen() int {
	if s.Integ == nil {
		return 0
	}
	return s.Integ.KeyLen
}

// ESPSuite is the resolved Child SA cipher suite (encryption + optional integ).
type ESPSuite struct {
	EncrID    uint16
	EncrKeyLn uint16
	IntegID   uint16
	Cipher    cryptoutil.SKCipher
	Integ     *cryptoutil.Integrity
}

// SelectESPSuite picks the first acceptable ESP proposal from the peer.
func SelectESPSuite(sa payload.SAPayload) (ESPSuite, payload.Proposal, error) {
	for _, p := range sa.Proposals {
		if p.Protocol != payload.ProtoESP {
			continue
		}
		encr, ok := chosenTransform(p, payload.TransformENCR, supportedENCR)
		if !ok {
			continue
		}
		var integ payload.Transform
		if !isAEAD(encr.ID) {
			integ, ok = chosenTransform(p, payload.TransformINTEG, supportedInteg)
			if !ok {
				continue
			}
		}
		c, err := transform.Cipher(encr.ID, int(encr.KeyLen))
		if err != nil {
			continue
		}
		es := ESPSuite{EncrID: encr.ID, EncrKeyLn: encr.KeyLen, Cipher: c}
		accepted := payload.Proposal{
			Num:      p.Num,
			Protocol: payload.ProtoESP,
			SPI:      p.SPI,
			Transforms: []payload.Transform{
				{Type: payload.TransformENCR, ID: encr.ID, KeyLen: encr.KeyLen},
			},
		}
		if !isAEAD(encr.ID) {
			ig, err := transform.Integrity(integ.ID)
			if err != nil {
				continue
			}
			es.IntegID = integ.ID
			es.Integ = ig
			accepted.Transforms = append(accepted.Transforms,
				payload.Transform{Type: payload.TransformINTEG, ID: integ.ID})
		}
		accepted.Transforms = append(accepted.Transforms,
			payload.Transform{Type: payload.TransformESN, ID: payload.ESN_NONE})
		return es, accepted, nil
	}
	return ESPSuite{}, payload.Proposal{}, fmt.Errorf("ike: no acceptable ESP proposal")
}
