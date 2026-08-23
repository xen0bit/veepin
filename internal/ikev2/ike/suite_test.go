package ike

import (
	"testing"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// TestNoProposalOffersAnAEADCipherBesideAnIntegrityTransform is the assertion
// that stops the mixed proposal coming back.
//
// A proposal is one set of transforms from which the peer picks one of each
// type, so a proposal listing AES-GCM, ChaCha20-Poly1305 *and* AES-CBC beside a
// single INTEG transform is claiming something untrue of three of the four:
// RFC 5282 section 8 requires an AEAD cipher's proposal to carry no integrity
// transform, or NONE. strongSwan negotiates with it anyway; libreswan answers
// NO_PROPOSAL_CHOSEN and the tunnel never comes up.
//
// If this fails, the two default proposals have been merged back into one and
// every libreswan cell will stop at IKE_SA_INIT.
func TestNoProposalOffersAnAEADCipherBesideAnIntegrityTransform(t *testing.T) {
	espSPI := []byte{1, 2, 3, 4}
	for name, props := range map[string][]payload.Proposal{
		"IKE": DefaultIKEProposals(),
		"ESP": DefaultESPProposals(espSPI),
	} {
		t.Run(name, func(t *testing.T) {
			if len(props) < 2 {
				t.Fatalf("%s offers %d proposal(s); the AEAD and non-AEAD suites must not share one", name, len(props))
			}
			for _, p := range props {
				var aead, block, integ int
				for _, tr := range p.Transforms {
					switch {
					case tr.Type != payload.TransformENCR && tr.Type != payload.TransformINTEG:
					case tr.Type == payload.TransformINTEG:
						integ++
					case isAEAD(tr.ID):
						aead++
					default:
						block++
					}
				}
				switch {
				case aead > 0 && block > 0:
					t.Errorf("proposal %d mixes %d AEAD and %d block ciphers; a peer cannot tell which the INTEG transforms apply to",
						p.Num, aead, block)
				case aead > 0 && integ > 0:
					t.Errorf("proposal %d offers %d AEAD cipher(s) beside %d integrity transform(s); RFC 5282 §8 forbids it",
						p.Num, aead, integ)
				case block > 0 && integ == 0:
					t.Errorf("proposal %d offers %d block cipher(s) and no integrity transform, which cannot be keyed",
						p.Num, block)
				}
			}
		})
	}
}

// TestEveryDefaultProposalIsNumberedFromOne: RFC 7296 §3.3.1 numbers proposals
// within one SA payload starting at 1 and increasing. A responder that echoes a
// proposal number it was never sent is unmatchable, and a duplicate number makes
// the echo ambiguous.
func TestEveryDefaultProposalIsNumberedFromOne(t *testing.T) {
	for name, props := range map[string][]payload.Proposal{
		"IKE": DefaultIKEProposals(),
		"ESP": DefaultESPProposals([]byte{1, 2, 3, 4}),
	} {
		for i, p := range props {
			if int(p.Num) != i+1 {
				t.Errorf("%s proposal at index %d is numbered %d, want %d", name, i, p.Num, i+1)
			}
		}
	}
}

// TestBothESPProposalsCarryTheSameSPI: the SPI names our inbound SA, not the
// suite. Two proposals with different SPIs would leave the peer sending to one
// of them and us listening on the other, which is a silent black hole rather
// than a handshake failure.
func TestBothESPProposalsCarryTheSameSPI(t *testing.T) {
	props := DefaultESPProposals([]byte{9, 8, 7, 6})
	for _, p := range props {
		if string(p.SPI) != string([]byte{9, 8, 7, 6}) {
			t.Errorf("ESP proposal %d carries SPI %x, want 09080706", p.Num, p.SPI)
		}
	}
}
