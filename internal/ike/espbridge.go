package ike

import (
	"fmt"

	"github.com/example/ikev2-go/internal/crypto"
	"github.com/example/ikev2-go/internal/esp"
)

// BuildESPSA converts a negotiated Child SA into a userspace esp.SA, wiring the
// directional keys and cipher/integrity transforms into the ESP data path.
//
// The returned SA uses the Child SA's inbound SPI to open received packets and
// its outbound SPI to protect sent packets, mirroring the key directions
// assigned during negotiation.
func BuildESPSA(child *ChildSA) (*esp.SA, error) {
	if child.Suite.Cipher == nil {
		return nil, fmt.Errorf("ike: child SA has no cipher")
	}

	// Fresh cipher instances (the negotiated Suite.Cipher captured key length
	// but AEAD/CBC state is keyed per call, so we can reuse the same value).
	outCipher, err := crypto.NewSKCipher(child.Suite.EncrID, int(child.Suite.EncrKeyLn))
	if err != nil {
		return nil, err
	}
	inCipher, err := crypto.NewSKCipher(child.Suite.EncrID, int(child.Suite.EncrKeyLn))
	if err != nil {
		return nil, err
	}

	var outInteg, inInteg *crypto.Integrity
	if child.Suite.Integ != nil {
		if outInteg, err = crypto.NewIntegrity(child.Suite.IntegID); err != nil {
			return nil, err
		}
		if inInteg, err = crypto.NewIntegrity(child.Suite.IntegID); err != nil {
			return nil, err
		}
	}

	return &esp.SA{
		SPIOut: child.OutboundSPI,
		SPIIn:  child.InboundSPI,
		Out: esp.Transform{
			Cipher:   outCipher,
			Integ:    outInteg,
			EncKey:   child.EncrOut,
			IntegKey: child.IntegOut,
		},
		In: esp.Transform{
			Cipher:   inCipher,
			Integ:    inInteg,
			EncKey:   child.EncrIn,
			IntegKey: child.IntegIn,
		},
	}, nil
}
