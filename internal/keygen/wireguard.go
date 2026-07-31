package keygen

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// genWireGuardKeypair generates a Curve25519 keypair and returns the private key
// as a base64-encoded string, matching WireGuard's key format.
func genWireGuardKeypair() (map[string]string, error) {
	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("keygen: wireguard: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	return map[string]string{
		"private-key": base64.StdEncoding.EncodeToString(priv[:]),
	}, nil
}
