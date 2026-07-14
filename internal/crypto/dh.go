// Package crypto implements the IKEv2 cryptographic primitives: Diffie-Hellman
// groups, the negotiated PRF, PRF+ key expansion, key derivation and the SK
// payload cipher suites.
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/example/ikev2-go/internal/payload"
)

// DHGroup abstracts a Diffie-Hellman group: generate an ephemeral key, expose
// the public value in IKEv2 wire form, and compute a shared secret.
type DHGroup interface {
	ID() uint16
	// Generate returns the public key bytes (wire form) for a fresh private key.
	Generate() (pub []byte, err error)
	// ComputeSecret takes the peer public key bytes and returns the shared secret.
	ComputeSecret(peerPub []byte) ([]byte, error)
}

// NewDHGroup returns an implementation for the given IANA group ID.
func NewDHGroup(id uint16) (DHGroup, error) {
	switch id {
	case payload.DH_CURVE25519:
		return &ecdhGroup{id: id, curve: ecdh.X25519()}, nil
	case payload.DH_ECP_256:
		return &ecdhGroup{id: id, curve: ecdh.P256()}, nil
	case payload.DH_ECP_384:
		return &ecdhGroup{id: id, curve: ecdh.P384()}, nil
	case payload.DH_ECP_521:
		return &ecdhGroup{id: id, curve: ecdh.P521()}, nil
	case payload.DH_MODP_2048:
		return &modpGroup{id: id, prime: modp2048Prime, g: big.NewInt(2), size: 256}, nil
	default:
		return nil, fmt.Errorf("crypto: unsupported DH group %d", id)
	}
}

// --- ECDH-based groups (X25519 and the NIST curves) ---

type ecdhGroup struct {
	id    uint16
	curve ecdh.Curve
	priv  *ecdh.PrivateKey
}

func (g *ecdhGroup) ID() uint16 { return g.id }

func (g *ecdhGroup) Generate() ([]byte, error) {
	priv, err := g.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	g.priv = priv
	pub := priv.PublicKey().Bytes()
	// For the NIST curves, crypto/ecdh emits an uncompressed point with a
	// leading 0x04. IKEv2 (RFC 5903) transmits only X||Y, so strip the prefix.
	if g.id == payload.DH_ECP_256 || g.id == payload.DH_ECP_384 || g.id == payload.DH_ECP_521 {
		if len(pub) > 0 && pub[0] == 0x04 {
			pub = pub[1:]
		}
	}
	return pub, nil
}

func (g *ecdhGroup) ComputeSecret(peerPub []byte) ([]byte, error) {
	if g.priv == nil {
		return nil, fmt.Errorf("crypto: DH private key not generated")
	}
	wire := peerPub
	if g.id == payload.DH_ECP_256 || g.id == payload.DH_ECP_384 || g.id == payload.DH_ECP_521 {
		// Re-add the uncompressed-point prefix crypto/ecdh expects.
		wire = append([]byte{0x04}, peerPub...)
	}
	pub, err := g.curve.NewPublicKey(wire)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid peer public key: %w", err)
	}
	return g.priv.ECDH(pub)
}

// --- MODP group (classic finite-field DH, RFC 3526) ---

type modpGroup struct {
	id    uint16
	prime *big.Int
	g     *big.Int
	size  int // shared-secret byte length (prime size)
	priv  *big.Int
}

func (m *modpGroup) ID() uint16 { return m.id }

func (m *modpGroup) Generate() ([]byte, error) {
	// Private exponent: a random value in [2, prime-2]. 320 bits of entropy is
	// comfortably above the security level of MODP-2048.
	priv, err := rand.Int(rand.Reader, new(big.Int).Sub(m.prime, big.NewInt(2)))
	if err != nil {
		return nil, err
	}
	priv.Add(priv, big.NewInt(2))
	m.priv = priv
	pub := new(big.Int).Exp(m.g, priv, m.prime)
	return leftPad(pub.Bytes(), m.size), nil
}

func (m *modpGroup) ComputeSecret(peerPub []byte) ([]byte, error) {
	if m.priv == nil {
		return nil, fmt.Errorf("crypto: DH private key not generated")
	}
	peer := new(big.Int).SetBytes(peerPub)
	// Reject degenerate public values (1, p-1, >=p) that force a weak secret.
	if peer.Cmp(big.NewInt(1)) <= 0 || peer.Cmp(new(big.Int).Sub(m.prime, big.NewInt(1))) >= 0 {
		return nil, fmt.Errorf("crypto: invalid MODP peer public value")
	}
	secret := new(big.Int).Exp(peer, m.priv, m.prime)
	return leftPad(secret.Bytes(), m.size), nil
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
