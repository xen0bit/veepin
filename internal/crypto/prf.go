package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/example/ikev2-go/internal/payload"
)

// PRF is a keyed pseudorandom function (RFC 7296 section 2.13).
type PRF struct {
	id     uint16
	newMAC func(key []byte) hash.Hash
	Size   int // output length in bytes
	// PreferredKeyLen is the key length used when the PRF key is variable and
	// we are choosing one (equal to the output size for HMAC PRFs).
	PreferredKeyLen int
}

// NewPRF returns the PRF for the given IANA transform ID.
func NewPRF(id uint16) (*PRF, error) {
	switch id {
	case payload.PRF_HMAC_SHA1:
		return &PRF{id, func(k []byte) hash.Hash { return hmac.New(sha1.New, k) }, 20, 20}, nil
	case payload.PRF_HMAC_SHA2_256:
		return &PRF{id, func(k []byte) hash.Hash { return hmac.New(sha256.New, k) }, 32, 32}, nil
	case payload.PRF_HMAC_SHA2_384:
		return &PRF{id, func(k []byte) hash.Hash { return hmac.New(sha512.New384, k) }, 48, 48}, nil
	case payload.PRF_HMAC_SHA2_512:
		return &PRF{id, func(k []byte) hash.Hash { return hmac.New(sha512.New, k) }, 64, 64}, nil
	default:
		return nil, fmt.Errorf("crypto: unsupported PRF %d", id)
	}
}

// ID returns the transform ID.
func (p *PRF) ID() uint16 { return p.id }

// Apply computes prf(key, data).
func (p *PRF) Apply(key, data []byte) []byte {
	m := p.newMAC(key)
	m.Write(data)
	return m.Sum(nil)
}

// Plus implements prf+ (RFC 7296 section 2.13):
//
//	prf+(K,S) = T1 | T2 | T3 | ...
//	T1 = prf(K, S | 0x01)
//	Tn = prf(K, Tn-1 | S | n)
//
// It returns exactly n bytes.
func (p *PRF) Plus(key, seed []byte, n int) []byte {
	out := make([]byte, 0, n)
	mac := p.newMAC(key) // reused across iterations via Reset
	var prev []byte
	var cb [1]byte
	var sumBuf [64]byte // large enough for any supported PRF output
	for counter := byte(1); len(out) < n; counter++ {
		mac.Reset()
		mac.Write(prev)
		mac.Write(seed)
		cb[0] = counter
		mac.Write(cb[:])
		prev = mac.Sum(sumBuf[:0])
		out = append(out, prev...)
	}
	return out[:n]
}

// Integrity is a MAC transform used by non-AEAD SK ciphers (RFC 7296 2.14).
type Integrity struct {
	id     uint16
	newMAC func(key []byte) hash.Hash
	KeyLen int // key length in bytes
	ICVLen int // truncated output length in bytes
}

// NewIntegrity returns the integrity transform for the given IANA ID.
func NewIntegrity(id uint16) (*Integrity, error) {
	switch id {
	case payload.AUTH_HMAC_SHA1_96:
		return &Integrity{id, func(k []byte) hash.Hash { return hmac.New(sha1.New, k) }, 20, 12}, nil
	case payload.AUTH_HMAC_SHA2_256_128:
		return &Integrity{id, func(k []byte) hash.Hash { return hmac.New(sha256.New, k) }, 32, 16}, nil
	case payload.AUTH_HMAC_SHA2_384_192:
		return &Integrity{id, func(k []byte) hash.Hash { return hmac.New(sha512.New384, k) }, 48, 24}, nil
	case payload.AUTH_HMAC_SHA2_512_256:
		return &Integrity{id, func(k []byte) hash.Hash { return hmac.New(sha512.New, k) }, 64, 32}, nil
	default:
		return nil, fmt.Errorf("crypto: unsupported integrity %d", id)
	}
}

// ID returns the transform ID.
func (i *Integrity) ID() uint16 { return i.id }

// Sum computes the truncated MAC over data.
func (i *Integrity) Sum(key, data []byte) []byte {
	m := i.newMAC(key)
	m.Write(data)
	return m.Sum(nil)[:i.ICVLen]
}
