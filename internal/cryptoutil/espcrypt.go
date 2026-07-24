package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"hash"
)

// ESPCrypter is an allocation-conscious cipher for the ESP data path. Unlike
// SKCipher (which rebuilds its cipher state on every call for handshake use),
// an ESPCrypter prepares its keyed cipher once and then seals/opens packets
// appending into a caller-supplied buffer, so the per-packet hot path performs
// no cipher construction and minimal allocation.
//
// A single ESPCrypter is intended to be driven by one goroutine at a time (one
// per SA direction), matching the userspace data-plane pump, which uses
// separate crypters for the inbound and outbound directions. It is not safe for
// concurrent use.
type ESPCrypter interface {
	// Overhead returns the number of octets Seal adds beyond the plaintext
	// (IV + ICV for AEAD; IV + MAC for CBC-ETM). Callers use it to size buffers.
	Overhead() int
	// BlockLen is the cipher block size for ESP trailer padding (1 for AEAD).
	BlockLen() int
	// Seal appends iv||ciphertext||icv for plaintext (authenticating aad) to
	// dst and returns the extended slice. aad is not encrypted.
	Seal(dst, aad, plaintext []byte) ([]byte, error)
	// Open verifies and decrypts ivCtIcv (authenticating aad), appending the
	// recovered plaintext to dst and returning the extended slice.
	Open(dst, aad, ivCtIcv []byte) ([]byte, error)
}

// NewAESGCMESPCrypter builds a prepared AES-GCM-16 ESP crypter. keyBits is the
// AES key length (0 selects AES-256); encKey is the ESP encryption key followed
// by its 4-octet GCM salt (RFC 4106).
func NewAESGCMESPCrypter(keyBits int, encKey []byte) (ESPCrypter, error) {
	kl, err := aesKeyLen(keyBits)
	if err != nil {
		return nil, err
	}
	if len(encKey) < kl+4 {
		return nil, fmt.Errorf("cryptoutil: GCM key too short (%d, need %d)", len(encKey), kl+4)
	}
	block, err := aes.NewCipher(encKey[:kl])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return newESPAEAD(aead, encKey[kl:kl+4]), nil
}

// NewChaCha20Poly1305ESPCrypter builds a prepared ChaCha20-Poly1305 ESP crypter
// (RFC 7634). encKey is the 32-octet key followed by its 4-octet salt; the wire
// framing (8-octet IV, 16-octet tag, salt||IV nonce) matches AES-GCM-16, so it
// reuses the same prepared-AEAD crypter.
func NewChaCha20Poly1305ESPCrypter(encKey []byte) (ESPCrypter, error) {
	const kl = ChaCha20Poly1305KeySize
	if len(encKey) < kl+4 {
		return nil, fmt.Errorf("cryptoutil: ChaCha20 key too short (%d, need %d)", len(encKey), kl+4)
	}
	aead, err := NewChaCha20Poly1305(encKey[:kl])
	if err != nil {
		return nil, err
	}
	return newESPAEAD(aead, encKey[kl:kl+4]), nil
}

// NewAESCBCESPCrypter builds a prepared AES-CBC + HMAC (encrypt-then-MAC) ESP
// crypter. keyBits is the AES key length (0 selects AES-256); integ and integKey
// supply the MAC.
func NewAESCBCESPCrypter(keyBits int, encKey []byte, integ *Integrity, integKey []byte) (ESPCrypter, error) {
	kl, err := aesKeyLen(keyBits)
	if err != nil {
		return nil, err
	}
	if len(encKey) < kl {
		return nil, fmt.Errorf("cryptoutil: CBC key too short")
	}
	if integ == nil {
		return nil, fmt.Errorf("cryptoutil: CBC ESP requires an integrity transform")
	}
	block, err := aes.NewCipher(encKey[:kl])
	if err != nil {
		return nil, err
	}
	return &espCBC{block: block, integ: integ, integKey: integKey, mac: integ.newMAC(integKey)}, nil
}

// --- Generic AEAD ESP crypter (AES-GCM, ChaCha20-Poly1305) ---

// espAEAD is the prepared data-path crypter for any AEAD framed like AES-GCM-16
// (RFC 4106) or ChaCha20-Poly1305 (RFC 7634): a 4-octet implicit salt, an
// 8-octet explicit IV on the wire, and a 16-octet tag. It holds the keyed AEAD
// built once, so the per-packet path constructs nothing.
type espAEAD struct {
	aead  cipher.AEAD
	salt  [4]byte
	nonce []byte // reused 12-octet nonce buffer (single-goroutine per direction)
}

func newESPAEAD(aead cipher.AEAD, salt []byte) *espAEAD {
	g := &espAEAD{aead: aead}
	copy(g.salt[:], salt)
	return g
}

func (g *espAEAD) Overhead() int { return 8 + 16 } // explicit IV + tag
func (g *espAEAD) BlockLen() int { return 1 }

func (g *espAEAD) Seal(dst, aad, plaintext []byte) ([]byte, error) {
	// nonce = salt(4) || explicit-iv(8). A reused heap buffer avoids the escape
	// that passing a stack array through the AEAD interface would cause.
	if g.nonce == nil {
		g.nonce = make([]byte, 12)
		copy(g.nonce[0:4], g.salt[:])
	}
	if _, err := rand.Read(g.nonce[4:12]); err != nil {
		return nil, err
	}
	// Write the explicit IV first, then seal appending the ciphertext+tag
	// directly after it in dst.
	dst = append(dst, g.nonce[4:12]...)
	dst = g.aead.Seal(dst, g.nonce, plaintext, aad)
	return dst, nil
}

func (g *espAEAD) Open(dst, aad, ivCtIcv []byte) ([]byte, error) {
	if len(ivCtIcv) < 8+16 {
		return nil, fmt.Errorf("cryptoutil: AEAD payload too short")
	}
	if g.nonce == nil {
		g.nonce = make([]byte, 12)
		copy(g.nonce[0:4], g.salt[:])
	}
	copy(g.nonce[4:12], ivCtIcv[:8])
	return g.aead.Open(dst, g.nonce, ivCtIcv[8:], aad)
}

// --- AES-CBC + HMAC ESP crypter (encrypt-then-MAC) ---

type espCBC struct {
	block    cipher.Block
	integ    *Integrity
	integKey []byte
	mac      hash.Hash // reused across calls (single-goroutine data path)
}

func (c *espCBC) Overhead() int { return aes.BlockSize + c.integ.ICVLen }
func (c *espCBC) BlockLen() int { return aes.BlockSize }

func (c *espCBC) Seal(dst, aad, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("cryptoutil: CBC plaintext not block-aligned (%d)", len(plaintext))
	}
	start := len(dst)
	// Reserve IV + ciphertext region, then fill.
	dst = append(dst, make([]byte, aes.BlockSize+len(plaintext))...)
	iv := dst[start : start+aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct := dst[start+aes.BlockSize:]
	cipher.NewCBCEncrypter(c.block, iv).CryptBlocks(ct, plaintext)
	// MAC covers aad || iv || ciphertext; append the truncated ICV.
	c.mac.Reset()
	c.mac.Write(aad)
	c.mac.Write(dst[start:]) // iv || ct
	var macBuf [64]byte
	icv := c.mac.Sum(macBuf[:0])[:c.integ.ICVLen]
	dst = append(dst, icv...)
	return dst, nil
}

func (c *espCBC) Open(dst, aad, ivCtIcv []byte) ([]byte, error) {
	if len(ivCtIcv) < aes.BlockSize+c.integ.ICVLen {
		return nil, fmt.Errorf("cryptoutil: CBC payload too short")
	}
	icv := ivCtIcv[len(ivCtIcv)-c.integ.ICVLen:]
	rest := ivCtIcv[:len(ivCtIcv)-c.integ.ICVLen]
	c.mac.Reset()
	c.mac.Write(aad)
	c.mac.Write(rest)
	var macBuf [64]byte
	want := c.mac.Sum(macBuf[:0])[:c.integ.ICVLen]
	if subtle.ConstantTimeCompare(want, icv) != 1 {
		return nil, fmt.Errorf("cryptoutil: ESP integrity check failed")
	}
	iv := rest[:aes.BlockSize]
	ct := rest[aes.BlockSize:]
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("cryptoutil: CBC ciphertext not block-aligned")
	}
	start := len(dst)
	dst = append(dst, make([]byte, len(ct))...)
	cipher.NewCBCDecrypter(c.block, iv).CryptBlocks(dst[start:], ct)
	return dst, nil
}
