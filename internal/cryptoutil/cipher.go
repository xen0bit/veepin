package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
)

// SKCipher protects the encrypted (SK) payload. It handles both AEAD ciphers
// (AES-GCM, ChaCha20-Poly1305) and the classic encrypt-then-MAC construction
// (AES-CBC + HMAC). The interface abstracts over both so the message layer is
// agnostic to which suite was negotiated.
//
// Layout of the SK payload body (RFC 7296 section 3.14):
//
//	[ IV | ciphertext(padded) | ICV ]
//
// For AEAD, IV is the explicit nonce portion and ICV is the auth tag. The AAD
// covers the IKE header and all preceding payload headers up to and including
// the SK generic header.
type SKCipher interface {
	// KeyLen is the encryption key length in bytes.
	KeyLen() int
	// IVLen is the length of the per-message IV/nonce written on the wire.
	IVLen() int
	// ICVLen is the length of the integrity tag/MAC appended after ciphertext.
	ICVLen() int
	// BlockLen is the cipher block size for padding; 1 for stream/AEAD.
	BlockLen() int
	// AEAD reports whether integrity is provided by the cipher itself.
	AEAD() bool

	// Seal encrypts plaintext and returns iv||ciphertext||icv. aad is the
	// authenticated-but-not-encrypted prefix (IKE header .. SK header).
	Seal(encKey, integKey, aad, plaintext []byte) ([]byte, error)
	// Open verifies and decrypts. For non-AEAD, integ is checked over
	// aad||iv||ciphertext before decryption (encrypt-then-MAC).
	Open(encKey, integKey, aad, ivCtIcv []byte) (plaintext []byte, err error)
}

// SKParams bundles a negotiated cipher and (for non-AEAD) integrity transform.
type SKParams struct {
	Cipher SKCipher
	Integ  *Integrity // nil for AEAD
}

// aesKeyLen validates an AES key length in bits, mapping 0 to the 256-bit
// default, and returns it in bytes.
func aesKeyLen(keyBits int) (int, error) {
	kl := keyBits / 8
	if kl == 0 {
		kl = 32
	}
	if kl != 16 && kl != 24 && kl != 32 {
		return 0, fmt.Errorf("cryptoutil: bad AES key length %d bits", keyBits)
	}
	return kl, nil
}

// NewAESGCMSKCipher returns an AES-GCM-16 SK cipher (RFC 5282) for the given
// key length in bits; 0 selects AES-256.
func NewAESGCMSKCipher(keyBits int) (SKCipher, error) {
	kl, err := aesKeyLen(keyBits)
	if err != nil {
		return nil, err
	}
	return &gcmCipher{keyLen: kl}, nil
}

// NewAESCBCSKCipher returns an AES-CBC SK cipher for the given key length in
// bits; 0 selects AES-256. Integrity is supplied separately by an Integrity
// transform, and callers must route Seal/Open through SealETM/OpenETM.
func NewAESCBCSKCipher(keyBits int) (SKCipher, error) {
	kl, err := aesKeyLen(keyBits)
	if err != nil {
		return nil, err
	}
	return &cbcCipher{keyLen: kl}, nil
}

// --- AES-GCM (RFC 5282) ---

type gcmCipher struct{ keyLen int }

func (c *gcmCipher) KeyLen() int   { return c.keyLen + 4 } // + 4-octet salt
func (c *gcmCipher) IVLen() int    { return 8 }            // explicit nonce
func (c *gcmCipher) ICVLen() int   { return 16 }
func (c *gcmCipher) BlockLen() int { return 1 }
func (c *gcmCipher) AEAD() bool    { return true }

func (c *gcmCipher) aead(key []byte) (cipher.AEAD, []byte, error) {
	// The last 4 octets of the SK_e material are the salt (RFC 5282 4).
	salt := key[len(key)-4:]
	block, err := aes.NewCipher(key[:c.keyLen])
	if err != nil {
		return nil, nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return a, salt, nil
}

func (c *gcmCipher) Seal(encKey, _ /*integ*/, aad, plaintext []byte) ([]byte, error) {
	a, salt, err := c.aead(encKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, c.IVLen())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	nonce := append(append([]byte(nil), salt...), iv...)
	ct := a.Seal(nil, nonce, plaintext, aad)
	out := append(append([]byte(nil), iv...), ct...)
	return out, nil
}

func (c *gcmCipher) Open(encKey, _ /*integ*/, aad, ivCtIcv []byte) ([]byte, error) {
	if len(ivCtIcv) < c.IVLen()+c.ICVLen() {
		return nil, fmt.Errorf("cryptoutil: GCM payload too short")
	}
	a, salt, err := c.aead(encKey)
	if err != nil {
		return nil, err
	}
	iv := ivCtIcv[:c.IVLen()]
	ct := ivCtIcv[c.IVLen():]
	nonce := append(append([]byte(nil), salt...), iv...)
	return a.Open(nil, nonce, ct, aad)
}

// --- AES-CBC + HMAC (encrypt-then-MAC) ---

type cbcCipher struct{ keyLen int }

func (c *cbcCipher) KeyLen() int   { return c.keyLen }
func (c *cbcCipher) IVLen() int    { return aes.BlockSize }
func (c *cbcCipher) ICVLen() int   { return 0 } // provided by the Integrity transform
func (c *cbcCipher) BlockLen() int { return aes.BlockSize }
func (c *cbcCipher) AEAD() bool    { return false }

// cbcInteg is set by the message layer via SealCBC/OpenCBC helpers below; to
// keep the SKCipher interface uniform we thread the integrity MAC through the
// integKey argument and a package-level helper. For CBC, Seal/Open expect the
// integ transform to be supplied out-of-band through SKParams, so these two
// methods panic if called directly; the message layer always routes CBC via
// SealETM/OpenETM.
func (c *cbcCipher) Seal(encKey, integKey, aad, plaintext []byte) ([]byte, error) {
	return nil, fmt.Errorf("cryptoutil: CBC requires SealETM")
}

func (c *cbcCipher) Open(encKey, integKey, aad, ivCtIcv []byte) ([]byte, error) {
	return nil, fmt.Errorf("cryptoutil: CBC requires OpenETM")
}

// SealETM performs AES-CBC encrypt-then-MAC. It returns iv||ciphertext||icv.
// The plaintext MUST already be padded to a multiple of the block size by the
// caller (the SK and ESP layers own their respective padding schemes).
func (c *cbcCipher) SealETM(encKey, integKey, aad, plaintext []byte, integ *Integrity) ([]byte, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("cryptoutil: CBC plaintext not block-aligned (%d)", len(plaintext))
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	padded := plaintext
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	// MAC covers aad || iv || ciphertext.
	macInput := make([]byte, 0, len(aad)+len(iv)+len(ct))
	macInput = append(macInput, aad...)
	macInput = append(macInput, iv...)
	macInput = append(macInput, ct...)
	icv := integ.Sum(integKey, macInput)
	out := append(append(append([]byte(nil), iv...), ct...), icv...)
	return out, nil
}

// OpenETM verifies then decrypts an AES-CBC encrypt-then-MAC SK body.
func (c *cbcCipher) OpenETM(encKey, integKey, aad, ivCtIcv []byte, integ *Integrity) ([]byte, error) {
	if len(ivCtIcv) < aes.BlockSize+integ.ICVLen {
		return nil, fmt.Errorf("cryptoutil: CBC payload too short")
	}
	icv := ivCtIcv[len(ivCtIcv)-integ.ICVLen:]
	rest := ivCtIcv[:len(ivCtIcv)-integ.ICVLen]
	// Verify MAC before touching the ciphertext.
	macInput := make([]byte, 0, len(aad)+len(rest))
	macInput = append(macInput, aad...)
	macInput = append(macInput, rest...)
	want := integ.Sum(integKey, macInput)
	if subtle.ConstantTimeCompare(want, icv) != 1 {
		return nil, fmt.Errorf("cryptoutil: SK integrity check failed")
	}
	iv := rest[:aes.BlockSize]
	ct := rest[aes.BlockSize:]
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("cryptoutil: CBC ciphertext not block-aligned")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	// The caller strips its own padding scheme (RFC 7296 for SK, RFC 4303 for
	// ESP); return the raw block-aligned plaintext.
	return pt, nil
}

// ensure hmac import is used even if only AEAD ciphers are exercised.
var _ = hmac.New
