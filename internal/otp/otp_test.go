package otp

import (
	"testing"
	"time"
)

// The RFC 4226 Appendix D reference secret, as ASCII.
var rfc4226Secret = []byte("12345678901234567890")

// TestHOTPRFC4226 pins the implementation to the RFC's own table. These are the
// values every authenticator agrees on, so a drift here is a drift from the
// world, not merely from a previous version of this code.
func TestHOTPRFC4226(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for counter, code := range want {
		got, err := HOTP(rfc4226Secret, uint64(counter), Config{})
		if err != nil {
			t.Fatalf("counter %d: %v", counter, err)
		}
		if got != code {
			t.Errorf("HOTP(counter=%d) = %s, want %s", counter, got, code)
		}
	}
}

// TestTOTPRFC6238 pins the time-based construction, including the three hash
// algorithms. RFC 6238's table uses 8-digit codes and a secret per algorithm,
// each being the SHA1 secret repeated up to the hash's block size.
func TestTOTPRFC6238(t *testing.T) {
	seed := func(n int) []byte {
		out := make([]byte, 0, n)
		for len(out) < n {
			out = append(out, rfc4226Secret...)
		}
		return out[:n]
	}
	cases := []struct {
		unix int64
		alg  Algorithm
		want string
	}{
		{59, SHA1, "94287082"},
		{59, SHA256, "46119246"},
		{59, SHA512, "90693936"},
		{1111111109, SHA1, "07081804"},
		{1111111111, SHA1, "14050471"},
		{1234567890, SHA1, "89005924"},
		{2000000000, SHA1, "69279037"},
		{20000000000, SHA1, "65353130"},
		{1111111109, SHA256, "68084774"},
		{20000000000, SHA512, "47863826"},
	}
	for _, c := range cases {
		secret := rfc4226Secret
		switch c.alg {
		case SHA256:
			secret = seed(32)
		case SHA512:
			secret = seed(64)
		}
		got, err := TOTP(secret, time.Unix(c.unix, 0), Config{Algorithm: c.alg, Digits: 8})
		if err != nil {
			t.Fatalf("T=%d %s: %v", c.unix, c.alg, err)
		}
		if got != c.want {
			t.Errorf("TOTP(T=%d, %s) = %s, want %s", c.unix, c.alg, got, c.want)
		}
	}
}

// A verifier must accept the neighbouring steps, because the user's phone and
// the gateway never agree on the time to the second.
func TestVerifyAcceptsDrift(t *testing.T) {
	now := time.Unix(1111111111, 0)
	for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code, err := TOTP(rfc4226Secret, now.Add(offset), Config{})
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(rfc4226Secret, code, now, Config{}) {
			t.Errorf("a code generated %s from now was rejected", offset)
		}
	}
	// Two steps out is beyond the default allowance and must not be accepted:
	// the window is a concession to clock drift, not an open door.
	code, err := TOTP(rfc4226Secret, now.Add(90*time.Second), Config{})
	if err != nil {
		t.Fatal(err)
	}
	if Verify(rfc4226Secret, code, now, Config{}) {
		t.Error("a code three steps in the future was accepted")
	}
}

func TestVerifyRejects(t *testing.T) {
	now := time.Unix(1111111111, 0)
	for _, code := range []string{"", "   ", "000000", "94287082", "not-a-code", "07081804x"} {
		if Verify(rfc4226Secret, code, now, Config{}) {
			t.Errorf("Verify accepted %q", code)
		}
	}
	// The right code for the wrong secret must fail.
	code, err := TOTP(rfc4226Secret, now, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if Verify([]byte("09876543210987654321"), code, now, Config{}) {
		t.Error("Verify accepted a code generated under a different secret")
	}
}

func TestDecodeSecret(t *testing.T) {
	// The same key, written the several ways a user might paste it.
	for _, s := range []string{
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		"gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
		"GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",
	} {
		key, err := DecodeSecret(s)
		if err != nil {
			t.Fatalf("DecodeSecret(%q): %v", s, err)
		}
		if string(key) != string(rfc4226Secret) {
			t.Errorf("DecodeSecret(%q) = %q, want %q", s, key, rfc4226Secret)
		}
	}
	for _, s := range []string{"", "not base32!", "1234"} {
		if _, err := DecodeSecret(s); err == nil {
			t.Errorf("DecodeSecret accepted %q", s)
		}
	}
}

func TestHOTPRejectsBadDigits(t *testing.T) {
	for _, d := range []int{-1, 9, 100} {
		if _, err := HOTP(rfc4226Secret, 0, Config{Digits: d}); err == nil {
			t.Errorf("HOTP accepted %d digits", d)
		}
	}
}
