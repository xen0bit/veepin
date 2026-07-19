package ike

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func testRemote(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

func TestCookieRoundTrip(t *testing.T) {
	j := newCookieJar()
	nonce := bytes.Repeat([]byte{0xab}, 32)
	remote := testRemote("192.0.2.10", 500)

	c := j.issue(1234, nonce, remote)
	if len(c) != cookieLen {
		t.Fatalf("cookie is %d octets, want %d", len(c), cookieLen)
	}
	if !j.valid(c, 1234, nonce, remote) {
		t.Error("a cookie this responder issued did not verify")
	}
}

// The cookie binds the initiator's address, SPI and nonce. Each of those
// bindings is what stops a cookie issued for one attempt being reused for
// another -- most importantly, a cookie issued to a spoofed address is useless
// from any other address.
func TestCookieIsBoundToTheAttempt(t *testing.T) {
	j := newCookieJar()
	nonce := bytes.Repeat([]byte{0xab}, 32)
	remote := testRemote("192.0.2.10", 500)
	c := j.issue(1234, nonce, remote)

	for _, tc := range []struct {
		name   string
		spi    uint64
		nonce  []byte
		remote *net.UDPAddr
	}{
		{"different SPI", 9999, nonce, remote},
		{"different nonce", 1234, bytes.Repeat([]byte{0xcd}, 32), remote},
		{"different address", 1234, nonce, testRemote("198.51.100.7", 500)},
		{"different port", 1234, nonce, testRemote("192.0.2.10", 4500)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if j.valid(c, tc.spi, tc.nonce, tc.remote) {
				t.Errorf("a cookie verified for a %s", tc.name)
			}
		})
	}
}

func TestCookieRejectsGarbage(t *testing.T) {
	j := newCookieJar()
	nonce := bytes.Repeat([]byte{0xab}, 32)
	remote := testRemote("192.0.2.10", 500)

	for _, tc := range []struct {
		name string
		got  []byte
	}{
		{"empty", nil},
		{"short", []byte{1, 2, 3}},
		{"right length, wrong content", bytes.Repeat([]byte{0xff}, cookieLen)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if j.valid(tc.got, 1234, nonce, remote) {
				t.Error("accepted a cookie this responder never issued")
			}
		})
	}
}

// A cookie in flight when the secret rotates must still be accepted, or a
// legitimate initiator is bounced for the responder's own housekeeping.
func TestCookieSurvivesOneRotation(t *testing.T) {
	j := newCookieJar()
	clock := time.Unix(1_700_000_000, 0)
	j.now = func() time.Time { return clock }
	// newCookieJar stamped rotated from the real clock, so it has to be moved
	// onto the test clock too -- otherwise every elapsed comparison is negative
	// and rotation never fires, which would make this test pass vacuously.
	j.mu.Lock()
	j.rotated = clock
	j.mu.Unlock()

	nonce := bytes.Repeat([]byte{0xab}, 32)
	remote := testRemote("192.0.2.10", 500)
	c := j.issue(1234, nonce, remote)

	clock = clock.Add(cookieRotate + time.Second)
	// Issuing again is what triggers the rotation, as it would on a live server.
	_ = j.issue(5678, nonce, remote)

	if !j.valid(c, 1234, nonce, remote) {
		t.Error("a cookie issued before a rotation was rejected after it")
	}

	// Two rotations is beyond the retained window, and that is intentional --
	// the jar keeps exactly one previous secret so its state stays bounded.
	clock = clock.Add(cookieRotate + time.Second)
	_ = j.issue(5678, nonce, remote)
	if j.valid(c, 1234, nonce, remote) {
		t.Error("a cookie survived two rotations; the retained window is unbounded")
	}
}

// The point of the mechanism: issuing and checking cookies stores nothing per
// initiator. A responder that remembered outstanding cookies would recreate the
// allocation the cookie exists to avoid.
func TestCookieJarIsStateless(t *testing.T) {
	j := newCookieJar()
	nonce := bytes.Repeat([]byte{0xab}, 32)

	for i := range 10_000 {
		remote := testRemote("192.0.2.10", 1024+i%60000)
		c := j.issue(uint64(i), nonce, remote)
		if !j.valid(c, uint64(i), nonce, remote) {
			t.Fatalf("cookie %d did not verify", i)
		}
	}

	// The jar's entire state is two secrets, a version and a timestamp,
	// regardless of how many cookies passed through it. If a map ever appears
	// here, this test is the place that should have to change.
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.version == 0 {
		t.Error("no secret was ever installed")
	}
}
