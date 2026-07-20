package fortinet

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/otp"
)

// The shared secret these tests authenticate with, base32 as a user would paste
// it out of an authenticator app.
const testTOTPSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// twoFactorServer starts a gateway that demands a second factor from alice.
func twoFactorServer(t *testing.T) (base string, srv *Server) {
	t.Helper()
	pool, gateway, err := newTestPool()
	if err != nil {
		t.Fatal(err)
	}
	srv, err = NewServer(ServerConfig{
		Users:       map[string]string{"alice": "s3cret"},
		Pool:        pool,
		ServerIP:    gateway,
		TOTPSecrets: map[string]string{"alice": testTOTPSecret},
	}, newFakeTUN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ts := httptest.NewTLSServer(srv)
	t.Cleanup(ts.Close)
	return ts.URL, srv
}

func twoFactorClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

// currentCode is what an authenticator app would be showing right now.
func currentCode(t *testing.T) string {
	t.Helper()
	secret, err := otp.DecodeSecret(testTOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	code, err := otp.TOTP(secret, time.Now(), otp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// The whole two-stage login: the password earns a challenge rather than a
// cookie, and the right code turns it into a session.
func TestTwoFactorLogin(t *testing.T) {
	base, _ := twoFactorServer(t)

	var prompted Challenge
	cfg, cookie, err := Login(twoFactorClient(), base, "alice", "s3cret", "",
		func(c Challenge) (string, error) {
			prompted = c
			return currentCode(t), nil
		})
	if err != nil {
		t.Fatalf("Login with a valid second factor: %v", err)
	}
	if cookie == "" {
		t.Error("no SVPNCOOKIE was issued")
	}
	if cfg.AssignedIP == nil {
		t.Error("no address was assigned")
	}
	if prompted.Message == "" {
		t.Error("the challenge carried no prompt for the user")
	}
	if prompted.Echo["reqid"] == "" {
		t.Error("the challenge carried no reqid to echo back")
	}
}

// A wrong code must not produce a session, and must not leave the address it
// would have been given reserved.
func TestTwoFactorRejectsWrongCode(t *testing.T) {
	base, srv := twoFactorServer(t)

	_, _, err := Login(twoFactorClient(), base, "alice", "s3cret", "",
		func(Challenge) (string, error) { return "000000", nil })
	if err == nil {
		t.Fatal("Login succeeded with a wrong token code")
	}
	if !errors.Is(err, ErrAuth) {
		t.Errorf("error = %v, want an ErrAuth", err)
	}
	// Nothing was reserved. Granting a session is the only thing that allocates
	// from the pool, and it always records the result here, so an empty pending
	// map is the proof no address leaked to a login that never completed.
	srv.mu.Lock()
	pending := len(srv.pending)
	outstanding := len(srv.pending2FA)
	srv.mu.Unlock()
	if pending != 0 {
		t.Errorf("%d addresses reserved after a failed second factor, want 0", pending)
	}
	if outstanding != 0 {
		t.Errorf("%d challenges still outstanding after a failed answer, want 0", outstanding)
	}
}

// A password that is wrong must be refused before any challenge is issued: a
// gateway that prompts for a token first would confirm the password to an
// attacker who does not have one.
func TestTwoFactorRejectsWrongPasswordWithoutPrompting(t *testing.T) {
	base, _ := twoFactorServer(t)

	prompted := false
	_, _, err := Login(twoFactorClient(), base, "alice", "wrong", "",
		func(Challenge) (string, error) { prompted = true; return currentCode(t), nil })
	if err == nil {
		t.Fatal("Login succeeded with a wrong password")
	}
	if prompted {
		t.Error("the gateway issued a challenge for a password it should have rejected")
	}
}

// A client with no way to answer must fail cleanly and say why, rather than
// hang or report a wrong password.
func TestTwoFactorWithoutTokenFunc(t *testing.T) {
	base, _ := twoFactorServer(t)

	_, _, err := Login(twoFactorClient(), base, "alice", "s3cret", "", nil)
	if !errors.Is(err, ErrChallenge) {
		t.Fatalf("error = %v, want an ErrChallenge", err)
	}
}

// A challenge is single use: replaying a captured reqid with the right code must
// fail, so a captured exchange cannot be turned into a second session.
func TestTwoFactorChallengeIsSingleUse(t *testing.T) {
	base, srv := twoFactorServer(t)

	var captured Challenge
	if _, _, err := Login(twoFactorClient(), base, "alice", "s3cret", "",
		func(c Challenge) (string, error) { captured = c; return currentCode(t), nil }); err != nil {
		t.Fatalf("first login: %v", err)
	}

	// Replay the same challenge, with a code that is valid right now.
	hc := twoFactorClient()
	resp, err := hc.Post(base+PathLoginCheck, "application/x-www-form-urlencoded",
		strings.NewReader(BuildChallengeForm("alice", currentCode(t), "", captured)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("a replayed challenge was accepted (status %s)", resp.Status)
	}
	srv.mu.Lock()
	n := len(srv.pending)
	srv.mu.Unlock()
	if n != 1 {
		t.Errorf("server has %d pending sessions, want 1 (the replay must not have made another)", n)
	}
}

// A user with no second factor configured still logs in with one stage, so
// enabling 2FA for one account does not disturb the others.
func TestSingleFactorUserUnaffected(t *testing.T) {
	pool, gateway, err := newTestPool()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{
		Users:       map[string]string{"alice": "s3cret", "bob": "hunter2"},
		Pool:        pool,
		ServerIP:    gateway,
		TOTPSecrets: map[string]string{"alice": testTOTPSecret},
	}, newFakeTUN())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()

	// bob has no secret, so his password alone must produce a session -- and the
	// token supplier must never be consulted.
	_, cookie, err := Login(twoFactorClient(), ts.URL, "bob", "hunter2", "",
		func(Challenge) (string, error) {
			t.Error("a user without a second factor was challenged")
			return "", errors.New("unexpected")
		})
	if err != nil {
		t.Fatalf("single-factor login: %v", err)
	}
	if cookie == "" {
		t.Error("no SVPNCOOKIE was issued")
	}
}

// An expired challenge must be refused, so an abandoned login cannot be
// completed later from a captured reqid.
func TestTwoFactorChallengeExpires(t *testing.T) {
	base, srv := twoFactorServer(t)

	var captured Challenge
	_, _, err := Login(twoFactorClient(), base, "alice", "s3cret", "",
		func(c Challenge) (string, error) {
			captured = c
			// Age the challenge past its lifetime before answering it.
			srv.mu.Lock()
			for _, st := range srv.pending2FA {
				st.expires = time.Now().Add(-time.Second)
			}
			srv.mu.Unlock()
			return currentCode(t), nil
		})
	if err == nil {
		t.Fatal("an expired challenge was accepted")
	}
	if captured.Echo["reqid"] == "" {
		t.Fatal("no challenge was issued at all")
	}
}
