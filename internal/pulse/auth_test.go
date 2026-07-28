package pulse

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// runAuth drives ClientAuth and ServerAuth against each other over an in-memory
// pipe, which exercises the whole nested exchange without a TLS stack.
func runAuth(t *testing.T, serverUser, serverPass, clientUser, clientPass string) (LoginInfo, error, LoginInfo, error) {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	deadline := time.Now().Add(10 * time.Second)
	_ = c.SetDeadline(deadline)
	_ = s.SetDeadline(deadline)

	type outcome struct {
		info LoginInfo
		err  error
	}
	serverDone := make(chan outcome, 1)
	go func() {
		_, info, err := ServerAuth(s, func(u, p string) bool {
			return u == serverUser && p == serverPass
		})
		serverDone <- outcome{info, err}
	}()

	_, cinfo, cerr := ClientAuth(c, "vpn.example", "/", clientUser, clientPass, "testhost")
	so := <-serverDone
	return cinfo, cerr, so.info, so.err
}

func TestAuthRoundTrip(t *testing.T) {
	cinfo, cerr, sinfo, serr := runAuth(t, "alice", "hunter2", "alice", "hunter2")
	if cerr != nil || serr != nil {
		t.Fatalf("authentication failed: client=%v server=%v", cerr, serr)
	}
	if cinfo.Cookie == "" {
		t.Error("the client received no session cookie")
	}
	if cinfo.Cookie != sinfo.Cookie {
		t.Errorf("cookies disagree: client %q, server %q", cinfo.Cookie, sinfo.Cookie)
	}
	if sinfo.User != "alice" {
		t.Errorf("the server attributed the session to %q", sinfo.User)
	}
}

// TestAuthRejectsWrongPassword: the server must say so rather than hang up, so
// the client can report a bad password instead of a broken connection.
func TestAuthRejectsWrongPassword(t *testing.T) {
	_, cerr, _, serr := runAuth(t, "alice", "hunter2", "alice", "wrong")
	if !errors.Is(serr, ErrAuth) {
		t.Errorf("server error = %v, want ErrAuth", serr)
	}
	if !errors.Is(cerr, ErrAuth) {
		t.Errorf("client error = %v, want ErrAuth", cerr)
	}
}

func TestAuthRejectsWrongUser(t *testing.T) {
	_, cerr, _, serr := runAuth(t, "alice", "hunter2", "mallory", "hunter2")
	if !errors.Is(serr, ErrAuth) || !errors.Is(cerr, ErrAuth) {
		t.Errorf("client=%v server=%v, want ErrAuth from both", cerr, serr)
	}
}

// TestPasswordSurvivesItsFraming pins the one part of the credential response
// that is easy to get subtly wrong: the password is bounded by a length octet
// that carries its size plus two, not by the enclosing AVP.
func TestPasswordSurvivesItsFraming(t *testing.T) {
	for _, pw := range []string{"", "a", "hunter2", "a password with spaces and ünïcode"} {
		body := passwordResponse(7, "alice", pw)
		avps, err := ParseAVPs(body)
		if err != nil {
			t.Fatalf("%q: %v", pw, err)
		}
		if u, ok := FindAVP(avps, AVPUsername); !ok || string(u.Value) != "alice" {
			t.Errorf("%q: username AVP = %q (present=%v)", pw, u.Value, ok)
		}

		msg := EncodeMessage(VendorTCG, TypeAuthResponse, 0, append(
			[]byte{0x00, 0x0a, 0x4c, 0x01}, EncodeEAPExpanded(EAPResponse, 7, JuniperSubtypeAVP, body)...))
		m, _, err := ParseMessage(msg)
		if err != nil {
			t.Fatal(err)
		}
		gotUser, gotPass, err := credentialsFrom(m)
		if err != nil {
			t.Fatalf("%q: %v", pw, err)
		}
		if gotUser != "alice" || gotPass != pw {
			t.Errorf("round-tripped as %q/%q, want alice/%q", gotUser, gotPass, pw)
		}
	}
}

// TestCredentialsRejectALyingLength: the length octet is peer-supplied and
// bounds a slice, so one that claims more than arrived must be refused.
func TestCredentialsRejectALyingLength(t *testing.T) {
	body := passwordResponse(7, "alice", "hunter2")
	avps, err := ParseAVPs(body)
	if err != nil {
		t.Fatal(err)
	}
	inner, ok := FindAVP(avps, AVPEAPMessage)
	if !ok {
		t.Fatal("no EAP-Message AVP")
	}
	// The password length octet sits just past the expanded EAP header.
	inner.Value[eapExpandedHeaderLen+2] = 0xff

	msg := EncodeMessage(VendorTCG, TypeAuthResponse, 0, append(
		[]byte{0x00, 0x0a, 0x4c, 0x01}, EncodeEAPExpanded(EAPResponse, 7, JuniperSubtypeAVP, body)...))
	m, _, err := ParseMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := credentialsFrom(m); err == nil {
		t.Fatal("a password longer than its message was accepted")
	}
}

// TestUpgradeIsRequired: a plain HTTPS request must be refused rather than fed
// to the IF-T/TLS reader, which would read the request body as a message header.
func TestUpgradeIsRequired(t *testing.T) {
	c, s := net.Pipe()
	defer func() { _ = c.Close() }()
	defer func() { _ = s.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))

	done := make(chan error, 1)
	go func() {
		_, _, err := ServerAuth(s, func(string, string) bool { return true })
		done <- err
	}()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: vpn.example\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// The refusal is an HTTP status, not a hang-up: read it, both to assert it
	// and because net.Pipe is unbuffered and the write would otherwise block.
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("reading the refusal: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 400 ") {
		t.Errorf("refusal = %q, want a 400", buf[:n])
	}
	if err := <-done; err == nil {
		t.Fatal("a request without the upgrade header was accepted")
	}
}
