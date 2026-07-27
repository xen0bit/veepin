package gp

import (
	"net/url"
	"strings"
	"testing"
)

func TestLoginFormRoundTrip(t *testing.T) {
	form := BuildLoginForm("alice", "s3cret", "laptop", "10.50.0.7")
	req, err := ParseLoginForm(form)
	if err != nil {
		t.Fatalf("ParseLoginForm: %v", err)
	}
	if req.User != "alice" || req.Password != "s3cret" {
		t.Errorf("credentials %q/%q", req.User, req.Password)
	}
	if req.Computer != "laptop" || req.PreferredIP != "10.50.0.7" {
		t.Errorf("computer %q preferred-ip %q", req.Computer, req.PreferredIP)
	}
	if req.ClientVer != clientVersion {
		t.Errorf("clientVer %q, want %q", req.ClientVer, clientVersion)
	}
}

// TestLoginFormCarriesTheReferenceFields pins the field names, because the
// gateway looks for them by name and a rename would fail against a real one
// without failing any round-trip test.
func TestLoginFormCarriesTheReferenceFields(t *testing.T) {
	v, err := url.ParseQuery(BuildLoginForm("bob", "pw", "host", ""))
	if err != nil {
		t.Fatalf("parsing the form: %v", err)
	}
	for _, k := range []string{"prot", "jnlpReady", "user", "passwd", "clientVer", "clientos", "ok", "direct"} {
		if !v.Has(k) {
			t.Errorf("the login form omits %q", k)
		}
	}
}

func TestLoginResponseRoundTrip(t *testing.T) {
	want := LoginInfo{
		AuthCookie:       "0123456789abcdef0123456789abcdef",
		PersistentCookie: "cafe",
		Portal:           "gw",
		User:             "alice",
		Domain:           "example.com",
		PreferredIP:      "10.50.0.7",
	}
	got, err := ParseLoginResponse(BuildLoginResponse(want))
	if err != nil {
		t.Fatalf("ParseLoginResponse: %v", err)
	}
	if got != want {
		t.Errorf("round trip gave\n%+v\nwant\n%+v", got, want)
	}
}

// TestLoginResponseIsPositional proves the arguments are read by index rather
// than by content: the cookie must come out of slot 1 and the user out of slot 4,
// whatever they contain.
func TestLoginResponseIsPositional(t *testing.T) {
	doc := BuildLoginResponse(LoginInfo{AuthCookie: "AAA", User: "BBB"})
	args := strings.Count(string(doc), "<argument>")
	if args != argCount {
		t.Errorf("document carries %d arguments, want %d", args, argCount)
	}
	// Slot 12 must say "tunnel"; a client rejects anything else.
	if !strings.Contains(string(doc), "<argument>tunnel</argument>") {
		t.Error("the document does not declare the tunnel connection type")
	}
}

func TestLoginResponseRejects(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"not xml", "<<<"},
		{"wrong root", `<html><body/></html>`},
		{"no cookie", `<jnlp><application-desc><argument>(null)</argument></application-desc></jnlp>`},
		{"empty cookie", `<jnlp><application-desc><argument>(null)</argument><argument></argument></application-desc></jnlp>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseLoginResponse([]byte(tc.doc)); err == nil {
				t.Error("accepted a document with no usable cookie")
			}
		})
	}
}

// TestLoginResponseRejectsNonTunnel covers the gateway that authenticates the
// user for something other than a VPN — a real GlobalProtect deployment can do
// this, and the failure should name the reason rather than surface later as a
// broken tunnel request.
func TestLoginResponseRejectsNonTunnel(t *testing.T) {
	doc := BuildLoginResponse(LoginInfo{AuthCookie: "abc", User: "alice"})
	bad := strings.Replace(string(doc), "<argument>tunnel</argument>", "<argument>portal</argument>", 1)
	_, err := ParseLoginResponse([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "connection type") {
		t.Errorf("error %v, want one naming the connection type", err)
	}
}

func TestGetConfigFormRoundTrip(t *testing.T) {
	info := LoginInfo{AuthCookie: "cookie", User: "alice", Portal: "gw", Domain: "d"}
	req, err := ParseGetConfigForm(BuildGetConfigForm(info, "laptop"))
	if err != nil {
		t.Fatalf("ParseGetConfigForm: %v", err)
	}
	if req.AuthCookie != "cookie" || req.User != "alice" {
		t.Errorf("cookie %q user %q", req.AuthCookie, req.User)
	}
	if len(req.EncAlgos) != len(supportedEncAlgos) {
		t.Errorf("offered %v, want %v", req.EncAlgos, supportedEncAlgos)
	}
	if len(req.HMACAlgos) != len(supportedHMACAlgos) {
		t.Errorf("offered %v, want %v", req.HMACAlgos, supportedHMACAlgos)
	}
}

func TestSplitList(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"a", 1},
		{"a,b", 2},
		{"a, b ,", 2},
		{",,,", 0},
	}
	for _, tc := range cases {
		if got := splitList(tc.in); len(got) != tc.want {
			t.Errorf("splitList(%q) = %v, want %d entries", tc.in, got, tc.want)
		}
	}
}

func TestPreloginRoundTrip(t *testing.T) {
	pl, err := ParsePreloginResponse(BuildPreloginResponse("Enter your credentials"))
	if err != nil {
		t.Fatalf("ParsePreloginResponse: %v", err)
	}
	if pl.Status != "Success" {
		t.Errorf("status %q, want Success", pl.Status)
	}
	if pl.Message != "Enter your credentials" {
		t.Errorf("message %q", pl.Message)
	}
	if pl.SAML {
		t.Error("a password gateway reported SAML")
	}
}

// TestPreloginDetectsSAML matters because SAML is the one authentication method
// this client cannot do, and the failure should say so rather than look like a
// wrong password.
func TestPreloginDetectsSAML(t *testing.T) {
	doc := `<prelogin-response><status>Success</status>` +
		`<saml-auth-method>REDIRECT</saml-auth-method><saml-request>Zm9v</saml-request>` +
		`</prelogin-response>`
	pl, err := ParsePreloginResponse([]byte(doc))
	if err != nil {
		t.Fatalf("ParsePreloginResponse: %v", err)
	}
	if !pl.SAML {
		t.Error("a SAML gateway was not recognised")
	}
}

func TestTunnelRequest(t *testing.T) {
	info := LoginInfo{User: "alice", AuthCookie: "deadbeef"}
	req := string(TunnelRequest("gw.example:443", info))
	if !strings.HasPrefix(req, "GET "+PathTunnel+"?") {
		t.Errorf("request line is %q", strings.SplitN(req, "\r\n", 2)[0])
	}
	if !strings.HasSuffix(req, "\r\n\r\n") {
		t.Error("the request is not terminated by a blank line")
	}
	if !strings.Contains(req, "Host: gw.example:443\r\n") {
		t.Error("the request carries no Host header")
	}

	// The gateway authorises the tunnel from the query string alone.
	line := strings.SplitN(req, "\r\n", 2)[0]
	query := strings.TrimSuffix(strings.SplitN(line, "?", 2)[1], " HTTP/1.1")
	user, cookie := ParseTunnelRequest(query)
	if user != "alice" || cookie != "deadbeef" {
		t.Errorf("ParseTunnelRequest = %q, %q", user, cookie)
	}
}

func TestParseTunnelRequestRejectsGarbage(t *testing.T) {
	if user, cookie := ParseTunnelRequest("%zz"); user != "" || cookie != "" {
		t.Errorf("a malformed query yielded %q, %q", user, cookie)
	}
}

func TestLogoutForm(t *testing.T) {
	info := LoginInfo{AuthCookie: "c", User: "alice", Portal: "gw", Domain: "d"}
	v, err := url.ParseQuery(BuildLogoutForm(info, "laptop"))
	if err != nil {
		t.Fatalf("parsing the logout form: %v", err)
	}
	if v.Get("authcookie") != "c" || v.Get("user") != "alice" {
		t.Errorf("logout form is %v", v)
	}
}
