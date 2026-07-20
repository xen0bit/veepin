package fortinet

// The HTTPS login exchange at /remote/logincheck.
//
// The client POSTs a form; on success FortiOS answers with a short text line —
// ret=1,redir=/remote/fortisslvpn_xml — and sets the SVPNCOOKIE that authorises
// every later request. This file is just those two shapes: building and parsing
// the form, and building and parsing the response line. The cookie itself is an
// opaque bearer token, minted by the server and echoed back by the client.

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Well-known Fortinet SSL VPN endpoints and the session cookie name.
const (
	PathLoginCheck = "/remote/logincheck"
	PathConfigXML  = "/remote/fortisslvpn_xml"
	PathTunnel     = "/remote/sslvpn-tunnel"
	CookieName     = "SVPNCOOKIE"
)

// BuildLoginForm renders the application/x-www-form-urlencoded body a client
// POSTs to /remote/logincheck. realm may be empty. ajax=1 and just_logged_in=1
// are what the FortiOS web client sends and what the server expects to see.
func BuildLoginForm(username, password, realm string) string {
	v := url.Values{}
	v.Set("username", username)
	v.Set("credential", password)
	v.Set("realm", realm)
	v.Set("ajax", "1")
	v.Set("just_logged_in", "1")
	return v.Encode()
}

// LoginRequest is a decoded /remote/logincheck form.
type LoginRequest struct {
	Username string
	Password string
	Realm    string
}

// ParseLoginForm decodes the form body a client POSTed.
func ParseLoginForm(body string) (LoginRequest, error) {
	v, err := url.ParseQuery(body)
	if err != nil {
		return LoginRequest{}, fmt.Errorf("fortinet: malformed login form: %w", err)
	}
	return LoginRequest{
		Username: v.Get("username"),
		Password: v.Get("credential"),
		Realm:    v.Get("realm"),
	}, nil
}

// BuildLoginSuccess renders the response line for a successful login. redir is
// the path the client is told to fetch next, normally PathConfigXML.
func BuildLoginSuccess(redir string) string {
	return "ret=1,redir=" + redir
}

// LoginResult is a decoded /remote/logincheck response line.
type LoginResult struct {
	// Ret is the numeric status: 1 success, 2 challenge (2FA), other failures.
	Ret int
	// Redir is the follow-up path on success.
	Redir string
	// Fields holds every key=value pair, so a caller handling a challenge can
	// read reqid/polid/grp without this needing to know them.
	Fields map[string]string
}

// ParseLoginResult decodes the ret=…,redir=… response line.
func ParseLoginResult(line string) (LoginResult, error) {
	res := LoginResult{Ret: -1, Fields: map[string]string{}}
	for part := range strings.SplitSeq(strings.TrimSpace(line), ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		res.Fields[k] = v
		switch k {
		case "ret":
			if n, err := strconv.Atoi(v); err == nil {
				res.Ret = n
			}
		case "redir":
			res.Redir = v
		}
	}
	if res.Ret < 0 {
		return LoginResult{}, fmt.Errorf("fortinet: login response has no ret: %q", line)
	}
	return res, nil
}
