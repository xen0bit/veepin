package fortinet

import (
	"strings"
	"testing"
)

func TestLoginFormRoundTrip(t *testing.T) {
	form := BuildLoginForm("alice", "s3cr=t&pw", "corp")
	req, err := ParseLoginForm(form)
	if err != nil {
		t.Fatalf("ParseLoginForm: %v", err)
	}
	// The password contains characters that must survive URL encoding intact.
	if req.Username != "alice" || req.Password != "s3cr=t&pw" || req.Realm != "corp" {
		t.Errorf("round trip = %+v", req)
	}
}

func TestLoginFormHasFortiClientFields(t *testing.T) {
	form := BuildLoginForm("bob", "pw", "")
	for _, want := range []string{"ajax=1", "just_logged_in=1", "credential=pw", "username=bob"} {
		if !contains(form, want) {
			t.Errorf("login form missing %q: %s", want, form)
		}
	}
}

func TestParseLoginResult(t *testing.T) {
	res, err := ParseLoginResult("ret=1,redir=/remote/fortisslvpn_xml")
	if err != nil {
		t.Fatal(err)
	}
	if res.Ret != 1 {
		t.Errorf("ret = %d, want 1", res.Ret)
	}
	if res.Redir != "/remote/fortisslvpn_xml" {
		t.Errorf("redir = %q", res.Redir)
	}

	// A 2FA challenge carries extra fields the caller may need.
	chal, err := ParseLoginResult("ret=2,reqid=42,polid=1,grp=x,tokeninfo=,chal_msg=Enter code")
	if err != nil {
		t.Fatal(err)
	}
	if chal.Ret != 2 || chal.Fields["reqid"] != "42" {
		t.Errorf("challenge parse = %+v", chal)
	}
}

func TestLoginSuccessLine(t *testing.T) {
	line := BuildLoginSuccess(PathConfigXML)
	res, err := ParseLoginResult(line)
	if err != nil || res.Ret != 1 || res.Redir != PathConfigXML {
		t.Errorf("BuildLoginSuccess round trip = %q -> %+v (%v)", line, res, err)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// The challenge round trip: what the gateway sends, and what the client sends
// back. The echoed values are the server's only memory of the exchange, so they
// have to survive unchanged.
func TestChallengeRoundTrip(t *testing.T) {
	echo := map[string]string{
		"reqid": "1234", "polid": "1", "grp": "sslvpn", "portal": "full", "magic": "0xdeadbeef",
	}
	line := BuildChallengeResponse("Enter your token code", echo)

	res, err := ParseLoginResult(line)
	if err != nil {
		t.Fatalf("ParseLoginResult(%q): %v", line, err)
	}
	if res.Ret != 2 {
		t.Errorf("ret = %d, want 2", res.Ret)
	}
	if !res.IsChallenge() {
		t.Fatal("a response with tokeninfo was not recognised as a challenge")
	}
	c := res.Challenge()
	if c.Message != "Enter your token code" {
		t.Errorf("message = %q", c.Message)
	}
	for k, want := range echo {
		if c.Echo[k] != want {
			t.Errorf("echo[%q] = %q, want %q", k, c.Echo[k], want)
		}
	}

	body := BuildChallengeForm("alice", "123456", "", c)
	if !IsChallengeForm(body) {
		t.Error("the second-stage form was not recognised as one")
	}
	req, err := ParseChallengeForm(body)
	if err != nil {
		t.Fatalf("ParseChallengeForm: %v", err)
	}
	if req.Username != "alice" || req.Code != "123456" {
		t.Errorf("username=%q code=%q", req.Username, req.Code)
	}
	for k, want := range echo {
		if req.Echo[k] != want {
			t.Errorf("round-tripped echo[%q] = %q, want %q", k, req.Echo[k], want)
		}
	}
}

// "magic" must be the last parameter: the ftm_push variant truncates the body at
// "&magic=", so anything after it would be lost too.
func TestChallengeFormMagicIsLast(t *testing.T) {
	c := Challenge{Echo: map[string]string{
		"magic": "m", "reqid": "r", "polid": "p", "grp": "g", "portal": "P", "peer": "e",
	}}
	body := BuildChallengeForm("alice", "123456", "", c)
	if i := strings.Index(body, "&magic="); i < 0 {
		t.Fatal("magic is missing from the form")
	} else if strings.Contains(body[i+len("&magic="):], "&") {
		t.Errorf("magic is not the last parameter: %q", body)
	}
}

// An empty code against an ftm_push challenge is the mobile-push request: magic
// goes, ftmpush=1 arrives.
func TestChallengeFormFTMPush(t *testing.T) {
	c := Challenge{TokenInfo: "ftm_push", Echo: map[string]string{"reqid": "r", "magic": "m"}}

	body := BuildChallengeForm("alice", "", "", c)
	if strings.Contains(body, "magic=") {
		t.Errorf("a push request still carried magic: %q", body)
	}
	req, err := ParseChallengeForm(body)
	if err != nil {
		t.Fatal(err)
	}
	if !req.FTMPush {
		t.Errorf("a push request did not parse as one: %q", body)
	}

	// With a code supplied, it is an ordinary submission and magic stays.
	body = BuildChallengeForm("alice", "123456", "", c)
	if !strings.Contains(body, "magic=m") {
		t.Errorf("a coded submission dropped magic: %q", body)
	}
	if strings.Contains(body, "ftmpush") {
		t.Errorf("a coded submission asked for a push: %q", body)
	}
}

// A first-stage login must not be mistaken for a second-stage submission.
func TestIsChallengeFormDistinguishesStages(t *testing.T) {
	if IsChallengeForm(BuildLoginForm("alice", "pw", "")) {
		t.Error("a first-stage login form was taken for a challenge")
	}
	if res, _ := ParseLoginResult(BuildLoginSuccess(PathConfigXML)); res.IsChallenge() {
		t.Error("a success response was taken for a challenge")
	}
}
