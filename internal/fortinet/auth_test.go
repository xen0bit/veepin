package fortinet

import "testing"

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
