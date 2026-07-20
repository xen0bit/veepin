package fortinet

import "testing"

// The framing, config and login parsers all read bytes off a network peer that
// may be hostile or simply a different FortiOS version. A panic on malformed
// input is a denial of service; each of these must reject or round-trip, never
// crash.

func FuzzParseFrame(f *testing.F) {
	f.Add(EncodeFrame([]byte{0xff, 0x03, 0xc0, 0x21, 0x01}))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x0b, 0x50, 0x50, 0x00, 0x05})

	f.Fuzz(func(t *testing.T, data []byte) {
		ppp, rest, err := ParseFrame(data)
		if err != nil {
			return
		}
		// An accepted frame must re-encode to a prefix of the input, and the rest
		// must be exactly what is left.
		enc := EncodeFrame(ppp)
		if len(enc) > len(data) || len(rest) != len(data)-len(enc) {
			t.Fatalf("frame of %d octets: encoded %d, input %d, rest %d", len(ppp), len(enc), len(data), len(rest))
		}
	})
}

func FuzzParseConfigXML(f *testing.F) {
	f.Add(BuildConfigXML(Config{}))
	f.Add([]byte(`<sslvpn-tunnel><ipv4><assigned-addr ipv4="10.0.0.2"/></ipv4></sslvpn-tunnel>`))
	f.Add([]byte(""))
	f.Add([]byte("<not-xml"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseConfigXML(data)
	})
}

func FuzzParseLoginResult(f *testing.F) {
	f.Add("ret=1,redir=/remote/fortisslvpn_xml")
	f.Add("ret=2,reqid=1,tokeninfo=")
	f.Add("")
	f.Add("garbage,,,==")

	f.Fuzz(func(t *testing.T, line string) {
		_, _ = ParseLoginResult(line)
	})
}

func FuzzParseLoginForm(f *testing.F) {
	f.Add(BuildLoginForm("alice", "pw", "realm"))
	f.Add("username=x&credential=y")
	f.Add("")

	f.Fuzz(func(t *testing.T, body string) {
		_, _ = ParseLoginForm(body)
	})
}

// The GFtype exchange is the first thing an unauthenticated peer sends over a
// fresh DTLS session, so its parsers see attacker-chosen bytes by design.
func FuzzParseDTLSClientHello(f *testing.F) {
	f.Add(BuildDTLSClientHello("cookie"))
	f.Add(BuildDTLSClientHello(""))
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		cookie, err := ParseDTLSClientHello(data)
		if err != nil {
			return
		}
		// An accepted message must re-encode to exactly what was accepted:
		// anything else means the parser read a cookie the builder cannot express.
		if enc := BuildDTLSClientHello(cookie); string(enc) != string(data) {
			t.Fatalf("cookie %q re-encoded to %d octets, input was %d", cookie, len(enc), len(data))
		}
	})
}

func FuzzParseDTLSServerHello(f *testing.F) {
	f.Add(BuildDTLSServerHello())
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x02})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseDTLSServerHello(data)
	})
}

// The challenge forms cross the same trust boundary as the login ones: the
// gateway parses whatever a client POSTs, and the client parses whatever the
// gateway answers.
func FuzzParseChallengeForm(f *testing.F) {
	f.Add(BuildChallengeForm("alice", "123456", "", Challenge{Echo: map[string]string{"reqid": "r", "magic": "m"}}))
	f.Add(BuildChallengeForm("alice", "", "", Challenge{TokenInfo: "ftm_push", Echo: map[string]string{"reqid": "r"}}))
	f.Add("reqid=1&code=2")
	f.Add("")
	f.Add("%%%")

	f.Fuzz(func(t *testing.T, body string) {
		req, err := ParseChallengeForm(body)
		if err != nil {
			return
		}
		// Anything that parses must also be recognised as a challenge form when
		// it carries a reqid; the server routes on exactly that distinction, so a
		// disagreement between the two would send a stage to the wrong handler.
		if _, ok := req.Echo["reqid"]; ok != IsChallengeForm(body) {
			t.Fatalf("reqid present = %v but IsChallengeForm = %v for %q", ok, IsChallengeForm(body), body)
		}
	})
}
