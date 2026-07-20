package fortinet

import "testing"

func TestGFTypeClientHelloRoundTrip(t *testing.T) {
	cookie := "abc123DEADBEEFcookievalue"
	msg := BuildDTLSClientHello(cookie)

	// The literal prefix must be present, and the length must include itself.
	if int(msg[0])<<8|int(msg[1]) != len(msg) {
		t.Errorf("length field %d does not equal message length %d", int(msg[0])<<8|int(msg[1]), len(msg))
	}
	got, err := ParseDTLSClientHello(msg)
	if err != nil {
		t.Fatalf("ParseDTLSClientHello: %v", err)
	}
	if got != cookie {
		t.Errorf("cookie = %q, want %q", got, cookie)
	}
}

func TestGFTypeServerHelloRoundTrip(t *testing.T) {
	msg := BuildDTLSServerHello()
	if err := ParseDTLSServerHello(msg); err != nil {
		t.Fatalf("ParseDTLSServerHello rejected a well-formed response: %v", err)
	}
}

func TestGFTypeRejects(t *testing.T) {
	if _, err := ParseDTLSClientHello([]byte{0x00}); err == nil {
		t.Error("accepted a truncated clthello")
	}
	if _, err := ParseDTLSClientHello([]byte("\x00\x08nonsense")); err == nil {
		t.Error("accepted a clthello with the wrong prefix")
	}
	// A svrhello whose confirmation is not "ok" must be rejected.
	bad := BuildDTLSServerHello()
	bad[len(bad)-1] = 'X'
	if err := ParseDTLSServerHello(bad); err == nil {
		t.Error("accepted a svrhello that did not confirm")
	}
}
