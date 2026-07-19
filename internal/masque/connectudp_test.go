package masque

import "testing"

func TestConnectUDPPath(t *testing.T) {
	for _, tc := range []struct {
		host string
		port int
		want string
	}{
		{"1.1.1.1", 53, "/.well-known/masque/udp/1.1.1.1/53/"},
		{"example.com", 443, "/.well-known/masque/udp/example.com/443/"},
		// An IPv6 literal has its colons percent-encoded.
		{"2001:db8::1", 53, "/.well-known/masque/udp/2001:db8::1/53/"},
	} {
		got := ConnectUDPPath(tc.host, tc.port)
		host, port, ok := ParseConnectUDPTarget(got)
		if !ok {
			t.Errorf("ParseConnectUDPTarget(%q) failed", got)
			continue
		}
		if host != tc.host || port != tc.port {
			t.Errorf("round trip %q: got %s:%d, want %s:%d", got, host, port, tc.host, tc.port)
		}
	}
}

func TestParseConnectUDPTargetRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
	}{
		{"wrong prefix", "/.well-known/masque/ip/1.1.1.1/53/"},
		{"no port", "/.well-known/masque/udp/1.1.1.1/"},
		{"port not a number", "/.well-known/masque/udp/1.1.1.1/http/"},
		{"port out of range", "/.well-known/masque/udp/1.1.1.1/70000/"},
		{"empty host", "/.well-known/masque/udp//53/"},
		{"extra segments", "/.well-known/masque/udp/1.1.1.1/53/extra/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := ParseConnectUDPTarget(tc.path); ok {
				t.Errorf("accepted a bad path: %q", tc.path)
			}
		})
	}
}

func TestIsConnectUDP(t *testing.T) {
	if !IsConnectUDP(ConnectUDPHeaders("proxy", ConnectUDPPath("1.1.1.1", 53))) {
		t.Error("a well-formed CONNECT-UDP request was not recognised")
	}
	// A CONNECT-IP request must not read as CONNECT-UDP, and vice versa.
	if IsConnectUDP(ConnectIPHeaders("proxy", "/.well-known/masque/ip/*/*/")) {
		t.Error("CONNECT-IP was accepted as CONNECT-UDP")
	}
	if IsConnectIP(ConnectUDPHeaders("proxy", ConnectUDPPath("1.1.1.1", 53))) {
		t.Error("CONNECT-UDP was accepted as CONNECT-IP")
	}
}
