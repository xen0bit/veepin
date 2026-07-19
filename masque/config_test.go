package masque

import "testing"

func TestParseOptionsRequiresServer(t *testing.T) {
	if _, err := parseOptions(map[string]string{}); err == nil {
		t.Error("accepted options with no server")
	}
}

func TestParseOptionsPortValidation(t *testing.T) {
	for _, tc := range []struct {
		port string
		ok   bool
	}{
		{"443", true},
		{"1", true},
		{"65535", true},
		{"0", false},
		{"70000", false},
		{"nope", false},
	} {
		_, err := parseOptions(map[string]string{OptServer: "proxy.example", OptPort: tc.port})
		if (err == nil) != tc.ok {
			t.Errorf("port %q: err=%v, want ok=%v", tc.port, err, tc.ok)
		}
	}
}

func TestParseOptionsInsecure(t *testing.T) {
	d, err := parseOptions(map[string]string{OptServer: "proxy.example", OptInsecure: "true"})
	if err != nil {
		t.Fatal(err)
	}
	if !d.(dialer).cfg.Insecure {
		t.Error("insecure=true was not carried into the config")
	}
}

func TestParseServerOptionsRequiresKeypair(t *testing.T) {
	// No cert/key paths: must be rejected rather than starting an unauthenticated
	// proxy.
	if _, err := parseServerOptions(map[string]string{OptServerPool: "10.30.0.0/24"}); err == nil {
		t.Error("accepted a server with no certificate")
	}
}
