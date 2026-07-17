package client

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

// stubServer is a minimal Server for registry tests.
type stubServer struct{ tun string }

func (s stubServer) ListenAndServe() error { return nil }
func (s stubServer) Close() error          { return nil }
func (s stubServer) TUNName() string       { return s.tun }
func (s stubServer) Gateway() net.IP       { return nil }
func (s stubServer) Network() *net.IPNet   { return nil }

// withServerRegistry swaps the server registry for the duration of a test, so
// tests do not depend on which protocol packages happen to be linked in.
func withServerRegistry(t *testing.T, entries map[string]ServerParseFunc) {
	t.Helper()
	serverMu.Lock()
	saved := serverParse
	serverParse = entries
	serverMu.Unlock()
	t.Cleanup(func() {
		serverMu.Lock()
		serverParse = saved
		serverMu.Unlock()
	})
}

func TestNewServerUnknownProtocol(t *testing.T) {
	withServerRegistry(t, map[string]ServerParseFunc{
		"ikev2": func(map[string]string) (Server, error) { return stubServer{}, nil },
	})

	_, err := NewServer("openvpn", nil)
	if !errors.Is(err, ErrUnknownProtocol) {
		t.Fatalf("err = %v, want ErrUnknownProtocol", err)
	}
	// The message should name the protocols that *can* serve, since a client-only
	// protocol (openvpn today) is the usual cause.
	if got := err.Error(); !contains(got, "ikev2") {
		t.Errorf("error %q does not mention the server protocols", got)
	}
}

func TestNewServerRoutesToRegisteredProtocol(t *testing.T) {
	var gotOpts map[string]string
	withServerRegistry(t, map[string]ServerParseFunc{
		"ikev2": func(opts map[string]string) (Server, error) {
			gotOpts = opts
			return stubServer{tun: opts["tun"]}, nil
		},
	})

	srv, err := NewServer("ikev2", map[string]string{"tun": "tun7"})
	if err != nil {
		t.Fatal(err)
	}
	if gotOpts["tun"] != "tun7" {
		t.Errorf("ServerParseFunc got opts %v, want tun=tun7", gotOpts)
	}
	if srv.TUNName() != "tun7" {
		t.Errorf("Server.TUNName() = %q, want tun7", srv.TUNName())
	}
}

// TestNewServerParseErrorIsReported ensures a protocol's validation error reaches
// the caller rather than being swallowed.
func TestNewServerParseErrorIsReported(t *testing.T) {
	sentinel := errors.New("psk is required")
	withServerRegistry(t, map[string]ServerParseFunc{
		"ikev2": func(map[string]string) (Server, error) { return nil, sentinel },
	})

	_, err := NewServer("ikev2", nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap %v", err, sentinel)
	}
}

func TestServerProtocolsIsSorted(t *testing.T) {
	stub := func(map[string]string) (Server, error) { return stubServer{}, nil }
	withServerRegistry(t, map[string]ServerParseFunc{
		"wireguard": stub,
		"ikev2":     stub,
	})

	got := ServerProtocols()
	want := []string{"ikev2", "wireguard"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("ServerProtocols() = %v, want %v", got, want)
	}
}

func TestRegisterServerRejectsDuplicates(t *testing.T) {
	withServerRegistry(t, map[string]ServerParseFunc{})
	stub := func(map[string]string) (Server, error) { return stubServer{}, nil }

	RegisterServer("ikev2", stub)
	defer func() {
		if recover() == nil {
			t.Fatal("registering the same server protocol twice did not panic")
		}
	}()
	RegisterServer("ikev2", stub)
}
