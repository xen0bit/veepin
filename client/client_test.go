package client

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// stubDialer records the options it was built from.
type stubDialer struct{ opts map[string]string }

func (d stubDialer) Dial(context.Context) (Session, Result, error) {
	return nil, Result{TUNName: d.opts["tun"]}, nil
}

// withRegistry swaps the package registry for the duration of a test, so tests
// do not depend on which protocol packages happen to be linked in.
func withRegistry(t *testing.T, entries map[string]ParseFunc) {
	t.Helper()
	mu.Lock()
	saved := protocols
	protocols = entries
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		protocols = saved
		mu.Unlock()
	})
}

func TestDialUnknownProtocol(t *testing.T) {
	withRegistry(t, map[string]ParseFunc{
		"ikev2": func(map[string]string) (Dialer, error) { return stubDialer{}, nil },
	})

	_, _, err := Dial(context.Background(), "wireguard", nil)
	if !errors.Is(err, ErrUnknownProtocol) {
		t.Fatalf("err = %v, want ErrUnknownProtocol", err)
	}
	// The message should name what *is* available, since the usual cause is a
	// missing blank import of the protocol package.
	if got := err.Error(); !contains(got, "ikev2") {
		t.Errorf("error %q does not mention the registered protocols", got)
	}
}

func TestDialRoutesToRegisteredProtocol(t *testing.T) {
	var gotOpts map[string]string
	withRegistry(t, map[string]ParseFunc{
		"ikev2": func(opts map[string]string) (Dialer, error) {
			gotOpts = opts
			return stubDialer{opts}, nil
		},
	})

	_, res, err := Dial(context.Background(), "ikev2", map[string]string{"tun": "tun7"})
	if err != nil {
		t.Fatal(err)
	}
	if gotOpts["tun"] != "tun7" {
		t.Errorf("ParseFunc got opts %v, want tun=tun7", gotOpts)
	}
	if res.TUNName != "tun7" {
		t.Errorf("Result.TUNName = %q, want tun7", res.TUNName)
	}
}

// TestDialParseErrorIsReported ensures a protocol's validation error reaches the
// caller rather than being swallowed into a generic failure.
func TestDialParseErrorIsReported(t *testing.T) {
	sentinel := errors.New("psk is required")
	withRegistry(t, map[string]ParseFunc{
		"ikev2": func(map[string]string) (Dialer, error) { return nil, sentinel },
	})

	_, _, err := Dial(context.Background(), "ikev2", nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap %v", err, sentinel)
	}
}

func TestProtocolsIsSorted(t *testing.T) {
	stub := func(map[string]string) (Dialer, error) { return stubDialer{}, nil }
	withRegistry(t, map[string]ParseFunc{
		"wireguard": stub,
		"ikev2":     stub,
		"openvpn":   stub,
	})

	got := Protocols()
	want := []string{"ikev2", "openvpn", "wireguard"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Protocols() = %v, want %v", got, want)
	}
}

func TestRegisterRejectsDuplicates(t *testing.T) {
	withRegistry(t, map[string]ParseFunc{})
	stub := func(map[string]string) (Dialer, error) { return stubDialer{}, nil }

	Register("ikev2", stub)
	defer func() {
		if recover() == nil {
			t.Fatal("registering the same protocol twice did not panic")
		}
	}()
	Register("ikev2", stub)
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestWrapAuthKeepsTheProtocolsOwnSentinelReachable is the claim that makes
// WrapAuth worth having over a hand-written fmt.Errorf at each call site.
//
// The three facades that mapped ErrAuth before this existed all formatted the
// inner error with %v, which severs it: errors.Is stops finding the protocol's
// own sentinel the moment the registry's one is attached. Nothing failed when
// that happened, because nothing looked. A caller that knows which protocol it
// dialled should still be able to ask how the credential was refused.
func TestWrapAuthKeepsTheProtocolsOwnSentinelReachable(t *testing.T) {
	sentinel := errors.New("proto: authentication failed")
	inner := fmt.Errorf("%w: the server said no", sentinel)

	got := WrapAuth(fmt.Errorf("proto: connect: %w", inner), sentinel)

	if !errors.Is(got, ErrAuth) {
		t.Errorf("errors.Is(%v, ErrAuth) = false, want true", got)
	}
	if !errors.Is(got, sentinel) {
		t.Errorf("errors.Is(%v, sentinel) = false, want true — the chain was severed", got)
	}
}

// TestWrapAuthLeavesEveryOtherFailureAlone. A transport error that reached
// ErrAuth would be worse than one that did not: -retry would stop waiting out an
// outage it should wait out, and NetworkManager would prompt for a password that
// was never wrong.
func TestWrapAuthLeavesEveryOtherFailureAlone(t *testing.T) {
	sentinel := errors.New("proto: authentication failed")
	timeout := errors.New("proto: i/o timeout")

	if got := WrapAuth(timeout, sentinel); !errors.Is(got, timeout) || errors.Is(got, ErrAuth) {
		t.Errorf("WrapAuth(timeout) = %v, want the timeout unchanged and not ErrAuth", got)
	}
	if got := WrapAuth(nil, sentinel); got != nil {
		t.Errorf("WrapAuth(nil) = %v, want nil", got)
	}
}

// TestWrapAuthMatchesAnyOfSeveralSentinels covers the protocols that
// authenticate twice in sequence: l2tp's IPsec PSK then its MS-CHAPv2 password,
// cisco's group key then its XAuth password. Either being wrong is the caller's
// to fix, and a version that only checked the first would report the second as
// an outage.
func TestWrapAuthMatchesAnyOfSeveralSentinels(t *testing.T) {
	first := errors.New("phase 1 rejected")
	second := errors.New("phase 2 rejected")

	for _, s := range []error{first, second} {
		if got := WrapAuth(fmt.Errorf("wrapped: %w", s), first, second); !errors.Is(got, ErrAuth) {
			t.Errorf("WrapAuth(%v) did not report ErrAuth", s)
		}
	}
}
