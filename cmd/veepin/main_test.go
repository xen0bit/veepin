package main

import (
	"testing"

	"github.com/xen0bit/veepin/client"
)

// TestProtocolsAreRegistered guards a failure the compiler cannot see: the CLI
// dials by name, so if a protocol's blank import is dropped this binary still
// builds and only fails at runtime with "unknown protocol".
func TestProtocolsAreRegistered(t *testing.T) {
	got := client.Protocols()
	if len(got) == 0 {
		t.Fatal("no protocols registered; a blank import is missing from main.go")
	}
	for _, want := range []string{"ikev2"} {
		found := false
		for _, name := range got {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("protocol %q not registered (registered: %v)", want, got)
		}
	}
}

// TestConnectFlagsCoverRegisteredProtocols keeps the CLI's per-protocol flag
// sets in step with the registry: a protocol you can dial but cannot pass flags
// to is unreachable from the command line.
//
// It iterates AllProtocols rather than Protocols so that the pq- variants are
// covered. They carry no OptSpec table of their own -- ClientOptsFor falls back
// to the base -- and this is what proves that fallback actually reaches the flag
// generator rather than merely being written down.
func TestConnectFlagsCoverRegisteredProtocols(t *testing.T) {
	for _, name := range client.AllProtocols() {
		if _, err := connectFlags(name, newTestFlagSet()); err != nil {
			t.Errorf("connect has no flags for registered protocol %q: %v", name, err)
		}
	}
}

// TestEveryDialableNameResolvesAsAProtocol guards the gate that decides whether
// `veepin connect X` means a protocol or a saved profile.
//
// It is a separate check from the flag-set one above because they fail
// differently and only one of them is visible. connectFlags can succeed for a
// name that isProtocol rejects, and then the CLI looks past the registry
// entirely and reports "X is neither a protocol nor a saved profile" -- which
// reads as a user error rather than a missing registration.
//
// That is not hypothetical. isProtocol consulted client.Protocols(), which
// deliberately excludes variants, so every pq- name was unreachable from
// `veepin connect` while `veepin serve` worked fine. An interop cell found it;
// no unit test could have, because none of them went through this gate.
func TestEveryDialableNameResolvesAsAProtocol(t *testing.T) {
	for _, name := range client.AllProtocols() {
		if !knownProtocol(name) {
			t.Errorf("knownProtocol(%q) is false, so `veepin connect %s` looks for a profile "+
				"of that name instead of dialing the protocol", name, name)
		}
	}
	if len(client.AllVariants()) == 0 {
		t.Error("no variants are registered in this binary, so this guard proved nothing " +
			"about the case it exists for")
	}
}
