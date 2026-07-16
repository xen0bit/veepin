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
func TestConnectFlagsCoverRegisteredProtocols(t *testing.T) {
	for _, name := range client.Protocols() {
		if _, err := connectFlags(name, newTestFlagSet()); err != nil {
			t.Errorf("connect has no flags for registered protocol %q: %v", name, err)
		}
	}
}
