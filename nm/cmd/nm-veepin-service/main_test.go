package main

import (
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/nm/internal/nmconfig"
)

// TestDefaultProtocolIsRegistered guards a failure the compiler cannot see: the
// plugin dials by name, so if the blank import of a protocol package is dropped
// this binary still builds and then fails every Connect at runtime with
// "unknown protocol".
func TestDefaultProtocolIsRegistered(t *testing.T) {
	for _, name := range client.Protocols() {
		if name == nmconfig.DefaultProtocol {
			return
		}
	}
	t.Fatalf("default protocol %q is not registered (registered: %v); "+
		"the blank import of the protocol package is missing from this command",
		nmconfig.DefaultProtocol, client.Protocols())
}
