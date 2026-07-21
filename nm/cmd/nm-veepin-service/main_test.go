package main

import (
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/nm/internal/nmconfig"
)

// registered reports whether name is in the client registry (i.e. its package
// was blank-imported by this command).
func registered(name string) bool {
	for _, n := range client.Protocols() {
		if n == name {
			return true
		}
	}
	return false
}

// TestDefaultProtocolIsRegistered guards a failure the compiler cannot see: the
// plugin dials by name, so if the blank import of a protocol package is dropped
// this binary still builds and then fails every Connect at runtime with
// "unknown protocol".
func TestDefaultProtocolIsRegistered(t *testing.T) {
	if !registered(nmconfig.DefaultProtocol) {
		t.Fatalf("default protocol %q is not registered (registered: %v); "+
			"the blank import of the protocol package is missing from this command",
			nmconfig.DefaultProtocol, client.Protocols())
	}
}

// TestAllSupportedProtocolsRegistered keeps the two protocol lists in lockstep:
// every protocol nmconfig knows how to configure must have its package imported
// here (or Connect fails at runtime), and every protocol imported here — except
// the deliberately excluded "toy" — should be one nmconfig can configure (or the
// GUI/nmcli can select a protocol the plugin then rejects).
func TestAllSupportedProtocolsRegistered(t *testing.T) {
	for _, name := range nmconfig.SupportedProtocols {
		if !registered(name) {
			t.Errorf("nmconfig supports %q but its package is not blank-imported by the service; "+
				"add `_ \"github.com/xen0bit/veepin/%s\"` to main.go", name, name)
		}
	}

	supported := make(map[string]bool, len(nmconfig.SupportedProtocols))
	for _, name := range nmconfig.SupportedProtocols {
		supported[name] = true
	}
	for _, name := range client.Protocols() {
		if name == "toy" {
			continue // the insecure example is intentionally not offered by the plugin
		}
		if !supported[name] {
			t.Errorf("protocol %q is registered but nmconfig cannot configure it; "+
				"add it to nmconfig.SupportedProtocols and the requireKeys/secretMissing switches", name)
		}
	}
}
