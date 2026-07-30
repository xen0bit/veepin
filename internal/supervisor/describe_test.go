package supervisor

// Guards the option-metadata contract the management panel relies on. The
// panel renders a typed form only when client.ServerOptsFor(protocol) returns
// real metadata; without it, the panel falls back to a free-form JSON editor
// for that protocol. Allowing an unguarded pair means the panel silently
// degrades for exactly the protocols that just landed -- a later person adds
// the facade and forgets to register option metadata, and only the panel's UX
// reveals it, after the PR merged.
//
// This test runs against the production registry. To populate the registry, the
// test file pulls in the same blank imports as the binary (`cmd/veepin`):
// every server facade for its registration side effect. The selection is the
// set of protocols client.ServerProtocols() reports; toy is included, because
// a "toy has no opts" regression is exactly the same shape as a production
// protocol missing them.
//
// The check accepts every protocol the registry knows, including "toy", and
// fails on the first that does not declare ServerOpts.

import (
	"testing"

	"github.com/xen0bit/veepin/client"

	_ "github.com/xen0bit/veepin/amneziawg"
	_ "github.com/xen0bit/veepin/anyconnect"
	_ "github.com/xen0bit/veepin/cisco"
	_ "github.com/xen0bit/veepin/fortinet"
	_ "github.com/xen0bit/veepin/gp"
	_ "github.com/xen0bit/veepin/ikev2"
	_ "github.com/xen0bit/veepin/l2tp"
	_ "github.com/xen0bit/veepin/l2tpv3"
	_ "github.com/xen0bit/veepin/masque"
	_ "github.com/xen0bit/veepin/nebula"
	_ "github.com/xen0bit/veepin/openvpn"
	_ "github.com/xen0bit/veepin/pulse"
	_ "github.com/xen0bit/veepin/softether"
	_ "github.com/xen0bit/veepin/ssh"
	_ "github.com/xen0bit/veepin/sstp"
	_ "github.com/xen0bit/veepin/toy"
	_ "github.com/xen0bit/veepin/wireguard"
)

// TestEveryServerProtocolDeclaresOptions is the guard proper. Every protocol
// the registry serves must have called RegisterServerOpts, otherwise the
// panel renders a JSON-textarea for it -- not the typed form an operator who
// just added a production protocol would expect.
func TestEveryServerProtocolDeclaresOptions(t *testing.T) {
	protocols := client.ServerProtocols()
	if len(protocols) == 0 {
		t.Fatal("no server protocols registered; blank imports are missing from this test")
	}
	for _, name := range protocols {
		opts, ok := client.ServerOptsFor(name)
		if !ok {
			t.Errorf("protocol %q registered as a server but declared no OptSpec via "+
				"client.RegisterServerOpts -- the management panel falls back to a "+
				"free-form JSON editor for it", name)
			continue
		}
		if len(opts) == 0 {
			t.Errorf("protocol %q declared an empty OptSpec slice; same UX regression", name)
		}
		// Every spec must have a Key -- a spec without a Key would render a
		// form field with no name and silently get dropped on submit.
		var sawKeys = make(map[string]bool, len(opts))
		for _, s := range opts {
			if s.Key == "" {
				t.Errorf("protocol %q: an OptSpec has an empty Key", name)
			}
			if sawKeys[s.Key] {
				t.Errorf("protocol %q: OptSpec %q listed twice", name, s.Key)
			}
			sawKeys[s.Key] = true
		}
	}
}

// The back half of the contract -- that a spec's Key is one the protocol's
// parseServerOptions actually reads, and that every key it reads has a spec --
// lives in cmd/veepin/flags_test.go as
// TestServerOptSpecsMatchTheKeysTheProtocolReads. It belongs there because the
// reference it checks against is serveFlags' emitted option map, which is by
// construction the set of keys `veepin serve <protocol>` can set.
