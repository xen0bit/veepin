package main

import (
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
)

// -route names what the tunnel carries, which is the thing -full-tunnel=false
// left an operator to do by hand with `ip route`.
func TestRouteAndExcludeParseIntoPrefixes(t *testing.T) {
	fs := newTestFlagSet()
	n := bindNetFlags(fs)
	err := fs.Parse([]string{
		"-route", "10.0.0.0/8",
		"-route", "192.168.1.0/24",
		"-exclude", "10.1.2.0/24",
		// A bare address is what an operator will type, and refusing it over a
		// missing /32 helps nobody.
		"-exclude", "192.0.2.10",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := n.routes.String(); got != "10.0.0.0/8,192.168.1.0/24" {
		t.Errorf("routes = %q", got)
	}
	if got := n.excludes.String(); got != "10.1.2.0/24,192.0.2.10/32" {
		t.Errorf("excludes = %q", got)
	}
}

// A prefix is parsed when it is typed, so a typo is a command-line error naming
// the value -- not a route that quietly never appears, which is the failure
// shape this tree calls the worst kind.
func TestAMalformedPrefixIsACommandLineError(t *testing.T) {
	for _, bad := range []string{"10.0.0.0/33", "not-an-address", "10.0.0.0/", ""} {
		fs := newTestFlagSet()
		bindNetFlags(fs)
		if err := fs.Parse([]string{"-route", bad}); err == nil {
			t.Errorf("-route %q was accepted", bad)
		}
	}
}

// Naming the prefixes to route and also routing everything is a contradiction.
// Honouring the default full tunnel would make -route a silent no-op.
func TestRouteImpliesASplitTunnel(t *testing.T) {
	fs := newTestFlagSet()
	n := bindNetFlags(fs)
	if err := fs.Parse([]string{"-route", "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if !n.fullTunnel {
		t.Fatal("the default is not a full tunnel; this test proves nothing")
	}
	if err := n.resolve(fs); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n.fullTunnel {
		t.Error("-route left the full tunnel on, so the named prefixes change nothing")
	}
}

// A contradiction the operator typed is reported, not resolved: silently
// picking one of two explicit instructions is how they end up with routing they
// did not ask for.
func TestRouteWithAnExplicitFullTunnelIsRefused(t *testing.T) {
	fs := newTestFlagSet()
	n := bindNetFlags(fs)
	if err := fs.Parse([]string{"-route", "10.0.0.0/8", "-full-tunnel=true"}); err != nil {
		t.Fatal(err)
	}
	err := n.resolve(fs)
	if err == nil {
		t.Fatal("-route with an explicit -full-tunnel=true was accepted")
	}
	if !strings.Contains(err.Error(), "pick one") {
		t.Errorf("error does not name the contradiction: %v", err)
	}
}

// -exclude on its own says nothing about the full tunnel: excluding a prefix
// from a full tunnel is exactly the useful case.
func TestExcludeAloneLeavesTheFullTunnelAlone(t *testing.T) {
	fs := newTestFlagSet()
	n := bindNetFlags(fs)
	if err := fs.Parse([]string{"-exclude", "192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := n.resolve(fs); err != nil {
		t.Fatal(err)
	}
	if !n.fullTunnel {
		t.Error("-exclude turned the full tunnel off; excluding from a full tunnel is the point")
	}
}

// probe used to name one protocol of seventeen while the usage block and the
// README both presented it as generic. It must now accept every registered
// protocol -- reaching a real dial attempt, not an "unknown protocol" refusal.
func TestProbeAcceptsEveryRegisteredProtocol(t *testing.T) {
	for _, protocol := range client.Protocols() {
		t.Run(protocol, func(t *testing.T) {
			// No options, so the dial fails at the parse -- which is the point:
			// a protocol-specific complaint proves probe got past the registry
			// check and bound that protocol's flags.
			err := runProbe([]string{protocol})
			if err == nil {
				t.Skip("dialed successfully, which needs no assertion here")
			}
			if strings.Contains(err.Error(), "unknown protocol") {
				t.Errorf("probe still refuses %q: %v", protocol, err)
			}
		})
	}
}

// A name that is not a protocol still says so, listing what is available --
// the one thing the old ikev2-only check got right.
func TestProbeStillRefusesAnUnknownProtocol(t *testing.T) {
	err := runProbe([]string{"nosuchvpn"})
	if err == nil {
		t.Fatal("an unknown protocol was accepted")
	}
	if !strings.Contains(err.Error(), "unknown protocol") {
		t.Errorf("error = %v", err)
	}
	// It must list the real set, not one name.
	if !strings.Contains(err.Error(), "wireguard") || !strings.Contains(err.Error(), "ikev2") {
		t.Errorf("error does not list the available protocols: %v", err)
	}
}
