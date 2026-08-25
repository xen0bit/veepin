package main

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/vlog"
)

func quietLogger() *vlog.Logger { return vlog.Discard() }

// A split tunnel deliberately sends some traffic outside the VPN, so there is
// nothing there to fail closed: blackholing everything would break exactly the
// traffic the operator asked to keep outside. Refused rather than delivered as
// something worse than what was asked for.
func TestKillSwitchRefusesASplitTunnel(t *testing.T) {
	var killer *dataplane.KillSwitch
	res := client.Result{TUNName: "tun0", AssignedIP: net.ParseIP("10.0.0.2"), Gateway: net.ParseIP("192.0.2.10")}

	err := armKillSwitch(&killer, res, false, quietLogger())
	if err == nil {
		t.Fatal("armed on a split tunnel")
	}
	if !strings.Contains(err.Error(), "full tunnel") {
		t.Errorf("error does not say what is missing: %v", err)
	}
	if killer != nil {
		t.Error("a refused arm left a kill switch behind")
	}
}

// A mesh reaches peers at many underlay addresses, so there is no single route
// to carve out of the blackhole -- and a kill switch with no carve-out is a
// host that can never reconnect. This is the case worth refusing loudly: the
// alternative is a bricked machine that looks like it is retrying.
func TestKillSwitchRefusesAProtocolWithNoSingleServerAddress(t *testing.T) {
	var killer *dataplane.KillSwitch
	res := client.Result{TUNName: "nebula0", AssignedIP: net.ParseIP("10.42.0.2")} // Gateway nil, as a mesh reports

	err := armKillSwitch(&killer, res, true, quietLogger())
	if err == nil {
		t.Fatal("armed for a protocol with no server address; the host could never re-dial")
	}
	if !strings.Contains(err.Error(), "cannot re-dial") {
		t.Errorf("error does not name the consequence: %v", err)
	}
}

// Both refusals are configuration, not weather. Retrying them prints the same
// line every sixty seconds forever, which reads to an operator as a network
// problem rather than as the thing they typed.
func TestKillSwitchRefusalsAreNotRetried(t *testing.T) {
	var killer *dataplane.KillSwitch
	res := client.Result{TUNName: "tun0", AssignedIP: net.ParseIP("10.0.0.2"), Gateway: net.ParseIP("192.0.2.10")}
	splitErr := armKillSwitch(&killer, res, false, quietLogger())

	mesh := client.Result{TUNName: "nebula0", AssignedIP: net.ParseIP("10.42.0.2")}
	meshErr := armKillSwitch(&killer, mesh, true, quietLogger())

	for name, err := range map[string]error{"split tunnel": splitErr, "no gateway": meshErr} {
		if err == nil {
			t.Fatalf("%s: expected a refusal", name)
		}
		if !errors.Is(err, errNoRetry) {
			t.Errorf("%s: %v is retryable; the loop will repeat it forever", name, err)
		}
		if !permanent(err) {
			t.Errorf("%s: permanent() does not stop on %v", name, err)
		}
	}
}

// Off by default. A kill switch that engages when the user did not ask for one
// strands a machine they may only be able to reach over the network they just
// blackholed.
func TestKillSwitchIsOffByDefault(t *testing.T) {
	fs := newTestFlagSet()
	n := bindNetFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if n.killSwitch {
		t.Error("-kill-switch defaults to on; an unasked-for kill switch can strand a remote host")
	}
}

// The one refusal that was missing, and the only one that used to be silent.
//
// dialConnect arms the switch inside the same `if !noRoute` block that installs
// the routes, so -no-route -kill-switch brought the tunnel up, said nothing, and
// failed open while the operator had explicitly asked to fail closed. A flag
// that is accepted and does nothing is the shape of bug this tree calls the
// worst kind, and it is worse again when the flag is the safety one.
func TestKillSwitchAndNoRouteAreRefusedTogether(t *testing.T) {
	fs := newTestFlagSet()
	n := bindNetFlags(fs)
	if err := fs.Parse([]string{"-no-route", "-kill-switch"}); err != nil {
		t.Fatal(err)
	}
	err := n.resolve(fs)
	if err == nil {
		t.Fatal("-no-route -kill-switch was accepted; the switch never arms and nothing says so")
	}
	// Both flags named, because the operator has to know which one to drop.
	for _, want := range []string{"-kill-switch", "-no-route"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s: %v", want, err)
		}
	}
}

// The refusal above must not catch the ordinary case. -kill-switch on its own is
// the configuration the flag exists for, and a check that rejects it too would
// be found only by someone trying to use the feature.
func TestKillSwitchAloneIsAccepted(t *testing.T) {
	fs := newTestFlagSet()
	n := bindNetFlags(fs)
	if err := fs.Parse([]string{"-kill-switch"}); err != nil {
		t.Fatal(err)
	}
	if err := n.resolve(fs); err != nil {
		t.Fatalf("-kill-switch alone was refused: %v", err)
	}
	if !n.killSwitch {
		t.Error("-kill-switch did not survive resolve")
	}
}
