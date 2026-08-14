package main

import (
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
)

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

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
