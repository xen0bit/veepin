package dataplane

import (
	"net"
	"slices"
	"strings"
	"testing"
)

// The four prefixes, per family, exactly mirroring what ClientRouter installs
// for a full tunnel. Two /1s rather than one /0 is the whole mechanism: at the
// same specificity as the routes being replaced, the physical default is never
// the most specific match again. A /0 blackhole would lose to it.
func TestKillSwitchMirrorsTheRoutesItReplaces(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  KillSwitchConfig
		want []string
	}{
		{"v4 only", KillSwitchConfig{V4: true}, []string{"0.0.0.0/1", "128.0.0.0/1"}},
		{"v6 only", KillSwitchConfig{V6: true}, []string{"::/1", "8000::/1"}},
		{"dual stack", KillSwitchConfig{V4: true, V6: true},
			[]string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}},
		{"neither", KillSwitchConfig{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := NewKillSwitch(tc.cfg)
			var got []string
			for _, h := range k.halves() {
				got = append(got, h.prefix)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("halves = %v, want %v", got, tc.want)
			}
		})
	}
}

// The metric is the mechanism. Without it the blackhole and the tunnel's own
// route are the same route, so the switch could not be armed while the tunnel
// is healthy -- and arming it on teardown instead leaves however long that
// takes as plaintext.
func TestKillSwitchRoutesCarryAWorseMetricThanTheTunnels(t *testing.T) {
	k := NewKillSwitch(KillSwitchConfig{V4: true, V6: true})
	for _, h := range k.halves() {
		cmd := strings.Join(h.add(), " ")
		if !strings.Contains(cmd, "metric "+killSwitchMetric) {
			t.Errorf("%q carries no metric; it would collide with the tunnel's own route", cmd)
		}
		if !strings.Contains(cmd, "blackhole") {
			t.Errorf("%q is not a blackhole", cmd)
		}
	}
	if killSwitchMetric == "0" {
		t.Fatal("the kill switch metric is 0, which is the tunnel's own; the two would collide")
	}
}

// The v6 halves must go through `ip -6`. Sending "::/1" to the v4 command is
// the kind of mistake that produces a half-closed host whose state nobody can
// read off `ip route`.
func TestKillSwitchUsesTheRightFamilysCommand(t *testing.T) {
	k := NewKillSwitch(KillSwitchConfig{V4: true, V6: true})
	for _, h := range k.halves() {
		cmd := strings.Join(h.add(), " ")
		wantV6 := strings.Contains(h.prefix, ":")
		gotV6 := strings.HasPrefix(cmd, "ip -6 ")
		if wantV6 != gotV6 {
			t.Errorf("%q: family mismatch for prefix %s", cmd, h.prefix)
		}
	}
}

// A kill switch with no way back is a brick, not a switch: a /1 blackhole
// covers the VPN server too, so without a carve-out the re-dial could never
// reach it. Engage refuses rather than delivering that.
func TestKillSwitchRefusesToEngageWithNoServerToKeepReachable(t *testing.T) {
	k := NewKillSwitch(KillSwitchConfig{V4: true})
	err := k.Engage()
	if err == nil {
		t.Fatal("engaged with no server address; the host could never reconnect")
	}
	if !strings.Contains(err.Error(), "no single peer") {
		t.Errorf("error does not say why: %v", err)
	}
	if k.Engaged() {
		t.Error("a refused Engage reports itself engaged")
	}
}

// The recovery command is what an operator types into a console when veepin
// died without running its defers, so it has to be the actual inverse of what
// was installed -- same prefixes, same metric, and runnable as printed.
func TestRecoveryCommandUndoesExactlyWhatWasInstalled(t *testing.T) {
	k := NewKillSwitch(KillSwitchConfig{ServerIP: net.ParseIP("192.0.2.10"), V4: true, V6: true})
	got := k.RecoveryCommand()
	for _, h := range k.halves() {
		want := "sudo " + strings.Join(h.del(), " ")
		if !strings.Contains(got, want) {
			t.Errorf("recovery command does not include %q\ngot: %s", want, got)
		}
	}
	if strings.Contains(got, " add ") {
		t.Errorf("recovery command installs rather than removes: %s", got)
	}
}

// Disengage on a switch that never engaged must be safe: it is reached from a
// defer that also runs on the paths where Engage was refused.
func TestDisengageIsSafeBeforeEngage(t *testing.T) {
	k := NewKillSwitch(KillSwitchConfig{ServerIP: net.ParseIP("192.0.2.10")})
	if err := k.Disengage(); err != nil {
		t.Errorf("Disengage before Engage: %v", err)
	}
	if k.Engaged() {
		t.Error("Disengage left the switch reporting itself engaged")
	}
}
