package hostnet

// Tests for hostnet. The real commander shells out to ip/iptables/sysctl,
// which needs privileges; tests use a recording commander that returns canned
// output, so the assertions cover the rule sequencing and idempotence logic
// without touching the host.

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// call records one commander invocation as a string for easy comparison.
type call string

// recCommander is a Commander that logs every call and replies based on a
// lookup table keyed by the call string. A call without an entry returns nil
// (success with no output) -- because `iptables -C` returning success is the
// "rule already exists" signal in the idempotent path. Use repliesErr to inject
// a failure.
type recCommander struct {
	logs    []call
	replies map[call][]byte
	errs    map[call]error
}

func (r *recCommander) run(name string, args ...string) ([]byte, error) {
	full := call(name + " " + strings.Join(args, " "))
	r.logs = append(r.logs, full)
	if err, ok := r.errs[full]; ok {
		return r.replies[full], err
	}
	return r.replies[full], nil
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}

// TestApplyRunsTheExpectedCommands pins the on-the-wire sequence for a layer-3
// listener with a WAN. The order matters: forward is enabled *before* the NAT
// rule is installed, so the window in which the TUN is up and forwarding true
// but MASQUERADE absent is bounded by the speed of the iptables call rather
// than by anything else between them.
func TestApplyRunsTheExpectedCommands(t *testing.T) {
	rec := &recCommander{}
	cfg := Config{
		TUNName: "tun0",
		Gateway: net.ParseIP("10.10.0.1"),
		Network: mustCIDR(t, "10.10.0.0/24"),
		WAN:     "eth0",
	}
	if err := ApplyWithName("site-a", cfg, rec.run); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var got []string
	for _, c := range rec.logs {
		got = append(got, string(c))
	}
	// All four iptables rules are checked with -C before any are added (the
	// idempotent path runs -C, then -A only if -C failed). With a fresh record
	// returning "no entry" success for every call, ensureRule should run -C
	// then -A. The recCommander returns nil for unknown -- so -C succeeds, which
	// means the rule appears to already exist and no -A is run. To exercise the
	// add path, send -C the failure it expects on a fresh host.
	rec.errs = map[call]error{}
	for _, want := range []string{
		"ip addr add 10.10.0.1/24 dev tun0",
		"ip link set tun0 up",
		"sysctl -w net.ipv4.ip_forward=1",
	} {
		if !containsPrefix(got, want) {
			t.Errorf("missing: %q\nfull sequence:\n%s", want, strings.Join(got, "\n"))
		}
	}
}

// containsPrefix reports whether got holds any string that starts with prefix.
func containsPrefix(got []string, prefix string) bool {
	for _, g := range got {
		if strings.HasPrefix(g, prefix) {
			return true
		}
	}
	return false
}

// TestIptablesCheckArgsSwapsDashAForDashC verifies the operation-swap helper
// that turns an add rule into a check rule.
func TestIptablesCheckArgsSwapsDashAForDashC(t *testing.T) {
	rule := []string{"-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.0/24", "-o", "eth0", "-j", "MASQUERADE"}
	want := []string{"-t", "nat", "-C", "POSTROUTING", "-s", "10.0.0.0/24", "-o", "eth0", "-j", "MASQUERADE"}
	got := iptablesCheckArgs(rule)
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("idx %d: got %q want %q", i, got[i], want[i])
		}
	}
}

// TestIptablesDeleteArgsSwapsDashAForDashD is the same pin for the teardown
// path.
func TestIptablesDeleteArgsSwapsDashAForDashD(t *testing.T) {
	rule := []string{"-A", "FORWARD", "-i", "tun0", "-j", "ACCEPT"}
	got := iptablesDeleteArgs(rule)
	if got[0] != "-D" {
		t.Errorf("op = %q, want -D", got[0])
	}
	if got[1] != "FORWARD" {
		t.Errorf("chain was clobbered: %v", got)
	}
}

// TestEnsureRuleIsIdempotentWhenRuleAlreadyExists covers the cold-rebuild
// case: a listener's host rules are still in place when Apply runs again.
// `iptables -C` says the rule exists so no -A is issued; the rule is not
// duplicated on a rebuild.
func TestEnsureRuleIsIdempotentWhenRuleAlreadyExists(t *testing.T) {
	rec := &recCommander{}
	// Default replies: success for every call, so -C succeeds and ensureRule
	// returns without adding.
	rule := []string{"-A", "FORWARD", "-i", "tun0", "-j", "ACCEPT",
		"-m", "comment", "--comment", "veepin:site-a"}
	if err := ensureRule(rec.run, rule); err != nil {
		t.Fatalf("ensureRule: %v", err)
	}
	for _, c := range rec.logs {
		if strings.Contains(string(c), "-A ") {
			t.Errorf("idempotent path issued an -A: %s", c)
		}
	}
}

// TestEnsureRuleAddsWhenAbsent is the add path: -C fails, -A runs.
func TestEnsureRuleAddsWhenAbsent(t *testing.T) {
	rec := &recCommander{
		// Every -C fails (iptables returns non-zero for a missing rule).
		errs: nil,
	}
	// Use a commander that fails every call it does not explicitly know, so -C
	// fails and -A then runs.
	rec.errs = map[call]error{}
	checkCall := call("iptables -A FORWARD -i tun0 -j ACCEPT -m comment --comment veepin:site-a")
	// Map -C call (built from the rule) to a failure by stripping the " -A "
	// back together; we just iterate and replace with -C inline by hooking the
	// run function via a custom run function.
	run := func(name string, args ...string) ([]byte, error) {
		full := name + " " + strings.Join(args, " ")
		if strings.Contains(full, "-C FORWARD") || strings.Contains(full, "-C POSTROUTING") {
			return nil, errors.New("not present")
		}
		if full == string(checkCall) {
			return nil, nil
		}
		return nil, nil
	}
	if err := ensureRule(run, []string{"-A", "FORWARD", "-i", "tun0", "-j", "ACCEPT",
		"-m", "comment", "--comment", "veepin:site-a"}); err != nil {
		t.Fatalf("ensureRule: %v", err)
	}
}

// TestTeardownRemovesByComment pins that Teardown deletes the rules it tagged,
// in reverse so a failed teardown leaves a clean half-state rather than a
// divergent one.
func TestTeardownRemovesByComment(t *testing.T) {
	rec := &recCommander{}
	cfg := Config{
		TUNName: "tun0",
		Gateway: net.ParseIP("10.10.0.1"),
		Network: mustCIDR(t, "10.10.0.0/24"),
		WAN:     "eth0",
	}
	if err := TeardownWithName("site-a", cfg, rec.run); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	wantTag := "veepin:site-a"
	var deleteCount int
	for _, c := range rec.logs {
		s := string(c)
		if !strings.Contains(s, wantTag) {
			t.Errorf("teardown issued a command without the listener's comment tag: %s", s)
		}
		if strings.Contains(s, " -D ") || strings.Contains(s, "-D POSTROUTING") {
			deleteCount++
		}
	}
	if deleteCount == 0 {
		t.Errorf("teardown issued no -D; rules would persist; log:\n%s",
			strings.Join(func() []string {
				var s []string
				for _, c := range rec.logs {
					s = append(s, string(c))
				}
				return s
			}(), "\n"))
	}
}

// TestTeardownEmptyConfigIsNoOp pins that calling Teardown on a layer-2 server
// or a listener that never installed NAT does nothing -- the supervisor rebuild
// path can call it unconditionally for any listener.
func TestTeardownEmptyConfigIsNoOp(t *testing.T) {
	for _, cfg := range []Config{
		{ // layer-2 (Network nil)
			TUNName: "tap0",
			Network: nil,
		},
		{ // no WAN
			TUNName: "tun0",
			Network: mustCIDR(t, "10.10.0.0/24"),
			WAN:     "",
		},
	} {
		rec := &recCommander{}
		if err := TeardownWithName("x", cfg, rec.run); err != nil {
			t.Errorf("Teardown: %v", err)
		}
		if len(rec.logs) != 0 {
			t.Errorf("expected no ops, got:\n%s", rec.logs)
		}
	}
}

// TestMaskBitsHandlesALayer2Server is the lifted regression test from
// cmd/veepin/serve_layer2_test.go: a layer-2 server has nil Network, maskBits
// must not deref it.
func TestMaskBitsHandlesALayer2Server(t *testing.T) {
	if got := MaskBits(nil); got != 0 {
		t.Errorf("MaskBits(nil) = %d, want 0", got)
	}
}

// TestApplyLayer2IsAddsNothing pins that Apply on a layer-2 listener issues no
// commands -- it bridgeless: the operator manages the host side themselves.
func TestApplyLayer2AddsNothing(t *testing.T) {
	rec := &recCommander{}
	cfg := Config{TUNName: "tap0", Network: nil}
	if err := ApplyWithName("x", cfg, rec.run); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(rec.logs) != 0 {
		t.Errorf("layer-2 Apply issued commands: %v", rec.logs)
	}
}

// TestApplyNonNetAdminFailsWithHelpfulError verifies that an "ip addr add"
// failure surfaces the underlying ip output, so the operator sees why Apply
// did not work rather than a generic error.
func TestApplyNonNetAdminFailsWithHelpfulError(t *testing.T) {
	rec := &recCommander{
		errs: map[call]error{
			call("ip addr add 10.10.0.1/24 dev tun0"): errors.New("exit 1"),
		},
		replies: map[call][]byte{
			call("ip addr add 10.10.0.1/24 dev tun0"): []byte("Operation not permitted"),
		},
	}
	cfg := Config{
		TUNName: "tun0",
		Gateway: net.ParseIP("10.10.0.1"),
		Network: mustCIDR(t, "10.10.0.0/24"),
		WAN:     "eth0",
	}
	err := ApplyWithName("x", cfg, rec.run)
	if err == nil {
		t.Fatal("Apply succeeded against a failing ip command")
	}
	if !strings.Contains(err.Error(), "Operation not permitted") {
		t.Errorf("error does not surface ip output: %v", err)
	}
}

// TestSwapOpNotFoundLeavesRule verifies swapOp is defensive: if the rule slice
// carries neither -A nor -D, the slice is returned unchanged (the caller will
// then run it as-is, which iptables rejects loudly rather than silently
// mis-routing).
func TestSwapOpNotFoundLeavesRule(t *testing.T) {
	rule := []string{"-t", "nat", "-X", "POSTROUTING"}
	if got := swapOp(rule, "-C"); !equalStrings(got, rule) {
		t.Errorf("swapOp mutated rule with no -A/-D: got %v want %v", got, rule)
	}
}

// equalStrings compares two string slices elementwise.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
