package hostnet

// Tests for hostnet. The real commander shells out to ip/iptables/sysctl,
// which needs privileges; tests use a recording commander that returns canned
// output, so the assertions cover the rule sequencing and idempotence logic
// without touching the host.

import (
	"errors"
	"net"
	"net/netip"
	"slices"
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
// It also has to check the iptables calls, and used to check none: the fake
// answered every -C successfully, so every rule looked already-installed and no
// -A was ever issued. The test then asserted three `ip`/`sysctl` lines and
// returned, and would have passed against an Apply that installed no firewall
// rules at all. The -C calls now fail, which is what a fresh host does.
func TestApplyRunsTheExpectedCommands(t *testing.T) {
	rec := &recCommander{errs: map[call]error{}}
	cfg := Config{
		TUNName: "tun0",
		Gateway: net.ParseIP("10.10.0.1"),
		Network: mustCIDR(t, "10.10.0.0/24"),
		WAN:     "eth0",
	}
	// Every -C fails, as it does on a host that has none of our rules yet, so
	// ensureRule takes the -A path and this test can see it.
	run := func(name string, args ...string) ([]byte, error) {
		if slices.Contains(args, "-C") {
			rec.logs = append(rec.logs, call(name+" "+strings.Join(args, " ")))
			return nil, errors.New("no such rule")
		}
		return rec.run(name, args...)
	}
	if err := ApplyWithName("site-a", cfg, run); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var got []string
	for _, c := range rec.logs {
		got = append(got, string(c))
	}
	for _, want := range []string{
		"ip addr add 10.10.0.1/24 dev tun0",
		"ip link set tun0 up",
		"sysctl -w net.ipv4.ip_forward=1",
		"iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE",
		"iptables -A FORWARD -i tun0 -j ACCEPT",
		"iptables -A FORWARD -o tun0 -j ACCEPT",
	} {
		if !containsPrefix(got, want) {
			t.Errorf("missing: %q\nfull sequence:\n%s", want, strings.Join(got, "\n"))
		}
	}
	// The ordering claim in this test's own name. Forwarding is enabled before
	// the NAT rule is installed, so the window where the TUN is up and
	// forwarding on but MASQUERADE absent is bounded by one iptables call.
	// containsPrefix is order-blind, so the claim went unchecked.
	forwardAt := indexOfPrefix(got, "sysctl -w net.ipv4.ip_forward=1")
	masqAt := indexOfPrefix(got, "iptables -t nat -A POSTROUTING")
	if forwardAt < 0 || masqAt < 0 || forwardAt > masqAt {
		t.Errorf("forwarding is enabled at %d and MASQUERADE installed at %d; forwarding must come first\n%s",
			forwardAt, masqAt, strings.Join(got, "\n"))
	}
	// Every rule we install carries our tag, or teardown cannot find it.
	for _, g := range got {
		if strings.Contains(g, "iptables") && slices.Contains(strings.Fields(g), "-A") &&
			!strings.Contains(g, "veepin:site-a") {
			t.Errorf("an installed rule carries no teardown tag: %s", g)
		}
	}
}

// indexOfPrefix returns the position of the first string starting with prefix,
// or -1.
func indexOfPrefix(got []string, prefix string) int {
	for i, g := range got {
		if strings.HasPrefix(g, prefix) {
			return i
		}
	}
	return -1
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
	if err := ensureRule(rec.run, "iptables", rule); err != nil {
		t.Fatalf("ensureRule: %v", err)
	}
	for _, c := range rec.logs {
		if strings.Contains(string(c), "-A ") {
			t.Errorf("idempotent path issued an -A: %s", c)
		}
	}
}

// TestEnsureRuleAddsWhenAbsent is the add path: -C fails, -A runs.
//
// It used to assert only err == nil, and built a `checkCall` variable it never
// compared against anything -- so an ensureRule that issued no command at all
// passed. Both halves of the claim are checked now: the -C happens, and the -A
// follows it.
func TestEnsureRuleAddsWhenAbsent(t *testing.T) {
	rule := []string{"-A", "FORWARD", "-i", "tun0", "-j", "ACCEPT",
		"-m", "comment", "--comment", "veepin:site-a"}
	var issued []string
	run := func(name string, args ...string) ([]byte, error) {
		issued = append(issued, name+" "+strings.Join(args, " "))
		if slices.Contains(args, "-C") {
			return nil, errors.New("not present")
		}
		return nil, nil
	}
	if err := ensureRule(run, "iptables", rule); err != nil {
		t.Fatalf("ensureRule: %v", err)
	}
	want := []string{
		"iptables -C FORWARD -i tun0 -j ACCEPT -m comment --comment veepin:site-a",
		"iptables -A FORWARD -i tun0 -j ACCEPT -m comment --comment veepin:site-a",
	}
	if !slices.Equal(issued, want) {
		t.Errorf("issued:\n%s\nwant:\n%s", strings.Join(issued, "\n"), strings.Join(want, "\n"))
	}
}

// TestEnsureRuleAddsNothingWhenPresent is the other half, and the one that
// makes the test above mean something: when -C succeeds the rule is already
// installed and no -A may follow, or every reconcile would stack duplicates.
func TestEnsureRuleAddsNothingWhenPresent(t *testing.T) {
	var issued []string
	run := func(name string, args ...string) ([]byte, error) {
		issued = append(issued, name+" "+strings.Join(args, " "))
		return nil, nil // -C succeeds: the rule is there
	}
	if err := ensureRule(run, "iptables", []string{"-A", "FORWARD", "-i", "tun0", "-j", "ACCEPT"}); err != nil {
		t.Fatalf("ensureRule: %v", err)
	}
	if len(issued) != 1 || !strings.Contains(issued[0], "-C") {
		t.Errorf("expected exactly one -C and no -A, got:\n%s", strings.Join(issued, "\n"))
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

// TestTeardownStateRemovesWhatTheConfigNoLongerSays: the persisted State, not
// the current config, is what teardown removes. A supervisor listener whose
// config was edited after Apply (WAN dropped, address changed) or whose TUN
// name the kernel assigned still has its originally-installed rules taken out
// when it stops. This is the regression pin for the supervisor's no-op teardown:
// re-deriving from a config with nil Network made Teardown return early and
// leave every tagged rule behind.
func TestTeardownStateRemovesWhatTheConfigNoLongerSays(t *testing.T) {
	rec := &recCommander{}
	st := State{TUNName: "tun3", WAN: "eth0", Network: "10.10.0.0/24"}
	if err := TeardownStateWithName("site-a", st, rec.run); err != nil {
		t.Fatalf("TeardownState: %v", err)
	}
	wantTag := "veepin:site-a"
	var got []string
	for _, c := range rec.logs {
		got = append(got, string(c))
	}
	if len(got) == 0 {
		t.Fatal("no teardown commands issued for a recorded State")
	}
	for _, want := range []string{
		"-o eth0", "-s 10.10.0.0/24", "-i tun3", "-o tun3", wantTag,
	} {
		if !strings.Contains(strings.Join(got, " "), want) {
			t.Errorf("teardown from State omitted %q; ran:\n%s", want, strings.Join(got, "\n"))
		}
	}
}

// TestTeardownStateEmptyIsNoOp pins that a State with no WAN or no Network
// removes nothing -- the layer-2 path and the no-WAN path both land here, and
// the supervisor calls teardown unconditionally.
func TestTeardownStateEmptyIsNoOp(t *testing.T) {
	for _, st := range []State{
		{TUNName: "tap0", Network: ""},                    // layer-2
		{TUNName: "tun0", WAN: "", Network: "10.0.0.0/8"}, // no WAN
	} {
		rec := &recCommander{}
		if err := TeardownStateWithName("x", st, rec.run); err != nil {
			t.Errorf("TeardownState: %v", err)
		}
		if len(rec.logs) != 0 {
			t.Errorf("expected no ops for %+v, got:\n%s", st, rec.logs)
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

// TestApplyLayer2BringsTheLinkUpAndNothingElse pins the layer-2 (L2TPv3) path.
// There is no tunnel subnet, so there is no address to assign and no NAT to
// install -- the operator owns bridging and addressing. The interface still has
// to come up, or the pseudowire carries nothing. An earlier version returned
// before the link-up and left the interface DOWN while reporting success.
func TestApplyLayer2BringsTheLinkUpAndNothingElse(t *testing.T) {
	rec := &recCommander{}
	cfg := Config{TUNName: "tap0", Network: nil}
	if err := ApplyWithName("x", cfg, rec.run); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := []call{"ip link set tap0 up"}
	if len(rec.logs) != len(want) || rec.logs[0] != want[0] {
		t.Errorf("layer-2 Apply ran %v, want exactly %v", rec.logs, want)
	}
}

// TestApplyLayer2ReportsAFailedLinkUp: the one command the layer-2 path does run
// must not fail silently, or the listener serves over an interface that is down.
func TestApplyLayer2ReportsAFailedLinkUp(t *testing.T) {
	rec := &recCommander{
		errs:    map[call]error{call("ip link set tap0 up"): errors.New("exit 1")},
		replies: map[call][]byte{call("ip link set tap0 up"): []byte("Operation not permitted")},
	}
	err := ApplyWithName("x", Config{TUNName: "tap0"}, rec.run)
	if err == nil {
		t.Fatal("Apply succeeded against a failing ip link")
	}
	if !strings.Contains(err.Error(), "Operation not permitted") {
		t.Errorf("error does not surface ip output: %v", err)
	}
}

// TestApplyWithoutWANReportsErrNoWAN pins the contract the supervisor depends on:
// a listener with a tunnel subnet but no WAN is configured and forwarding, but
// has no route off the host. That is worth reporting -- an operator must not be
// told a tunnel reaches the internet when it does not -- and it must be
// recognisable, because it is not a reason to refuse to serve. Before ErrNoWAN
// it was an opaque error, and one such listener aborted the whole fleet's Apply.
func TestApplyWithoutWANReportsErrNoWAN(t *testing.T) {
	rec := &recCommander{}
	cfg := Config{
		TUNName: "tun0",
		Gateway: net.ParseIP("10.10.0.1"),
		Network: mustCIDR(t, "10.10.0.0/24"),
	}
	err := ApplyWithName("site-a", cfg, rec.run)
	if !errors.Is(err, ErrNoWAN) {
		t.Fatalf("Apply without a WAN returned %v, want ErrNoWAN", err)
	}
	// The address and link-up still happened: the failure is only about NAT.
	var got []string
	for _, c := range rec.logs {
		got = append(got, string(c))
	}
	for _, want := range []string{"ip addr add 10.10.0.1/24 dev tun0", "ip link set tun0 up"} {
		if !containsPrefix(got, want) {
			t.Errorf("missing %q; ran:\n%s", want, strings.Join(got, "\n"))
		}
	}
	for _, g := range got {
		if strings.HasPrefix(g, "iptables") {
			t.Errorf("no WAN was named but an iptables rule was installed: %q", g)
		}
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
	if got := swapOp(rule, "-C"); !slices.Equal(got, rule) {
		t.Errorf("swapOp mutated rule with no -A/-D: got %v want %v", got, rule)
	}
}

// equalStrings compares two string slices elementwise.
// TestTaggedTeardownDeletesRulesItFindsInRealIptablesOutput: the tagged teardown
// is the recovery path -- it runs when the persisted state file is gone, which
// is exactly the case the state file was added to survive. It rebuilt its -D
// arguments from raw `iptables -S` fields, and -S prints the comment QUOTED:
//
//	-A POSTROUTING -o eth0 -m comment --comment "veepin:site-a" -j MASQUERADE
//
// There is no shell between here and execve, so the literal quote characters
// reached iptables, which then found no rule with that comment. Every -D failed,
// the loop returned on the first, and the MASQUERADE plus both FORWARD rules
// stayed on the host forever. The only test that touched this path fed unquoted
// comments -- a format iptables never produces -- so it could not see it.
func TestTaggedTeardownDeletesRulesItFindsInRealIptablesOutput(t *testing.T) {
	natRules := `-P POSTROUTING ACCEPT
-A POSTROUTING -s 10.0.0.0/24 -o eth0 -m comment --comment "veepin:site-a" -j MASQUERADE
-A POSTROUTING -s 10.9.0.0/24 -o eth0 -m comment --comment "veepin:other" -j MASQUERADE
`
	filterRules := `-P FORWARD DROP
-A FORWARD -i veepin0 -o eth0 -m comment --comment "veepin:site-a" -j ACCEPT
`
	// The v6 chains carry one tagged rule of their own, so this also pins that
	// the recovery sweep looks at both families: it cannot know which the
	// listener used, because losing that is what put it on this path.
	natRules6 := `-P POSTROUTING ACCEPT
-A POSTROUTING -s fd00:10:10::/64 -o eth0 -m comment --comment "veepin:site-a" -j MASQUERADE
`
	var deletes [][]string
	var sawBin []string
	run := func(name string, args ...string) ([]byte, error) {
		if len(args) >= 3 && args[2] == "-S" {
			switch {
			case name == "ip6tables" && args[1] == "nat":
				return []byte(natRules6), nil
			case name == "ip6tables":
				return nil, nil // no tagged FORWARD rules on the v6 side
			case args[1] == "nat":
				return []byte(natRules), nil
			case args[1] == "filter":
				return []byte(filterRules), nil
			}
		}
		if slices.Contains(args, "-D") {
			deletes = append(deletes, slices.Clone(args))
			sawBin = append(sawBin, name)
		}
		return nil, nil
	}

	if err := teardownByTagWith("site-a", run); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if len(deletes) != 3 {
		t.Fatalf("deleted %d rules, want the 3 tagged veepin:site-a across both families: %v",
			len(deletes), deletes)
	}
	if !slices.Contains(sawBin, "ip6tables") {
		t.Error("no v6 rule was deleted, so a dual-stack listener leaves its ip6tables " +
			"rules on the host when its recorded state is lost")
	}
	for _, args := range deletes {
		for _, a := range args {
			if strings.Contains(a, `"`) {
				t.Errorf("a delete argument still carries a literal quote, which matches no installed rule: %q in %v", a, args)
			}
		}
		if !slices.Contains(args, "veepin:site-a") {
			t.Errorf("delete does not carry the unquoted tag: %v", args)
		}
		if slices.Contains(args, "veepin:other") {
			t.Errorf("delete touched another listener's rule: %v", args)
		}
	}
}

// TestApplyConfiguresBothFamiliesForADualStackListener.
//
// ikev2's server has always been able to hand a client an IPv6 address from its
// own pool through config mode, and Gateway6/Network6 were documented as being
// "for routing and NAT rules" while having no caller anywhere in the tree. The
// consequences were both invisible from inside the tunnel: the v6 gateway never
// reached the interface, so the server could not answer a ping to its own
// tunnel address, and a client's v6 traffic arrived at a host that would not
// forward it.
func TestApplyConfiguresBothFamiliesForADualStackListener(t *testing.T) {
	rec := &recCommander{errs: map[call]error{}}
	cfg := Config{
		TUNName:  "tun0",
		Gateway:  net.ParseIP("10.10.0.1"),
		Network:  mustCIDR(t, "10.10.0.0/24"),
		Gateway6: netip.MustParseAddr("fd00:10:10::1"),
		Network6: netip.MustParsePrefix("fd00:10:10::/64"),
		WAN:      "eth0",
	}
	run := func(name string, args ...string) ([]byte, error) {
		if slices.Contains(args, "-C") {
			rec.logs = append(rec.logs, call(name+" "+strings.Join(args, " ")))
			return nil, errors.New("no such rule")
		}
		return rec.run(name, args...)
	}
	if err := ApplyWithName("site-a", cfg, run); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var got []string
	for _, c := range rec.logs {
		got = append(got, string(c))
	}
	for _, want := range []string{
		"ip addr add 10.10.0.1/24 dev tun0",
		"ip -6 addr add fd00:10:10::1/64 dev tun0",
		"sysctl -w net.ipv4.ip_forward=1",
		"sysctl -w net.ipv6.conf.all.forwarding=1",
		"iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE",
		"ip6tables -t nat -A POSTROUTING -s fd00:10:10::/64 -o eth0 -j MASQUERADE",
		"ip6tables -A FORWARD -i tun0 -j ACCEPT",
		"ip6tables -A FORWARD -o tun0 -j ACCEPT",
	} {
		if !containsPrefix(got, want) {
			t.Errorf("missing: %q\nfull sequence:\n%s", want, strings.Join(got, "\n"))
		}
	}
	// Same ordering claim as the v4 test, for the same reason.
	fwd6 := indexOfPrefix(got, "sysctl -w net.ipv6.conf.all.forwarding=1")
	masq6 := indexOfPrefix(got, "ip6tables -t nat -A POSTROUTING")
	if fwd6 < 0 || masq6 < 0 || fwd6 > masq6 {
		t.Errorf("v6 forwarding enabled at %d, v6 MASQUERADE at %d; forwarding must come first\n%s",
			fwd6, masq6, strings.Join(got, "\n"))
	}
	for _, g := range got {
		if strings.Contains(g, "tables") && slices.Contains(strings.Fields(g), "-A") &&
			!strings.Contains(g, "veepin:site-a") {
			t.Errorf("an installed rule carries no teardown tag: %s", g)
		}
	}
}

// TestAV4OnlyListenerNeverNamesIp6tables. A host that has no ip6tables at all
// must be unaffected by this package unless a listener actually hands out v6
// addresses -- otherwise adding the v6 half would break every existing
// deployment that never asked for it.
func TestAV4OnlyListenerNeverNamesIp6tables(t *testing.T) {
	rec := &recCommander{errs: map[call]error{}}
	cfg := Config{
		TUNName: "tun0",
		Gateway: net.ParseIP("10.10.0.1"),
		Network: mustCIDR(t, "10.10.0.0/24"),
		WAN:     "eth0",
	}
	run := func(name string, args ...string) ([]byte, error) {
		if slices.Contains(args, "-C") {
			rec.logs = append(rec.logs, call(name+" "+strings.Join(args, " ")))
			return nil, errors.New("no such rule")
		}
		return rec.run(name, args...)
	}
	if err := ApplyWithName("site-a", cfg, run); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, c := range rec.logs {
		if strings.HasPrefix(string(c), "ip6tables") || strings.Contains(string(c), "ipv6") {
			t.Errorf("a v4-only listener touched IPv6 state: %s", c)
		}
	}
}

// TestTeardownRemovesBothFamiliesInReverse. The recorded State carries the v6
// subnet separately so a listener that gained or lost its v6 pool since Apply
// still tears down what was actually installed -- the reason State exists.
func TestTeardownRemovesBothFamiliesInReverse(t *testing.T) {
	var deletes []string
	run := func(name string, args ...string) ([]byte, error) {
		joined := name + " " + strings.Join(args, " ")
		if slices.Contains(args, "-D") {
			deletes = append(deletes, joined)
		}
		return nil, nil // -C succeeds, so every rule is found and removed once
	}
	st := State{
		TUNName:  "tun0",
		WAN:      "eth0",
		Network:  "10.10.0.0/24",
		Network6: "fd00:10:10::/64",
	}
	if err := TeardownStateWithName("site-a", st, run); err != nil {
		t.Fatalf("TeardownState: %v", err)
	}
	if !containsPrefix(deletes, "ip6tables -t nat -D POSTROUTING -s fd00:10:10::/64") {
		t.Errorf("the v6 MASQUERADE was not removed:\n%s", strings.Join(deletes, "\n"))
	}
	if !containsPrefix(deletes, "iptables -t nat -D POSTROUTING -s 10.10.0.0/24") {
		t.Errorf("the v4 MASQUERADE was not removed:\n%s", strings.Join(deletes, "\n"))
	}
	v6At := indexOfPrefix(deletes, "ip6tables -t nat -D POSTROUTING")
	v4At := indexOfPrefix(deletes, "iptables -t nat -D POSTROUTING")
	if v6At > v4At {
		t.Errorf("v4 was torn down at %d before v6 at %d; teardown must reverse apply's order\n%s",
			v4At, v6At, strings.Join(deletes, "\n"))
	}
}

// TestTeardownOfAV4OnlyStateLeavesIp6tablesAlone is the teardown half of
// TestAV4OnlyListenerNeverNamesIp6tables.
func TestTeardownOfAV4OnlyStateLeavesIp6tablesAlone(t *testing.T) {
	var issued []string
	run := func(name string, args ...string) ([]byte, error) {
		issued = append(issued, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	st := State{TUNName: "tun0", WAN: "eth0", Network: "10.10.0.0/24"}
	if err := TeardownStateWithName("site-a", st, run); err != nil {
		t.Fatalf("TeardownState: %v", err)
	}
	for _, c := range issued {
		if strings.HasPrefix(c, "ip6tables") {
			t.Errorf("a v4-only teardown named ip6tables: %s", c)
		}
	}
}

// TestStateRecordsTheV6SubnetSeparately. Teardown is driven by the State, so a
// v6 subnet that never reaches it is a rule that stays on the host forever.
func TestStateRecordsTheV6SubnetSeparately(t *testing.T) {
	cfg := Config{
		TUNName:  "tun0",
		Network:  mustCIDR(t, "10.10.0.0/24"),
		Network6: netip.MustParsePrefix("fd00:10:10::/64"),
		WAN:      "eth0",
	}
	st := cfg.State()
	if st.Network != "10.10.0.0/24" {
		t.Errorf("State.Network = %q", st.Network)
	}
	if st.Network6 != "fd00:10:10::/64" {
		t.Errorf("State.Network6 = %q, want the v6 subnet: without it the v6 "+
			"MASQUERADE outlives the listener", st.Network6)
	}
}

// TestAHostWithoutIp6tablesStillServesV4.
//
// ikev2's v6 pool is on by DEFAULT -- NewServer fills Pool6 with
// fd00:10:10::/64 when the option is unset -- so every ikev2 listener asks this
// package for v6. Treating a missing ip6tables as fatal would therefore stop
// every existing v4 deployment on a v6-less host from serving at all, over a
// capability its operator never asked for.
func TestAHostWithoutIp6tablesStillServesV4(t *testing.T) {
	var issued []string
	run := func(name string, args ...string) ([]byte, error) {
		issued = append(issued, name+" "+strings.Join(args, " "))
		if name == "ip6tables" {
			return []byte("ip6tables: command not found"), errors.New("exec: not found")
		}
		if slices.Contains(args, "-C") {
			return nil, errors.New("no such rule")
		}
		return nil, nil
	}
	cfg := Config{
		TUNName:  "tun0",
		Gateway:  net.ParseIP("10.10.0.1"),
		Network:  mustCIDR(t, "10.10.0.0/24"),
		Gateway6: netip.MustParseAddr("fd00:10:10::1"),
		Network6: netip.MustParsePrefix("fd00:10:10::/64"),
		WAN:      "eth0",
	}
	err := ApplyWithName("site-a", cfg, run)
	if !errors.Is(err, ErrNoIPv6) {
		t.Fatalf("Apply = %v, want ErrNoIPv6 so the caller can log and carry on", err)
	}
	// The v4 half must be fully installed regardless.
	for _, want := range []string{
		"ip addr add 10.10.0.1/24 dev tun0",
		"ip link set tun0 up",
		"sysctl -w net.ipv4.ip_forward=1",
		"iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE",
	} {
		if !containsPrefix(issued, want) {
			t.Errorf("the v4 half is incomplete, missing: %q\n%s", want, strings.Join(issued, "\n"))
		}
	}
	// And no v6 address was put on the interface, since the host cannot route it.
	if containsPrefix(issued, "ip -6 addr add") {
		t.Error("a v6 address was assigned on a host that cannot forward or NAT it")
	}
}

// TestNoWANAndNoIPv6ReportsBoth. Each is "configured, but does not reach
// everything", and a caller testing errors.Is for either must still find it.
func TestNoWANAndNoIPv6ReportsBoth(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		if name == "ip6tables" {
			return nil, errors.New("exec: not found")
		}
		return nil, nil
	}
	cfg := Config{
		TUNName:  "tun0",
		Gateway:  net.ParseIP("10.10.0.1"),
		Network:  mustCIDR(t, "10.10.0.0/24"),
		Gateway6: netip.MustParseAddr("fd00:10:10::1"),
		Network6: netip.MustParsePrefix("fd00:10:10::/64"),
		// No WAN.
	}
	err := ApplyWithName("site-a", cfg, run)
	if !errors.Is(err, ErrNoWAN) {
		t.Errorf("Apply = %v, want it to report ErrNoWAN", err)
	}
	if !errors.Is(err, ErrNoIPv6) {
		t.Errorf("Apply = %v, want it to report ErrNoIPv6 as well", err)
	}
}
