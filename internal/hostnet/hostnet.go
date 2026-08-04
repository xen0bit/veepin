// Package hostnet owns the host-side network setup a veepin server needs but
// deliberately does not perform by itself: assigning the TUN interface its
// address, bringing it up, enabling IPv4 forwarding, and installing the NAT /
// FORWARD iptables rules that let a tunnel subnet reach the WAN.
//
// It is the home of the behaviour behind `veepin serve -setup-nat`, extracted
// from cmd/veepin/serve.go so that both the single-protocol command and the
// supervisor in internal/supervisor build servers the same way.
//
// Every iptables rule the package installs is tagged with a comment it owns,
//
//	-m comment --comment veepin:<name>
//
// and Apply is idempotent: it never adds a rule that is already present, so
// rebuilding a listener (the supervisor's cold-rebuild path) re-runs Apply
// safely and leaves the host exactly as it found it. Teardown removes by the
// same comment, so a rebuilt or deleted listener takes its host state with it
// rather than accumulating MASQUERADE lines on every restart.
//
// The package shells out to ip/iptables/sysctl, which must be present and
// runnable with sufficient privileges (root, or CAP_NET_ADMIN on the binary).
package hostnet

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Comment is the iptables comment tag every rule Apply installs and Teardown
// removes. The <name> is the supervisor listener name, or "serve" for the
// single-protocol command so the two paths remain visually distinct from each
// other and from anything else on the host.
const Comment = "veepin"

// Commander runs an external command and returns its combined stdout/stderr.
// The default shells out via os/exec; tests inject a fake to assert on the
// exact sequence of commands without touching the host.
type Commander func(name string, args ...string) ([]byte, error)

// realCommander is the production commander: it is exactly what
// exec.Command(name, args...).CombinedOutput() does, just shaped so the same
// call works in tests.
func realCommander(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// ErrNoWAN reports that the interface was addressed and forwarding enabled, but
// no MASQUERADE rule was installed because Config.WAN was empty. The listener is
// serving and its clients can reach the host; they cannot reach anything beyond
// it.
//
// It is deliberately an error — the caller must not tell an operator that a
// tunnel carries traffic to the internet when it does not — and deliberately a
// distinguishable one, because it is equally not a reason to refuse to serve.
// Callers that can carry on should test errors.Is(err, ErrNoWAN) and log rather
// than abort; the supervisor does exactly that, so one listener missing its
// `wan` does not take the rest of the fleet down with it.
var ErrNoWAN = errors.New("hostnet: interface configured but no wan given, so no MASQUERADE installed")

// Config is the host-network state for one listener.
type Config struct {
	// TUNName is the interface to bring up.
	TUNName string
	// Gateway is the server's in-tunnel address (the network end of the
	// tunnel subnet's first usable host).
	Gateway net.IP
	// Network is the tunnel subnet client addresses come from. Nil means a
	// layer-2 server (L2TPv3): no address to assign, no NAT to install.
	Network *net.IPNet
	// WAN is the upstream interface to masquerade behind. Empty means apply
	// the interface address and forwarding only; no MASQUERADE, and a non-nil
	// error is returned so the caller does not believe clients can reach the
	// internet when they cannot.
	WAN string
}

// MaskBits is the prefix length of the tunnel subnet, or 0 for a layer-2
// server. Lifted unchanged from serve.go so the nil-deref crash found by the
// L2TPv3 interop cell cannot come back.
func MaskBits(n *net.IPNet) int {
	if n == nil {
		return 0
	}
	ones, _ := n.Mask.Size()
	return ones
}

// State is the record of what Apply installed for one listener, sufficient for
// a later Teardown to remove exactly that. It is deliberately not the caller's
// current Config: the listener's config may have been edited since (WAN dropped,
// address changed), and a TUN name the kernel assigned is present only in the
// State, never in the listener's options. The caller persists it -- the
// supervisor writes <config>/mgmt/hostnet/<name>.json after Apply and reads it
// back on teardown -- so teardown is the inverse of what actually happened, not
// of what the config file now says.
type State struct {
	// TUNName is the interface the rules name. Kernel-assigned names ("tun0")
	// live only here once the server that owned them is closed.
	TUNName string `json:"tun"`
	// WAN is the interface MASQUERADE was installed for; empty means nothing
	// rule-shaped was installed.
	WAN string `json:"wan,omitempty"`
	// Network is the tunnel subnet the MASQUERADE source selector names, in
	// CIDR form; empty for a layer-2 server, which installs no rules.
	Network string `json:"network,omitempty"`
}

// State returns the record a Teardown needs for the config Apply is about to
// install.
func (c Config) State() State {
	st := State{TUNName: c.TUNName, WAN: c.WAN}
	if c.Network != nil {
		st.Network = c.Network.String()
	}
	return st
}

// Apply configures the TUN address, brings the interface up, enables IPv4
// forwarding, and installs tagged MASQUERADE/FORWARD rules if a WAN was given.
// It is idempotent: every iptables rule it adds is checked first so a second
// call for the same listener leaves the host unchanged.
func Apply(name string, cfg Config) error {
	return applyWith(name, cfg, realCommander)
}

// Teardown removes every host-side rule tagged for name, in reverse of Apply's
// order. It is bounded (at most 64 deletes per chain) so a runaway rule list
// cannot hang the supervisor; a healthy host has one row per listener.
//
// It derives the teardown set from cfg, which is correct for the bare command
// (whose config cannot have changed while it was running) and for tests. A
// caller that manages a fleet -- the supervisor -- must not do that: the
// listener's config may have been edited, or its TUN name kernel-assigned, so
// it persists the State that Apply installed and tears down from that instead.
// See TeardownState.
func Teardown(name string, cfg Config) error {
	return TeardownState(name, cfg.State())
}

// TeardownState is the persisted-state form of Teardown: it removes exactly the
// rules the recorded State describes, whether or not the listener's current
// config still matches. A State with an empty WAN or Network (no NAT was ever
// installed) is a no-op.
func TeardownState(name string, st State) error {
	return teardownStateWith(name, st, realCommander)
}

// ApplyWithName is Apply using an explicit commander. It exists for tests; non-
// test callers use Apply, which picks the real os/exec commander.
func ApplyWithName(name string, cfg Config, run Commander) error {
	return applyWith(name, cfg, run)
}

// TeardownWithName is Teardown using an explicit commander.
func TeardownWithName(name string, cfg Config, run Commander) error {
	return TeardownStateWithName(name, cfg.State(), run)
}

// TeardownStateWithName is TeardownState using an explicit commander.
func TeardownStateWithName(name string, st State, run Commander) error {
	return teardownStateWith(name, st, run)
}

func applyWith(name string, cfg Config, run Commander) error {
	if cfg.TUNName == "" {
		return errors.New("hostnet: TUNName is required")
	}

	// A layer-2 server (L2TPv3) has no tunnel subnet, so there is no address to
	// assign and no NAT to install -- the operator owns bridging and addressing.
	// The interface still has to come up, though, or the pseudowire carries
	// nothing: an earlier version returned here before the link-up below and
	// left the interface DOWN while reporting success.
	if cfg.Network == nil {
		if out, err := run("ip", "link", "set", cfg.TUNName, "up"); err != nil {
			return fmt.Errorf("hostnet: ip link set %s up: %v: %s",
				cfg.TUNName, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	bits := MaskBits(cfg.Network)

	// `ip addr add` is not idempotent: re-adding an address the interface
	// already holds fails with "File exists". Re-running Apply on a rebuild
	// would surface that as an error and the supervisor would refuse a benign
	// restart. Treat "already there" as success.
	addr := fmt.Sprintf("%s/%d", cfg.Gateway, bits)
	if out, err := run("ip", "addr", "add", addr, "dev", cfg.TUNName); err != nil {
		if !isAlreadyExists(out) {
			return fmt.Errorf("hostnet: ip addr add %s dev %s: %v: %s",
				addr, cfg.TUNName, err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := run("ip", "link", "set", cfg.TUNName, "up"); err != nil {
		return fmt.Errorf("hostnet: ip link set %s up: %v: %s",
			cfg.TUNName, err, strings.TrimSpace(string(out)))
	}
	// Advisory, deliberately: forwarding is host-wide, so a previous veepin
	// instance or another VPN daemon may already own it, and failing here would
	// make a shared host unable to start any listener once it had been set. The
	// branch that discarded the output was doing exactly this, at more length.
	_, _ = run("sysctl", "-w", "net.ipv4.ip_forward=1")

	tag := comment(name)
	if cfg.WAN != "" {
		natRule := []string{
			"-t", "nat", "-A", "POSTROUTING",
			"-s", cfg.Network.String(),
			"-o", cfg.WAN,
			"-j", "MASQUERADE",
			"-m", "comment", "--comment", tag,
		}
		if err := ensureRule(run, natRule); err != nil {
			return fmt.Errorf("hostnet: NAT MASQUERADE: %w", err)
		}
		fwdIn := []string{"-A", "FORWARD", "-i", cfg.TUNName, "-j", "ACCEPT",
			"-m", "comment", "--comment", tag}
		if err := ensureRule(run, fwdIn); err != nil {
			return fmt.Errorf("hostnet: FORWARD in: %w", err)
		}
		fwdOut := []string{"-A", "FORWARD", "-o", cfg.TUNName, "-j", "ACCEPT",
			"-m", "comment", "--comment", tag}
		if err := ensureRule(run, fwdOut); err != nil {
			return fmt.Errorf("hostnet: FORWARD out: %w", err)
		}
		return nil
	}
	// No WAN named: the interface has an address and forwarding, but nothing
	// leaves it. Report it, so neither the supervisor nor the bare command
	// advertises a tunnel that reaches the internet when it does not -- but
	// report it as ErrNoWAN, which a caller can recognise and carry on from.
	return ErrNoWAN
}

// teardownStateWith deletes the rules the recorded State describes, using the
// given commander. A State with no WAN or no Network installed nothing
// rule-shaped, so teardown is a no-op -- the layer-2 path (Network empty) and
// the no-WAN path (ErrNoWAN from Apply) both land here. Teardown is safe to
// call unconditionally for any listener.
func teardownStateWith(name string, st State, run Commander) error {
	if st.Network == "" || st.WAN == "" {
		return nil
	}
	tag := comment(name)
	natRule := []string{
		"-t", "nat", "-D", "POSTROUTING",
		"-s", st.Network,
		"-o", st.WAN,
		"-j", "MASQUERADE",
		"-m", "comment", "--comment", tag,
	}
	if err := removeRule(run, natRule); err != nil {
		return fmt.Errorf("hostnet: NAT teardown: %w", err)
	}
	fwdIn := []string{"-D", "FORWARD", "-i", st.TUNName, "-j", "ACCEPT",
		"-m", "comment", "--comment", tag}
	if err := removeRule(run, fwdIn); err != nil {
		return fmt.Errorf("hostnet: FORWARD in teardown: %w", err)
	}
	fwdOut := []string{"-D", "FORWARD", "-o", st.TUNName, "-j", "ACCEPT",
		"-m", "comment", "--comment", tag}
	if err := removeRule(run, fwdOut); err != nil {
		return fmt.Errorf("hostnet: FORWARD out teardown: %w", err)
	}
	return nil
}

// TeardownByTag removes every rule carrying this listener's comment tag,
// whatever its other fields say. It is the recovery path for when the recorded
// State is missing or unreadable: the tag is the one thing every rule Apply
// installs is guaranteed to carry, so it can find them when nothing else can.
//
// Deliberately not the normal path. TeardownState names the exact rules it
// expects and fails loudly if the host disagrees; this one deletes whatever it
// finds under the tag, which is right for recovery and too blunt for routine
// use.
func TeardownByTag(name string) error {
	return teardownByTagWith(name, realCommander)
}

// TeardownByTagWithName is TeardownByTag using an explicit commander.
func TeardownByTagWithName(name string, run Commander) error {
	return teardownByTagWith(name, run)
}

func teardownByTagWith(name string, run Commander) error {
	tag := comment(name)
	for _, c := range []struct{ table, chain string }{
		{"nat", "POSTROUTING"},
		{"filter", "FORWARD"},
	} {
		out, err := run("iptables", "-t", c.table, "-S", c.chain)
		if err != nil {
			// A chain that does not exist is not an error worth failing on: the
			// host simply has nothing of ours in it.
			continue
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "-A" || !ruleHasTag(fields, tag) {
				continue
			}
			// Unquoted, because `iptables -S` prints the comment quoted --
			// `--comment "veepin:site-a"` -- and there is no shell between here
			// and execve to take the quotes off. Passing them through made every
			// -D name a comment no installed rule has, so each one failed, the
			// loop returned on the first, and the rules stayed on the host
			// forever. ruleHasTag below already knew to unquote to MATCH; only
			// the rebuild did not.
			args := append([]string{"-t", c.table}, unquoteFields(fields)...)
			args[2] = "-D"
			if o, derr := run("iptables", args...); derr != nil {
				return fmt.Errorf("hostnet: tagged teardown: iptables %s: %v: %s",
					strings.Join(args, " "), derr, strings.TrimSpace(string(o)))
			}
		}
	}
	return nil
}

// unquoteFields strips the double quotes `iptables -S` puts around values that
// contain spaces (in practice, the comment). exec.Command passes each argument
// through untouched, so a quote that survives here is a literal quote in the
// value iptables compares against.
func unquoteFields(fields []string) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = strings.Trim(f, `"`)
	}
	return out
}

// ruleHasTag reports whether an `iptables -S` rule carries exactly this tag as
// its comment. Compared field-by-field rather than by substring so the tag for
// "site-a" does not match the rule belonging to "site-ab".
func ruleHasTag(fields []string, tag string) bool {
	for i, f := range fields {
		if f != "--comment" || i+1 >= len(fields) {
			continue
		}
		if strings.Trim(fields[i+1], `"`) == tag {
			return true
		}
	}
	return false
}

// ensureRule adds rule to iptables if it is not already there. The check uses
// `iptables -C` (does this rule exist?), the standard idempotent pattern.
func ensureRule(run Commander, rule []string) error {
	if _, err := run("iptables", iptablesCheckArgs(rule)...); err == nil {
		return nil // rule already exists
	}
	// rule is already in -A form, so it is passed straight through. It went via
	// an iptablesMutateArgs helper that copied the slice and returned it
	// unchanged, described by its own comment as "a place to swap operations
	// later" -- a hook for a caller that never arrived.
	if out, err := run("iptables", rule...); err != nil {
		return fmt.Errorf("iptables %s: %v: %s",
			strings.Join(rule, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeRule deletes rule(s) from iptables, looping while a matching rule still
// exists so duplicate installs (should be impossible with ensureRule, but
// defensive) do not survive teardown.
func removeRule(run Commander, rule []string) error {
	deleteArgs := iptablesDeleteArgs(rule)
	for range 64 {
		checkArgs := iptablesCheckArgs(rule)
		if _, err := run("iptables", checkArgs...); err != nil {
			return nil // no matching rule left
		}
		if out, err := run("iptables", deleteArgs...); err != nil {
			return fmt.Errorf("iptables %s: %v: %s",
				strings.Join(deleteArgs, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// iptablesCheckArgs swaps the operation token (-A / -D) in rule for -C, which
// tests whether a matching rule exists without adding or removing anything.
func iptablesCheckArgs(rule []string) []string {
	return swapOp(rule, "-C")
}

// iptablesDeleteArgs swaps the operation token (-A) in rule for -D.
func iptablesDeleteArgs(rule []string) []string {
	return swapOp(rule, "-D")
}

// swapOp returns rule with the first occurrence of "-A" replaced by op. The same
// helper handles -C and -D: the rule slice's structure is "[-t table] -A CHAIN
// ..." and only the -A changes between add/check/delete.
func swapOp(rule []string, op string) []string {
	out := make([]string, len(rule))
	copy(out, rule)
	for i, a := range out {
		if a == "-A" || a == "-D" {
			out[i] = op
			return out
		}
	}
	return out
}

// isAlreadyExists recognises `ip addr add`'s "File exists" / "RTNETLINK:
// File exists" so a re-application on a rebuilt interface is treated as a
// no-op rather than an error.
func isAlreadyExists(out []byte) bool {
	return strings.Contains(string(out), "File exists")
}

// comment is the verbatim value written to iptables -m comment --comment. The
// tag is the literal "veepin:<name>" so host iptables -L output reads as one
// recognizable cluster per listener.
func comment(name string) string {
	return Comment + ":" + name
}
