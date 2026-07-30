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
func Teardown(name string, cfg Config) error {
	return teardownWith(name, cfg, realCommander)
}

// ApplyWithName is Apply using an explicit commander. It exists for tests; non-
// test callers use Apply, which picks the real os/exec commander.
func ApplyWithName(name string, cfg Config, run Commander) error {
	return applyWith(name, cfg, run)
}

// TeardownWithName is Teardown using an explicit commander.
func TeardownWithName(name string, cfg Config, run Commander) error {
	return teardownWith(name, cfg, run)
}

func applyWith(name string, cfg Config, run Commander) error {
	if cfg.TUNName == "" {
		return errors.New("hostnet: TUNName is required")
	}
	if cfg.Network == nil {
		// Layer-2 server: no address, no NAT. The interface still needs to
		// come up, but the operator manages bridging and addressing.
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
	if out, err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		// Forwarding is host-wide: a previous veepin instance or another VPN
		// daemon may have set it. The failure here is benign in practice, but
		// surfacing it would make a shared host unable to start any listener
		// once it had already been set. Treat as advisory.
		_ = out
	}

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
	} else {
		// If no WAN is named, the interface gets an address and forwarding,
		// but nothing leaves it -- surface that so the supervisor / command
		// does not advertise a tunnel that has no internet. This matches the
		// old behaviour verbatim: it was an error in serve.go.
		return fmt.Errorf("hostnet: interface configured but no wan given, so no MASQUERADE installed")
	}
	return nil
}

func teardownWith(name string, cfg Config, run Commander) error {
	if cfg.Network == nil || cfg.WAN == "" {
		// Nothing was installed for this listener; teardown is a no-op.
		return nil
	}
	tag := comment(name)
	natRule := []string{
		"-t", "nat", "-D", "POSTROUTING",
		"-s", cfg.Network.String(),
		"-o", cfg.WAN,
		"-j", "MASQUERADE",
		"-m", "comment", "--comment", tag,
	}
	if err := removeRule(run, natRule); err != nil {
		return fmt.Errorf("hostnet: NAT teardown: %w", err)
	}
	fwdIn := []string{"-D", "FORWARD", "-i", cfg.TUNName, "-j", "ACCEPT",
		"-m", "comment", "--comment", tag}
	if err := removeRule(run, fwdIn); err != nil {
		return fmt.Errorf("hostnet: FORWARD in teardown: %w", err)
	}
	fwdOut := []string{"-D", "FORWARD", "-o", cfg.TUNName, "-j", "ACCEPT",
		"-m", "comment", "--comment", tag}
	if err := removeRule(run, fwdOut); err != nil {
		return fmt.Errorf("hostnet: FORWARD out teardown: %w", err)
	}
	return nil
}

// ensureRule adds rule to iptables if it is not already there. The check uses
// `iptables -C` (does this rule exist?), the standard idempotent pattern.
func ensureRule(run Commander, rule []string) error {
	if _, err := run("iptables", iptablesCheckArgs(rule)...); err == nil {
		return nil // rule already exists
	}
	addArgs := iptablesMutateArgs(rule)
	if out, err := run("iptables", addArgs...); err != nil {
		return fmt.Errorf("iptables %s: %v: %s",
			strings.Join(addArgs, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeRule deletes rule(s) from iptables, looping while a matching rule still
// exists so duplicate installs (should be impossible with ensureRule, but
// defensive) do not survive teardown.
func removeRule(run Commander, rule []string) error {
	deleteArgs := iptablesDeleteArgs(rule)
	for i := 0; i < 64; i++ {
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

// iptablesMutateArgs rewrites a rule slice (with -A or -t nat -A ...) into the
// form passed to iptables to add it. The rule slice is already in -A form; it
// is returned as-is so the helper reads as a place to swap operations later.
func iptablesMutateArgs(rule []string) []string {
	out := make([]string, len(rule))
	copy(out, rule)
	return out
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
