//go:build !linux

package dataplane

import (
	"fmt"
	"net"
	"runtime"
)

// The kill switch off Linux: refused, and the refusal says why rather than
// pretending.
//
// The Linux implementation installs the same two /1 halves ClientRouter uses,
// as blackholes at a worse metric, so they sit inert while the tunnel is up and
// take over the instant the kernel drops the TUN's routes with its device. That
// handover — with no window — is the whole property, and it depends on two
// things the BSD routing table does not offer: a blackhole route type, and per-
// route metrics that let two routes for one prefix coexist and be ordered.
//
// macOS has `route -n add -blackhole`, but no metric to sit it behind the
// tunnel's own route, so arming it while the tunnel is healthy is not possible
// and arming it on teardown leaves however long the teardown takes as
// plaintext. The honest macOS answer is a pf anchor, which means owning
// firewall state on the user's host — a far larger promise than the Linux one
// makes, and the alternative the Linux file already names and declines.
//
// So this returns an error naming the platform, and cmd/veepin treats it as the
// permanent configuration failure it is: the operator asked for something this
// platform cannot give them, and being told is better than being told nothing
// and believing they have it.

// KillSwitchConfig is the same shape as the Linux one, so the caller compiles
// everywhere and the refusal happens at run time with a message rather than at
// build time with a missing symbol.
type KillSwitchConfig struct {
	ServerIP net.IP
	V4, V6   bool
}

// KillSwitch is the unsupported stub.
type KillSwitch struct{ cfg KillSwitchConfig }

// NewKillSwitch creates a switch that will refuse to engage.
func NewKillSwitch(cfg KillSwitchConfig) *KillSwitch { return &KillSwitch{cfg: cfg} }

// Engaged is always false: nothing was ever installed.
func (k *KillSwitch) Engaged() bool { return false }

// Engage refuses, naming the platform and what it would take.
func (k *KillSwitch) Engage() error {
	return fmt.Errorf("kill switch: not supported on %s — it needs blackhole routes with "+
		"per-route metrics, which the BSD routing table does not have. The honest answer "+
		"here is a pf anchor, and owning firewall state on your host is a larger promise "+
		"than veepin makes. Drop -kill-switch, or set up pf yourself", runtime.GOOS)
}

// Disengage is a no-op: Engage never succeeded.
func (k *KillSwitch) Disengage() error { return nil }

// RecoveryCommand is empty, since nothing needs recovering.
func (k *KillSwitch) RecoveryCommand() string { return "" }
