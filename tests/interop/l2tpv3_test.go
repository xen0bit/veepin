//go:build interop

package interop

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The L2TPv3 cells, against the Linux kernel's own l2tp_eth.
//
// Two things here are not optional, and both come from what a layer-2 tunnel
// actually claims:
//
//   - The cookies are ASYMMETRIC. A symmetric cookie cannot catch a swapped
//     direction, because both ends would be wrong the same way -- the
//     mutually-consistent bug class that made the Pulse ESP keying pass every
//     veepin-to-veepin test and fail only against openconnect.
//   - Every cell asserts an ARP exchange completed INSIDE the tunnel. A ping
//     between two statically-addressed endpoints proves nothing about layer 2;
//     ARP is traffic no L3 tunnel can carry at all, so it is the assertion that
//     distinguishes a working pseudowire from a working IP tunnel.

// TestInteropVeepinClientKernelL2TPv3Server drives veepin's client against a
// static pseudowire configured with `ip l2tp`.
func TestInteropVeepinClientKernelL2TPv3Server(t *testing.T) {
	requireL2TPModules(t)
	runInteropBench(t, "compose.l2tpv3.yml", "veepin-l2tpv3-client", "l2tpv3-peer", "10.62.0.1")
	requireARPInsideTunnel(t, "compose.l2tpv3.yml", "veepin-l2tpv3-client", "tap0", "10.62.0.1")
}

// TestInteropKernelL2TPv3ClientVeepinServer is the other direction: the kernel
// configures the pseudowire and veepin answers it.
func TestInteropKernelL2TPv3ClientVeepinServer(t *testing.T) {
	requireL2TPModules(t)
	runInterop(t, "compose.l2tpv3-server.yml", "l2tpv3-peer", "10.63.0.1")
	requireARPInsideTunnel(t, "compose.l2tpv3-server.yml", "l2tpv3-peer", "l2tpeth0", "10.63.0.1")
}

// TestInteropL2TPv3Self proves both roles exist and that layer-2 shaping does
// not break the pseudowire. It proves nothing about correctness against a real
// peer -- the kernel cells above do that.
func TestInteropL2TPv3Self(t *testing.T) {
	runInterop(t, "compose.l2tpv3-self.yml", "veepin-l2tpv3-client", "10.64.0.1")
	requireARPInsideTunnel(t, "compose.l2tpv3-self.yml", "veepin-l2tpv3-client", "tap0", "10.64.0.1")
}

// requireL2TPModules skips a cell when the host kernel cannot provide an L2TP
// data plane.
//
// The peer for these cells IS the kernel: `ip l2tp` needs l2tp_core, l2tp_eth
// and l2tp_netlink, and the containers use the HOST's kernel, so the modules
// have to be present there. GitHub's runners ship a kernel with them absent --
// the peer container reports "the kernel has no L2TP support" and nothing can
// be tested.
//
// Skipping is the honest outcome: it says the environment cannot host the peer,
// where failing would claim veepin is broken. The cells do pass on any host with
// the modules, which is where the kernel interop claim comes from -- see
// internal/l2tpv3/README.md.
func requireL2TPModules(t *testing.T) {
	t.Helper()
	requireDocker(t)

	// Already loaded is the cheapest yes.
	if _, err := os.Stat("/sys/module/l2tp_eth"); err == nil {
		return
	}
	// Otherwise the module has to be on disk for the peer to modprobe it.
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		release := string(bytes.TrimRight(uts.Release[:], "\x00"))
		dir := filepath.Join("/lib/modules", release, "kernel/net/l2tp")
		if entries, derr := os.ReadDir(dir); derr == nil {
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "l2tp_eth.ko") {
					return
				}
			}
		}
	}
	t.Skip("no l2tp_eth kernel module on this host: the peer for this cell is the " +
		"Linux kernel itself, so there is nothing to test against (GitHub runners are like this)")
}

// requireARPInsideTunnel asserts the peer's MAC was learned through the tunnel.
//
// This is the layer-2 claim, and nothing else in the harness checks it: a ping
// succeeds identically over an L3 tunnel, but an ARP entry for a peer reachable
// only across the pseudowire can only exist if Ethernet frames crossed it. The
// neighbour table is read on the tunnel interface specifically, so an entry
// learned on the container's own bridge cannot be mistaken for one learned
// inside the tunnel.
func requireARPInsideTunnel(t *testing.T, composeFile, svc, iface, peerIP string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out, err := compose(t, composeFile, "exec", "-T", svc,
			"ip", "neigh", "show", "dev", iface)
		if err == nil && strings.Contains(out, peerIP) {
			if strings.Contains(out, "lladdr") {
				t.Logf("layer 2 confirmed: %s resolved %s to a MAC on %s inside the tunnel\n%s",
					svc, peerIP, iface, strings.TrimSpace(out))
				return
			}
		}
		last = out
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("no ARP entry for %s on %s in %s: the ping crossed something, but nothing "+
		"proves it was an Ethernet pseudowire\n%s", peerIP, iface, svc, last)
}
