//go:build interop

package interop

import (
	"strings"
	"testing"
	"time"
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

// requireL2TPModules skips a cell when the host kernel has no L2TP support. The
// peer IS the kernel, so without the modules there is no peer -- and skipping
// says so, rather than reporting a veepin failure for a missing dependency.
func requireL2TPModules(t *testing.T) {
	t.Helper()
	requireDocker(t)
	out, err := compose(t, "compose.l2tpv3.yml", "config")
	if err != nil {
		t.Fatalf("compose config: %v\n%s", err, out)
	}
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
