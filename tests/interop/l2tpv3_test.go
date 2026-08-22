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
//
// It measures, and that is a correction rather than an addition. The throughput
// table renders an unmeasured cell and an inapplicable one identically, and the
// README defines the em dash it renders as "iperf3 does not apply to that cell"
// -- which was never true here: both ends hold a tunnel-internal address and
// both images carry iperf3. Two working directions were published as though
// they could not be measured. Same distinction the harness already had to draw
// once between a broken measurement and an absent one.
func TestInteropKernelL2TPv3ClientVeepinServer(t *testing.T) {
	requireL2TPModules(t)
	runInteropBench(t, "compose.l2tpv3-server.yml", "l2tpv3-peer", "veepin-l2tpv3-server", "10.63.0.1")
	requireARPInsideTunnel(t, "compose.l2tpv3-server.yml", "l2tpv3-peer", "l2tpeth0", "10.63.0.1")
}

// TestInteropL2TPv3Self proves both roles exist and that layer-2 shaping does
// not break the pseudowire. It proves nothing about correctness against a real
// peer -- the kernel cells above do that. Its number is the shaped one: SHAPE is
// set in the compose file, so the rate it reports is layer-2 shaping's cost and
// not a like-for-like against the unshaped kernel cells.
func TestInteropL2TPv3Self(t *testing.T) {
	runInteropBench(t, "compose.l2tpv3-self.yml", "veepin-l2tpv3-client", "veepin-l2tpv3-server", "10.64.0.1")
	requireARPInsideTunnel(t, "compose.l2tpv3-self.yml", "veepin-l2tpv3-client", "tap0", "10.64.0.1")
}

// TestPendingQl2tpdKeepalive is a REPRODUCTION, not a passing cell. It is
// deliberately not named TestInterop* so it joins no CI shard and reports no
// result; run it by hand with -run TestPendingQl2tpdKeepalive.
//
// # What it is
//
// go-l2tp v0.1.8 wedges its receive queue on a conforming L2TPv3 ACK, and the
// cause is now located rather than guessed at. It is upstream, in two lines,
// and veepin's messages are correct.
//
// # The bytes
//
// Captured with tcpdump inside the ql2tpd container (CCID identifies the
// sender: RFC 3931 puts the RECIPIENT's Control Connection ID in the header, so
// CCID=2200 is addressed to ql2tpd and therefore came from veepin):
//
//	veepin -> ql2tpd   ccid=2200 ns=1 nr=1  HELLO
//	ql2tpd -> veepin   ccid=1100 ns=1 nr=2  ACK
//	ql2tpd -> veepin   ccid=1100 ns=0 nr=2  HELLO
//	veepin -> ql2tpd   ccid=2200 ns=2 nr=1  ACK    <- correct: nr=1 acks ns=0
//	... ql2tpd retransmits its ns=0 HELLO three times and gives up with
//	    "transmit of avpMsgTypeHello failed after 3 retry attempts"
//
// # Why it wedges
//
// veepin's ACK carries Ns = the next sequence number it will use, which is what
// RFC 3931 section 3.1 requires of a message that consumes no sequence number.
// That Ns is therefore AHEAD of ql2tpd's Nr. Two upstream lines then interact:
//
//	transport.go:187  msgIsInSequence: seqCompare(s.nr, msg.ns()) == 0
//	transport.go:194  msgIsStale:      seqCompare(msg.ns(), s.nr) == -1
//
// A message whose Ns is ahead of Nr is neither in sequence nor stale, so
// dequeueRxMessage never returns it -- and it stays at the head of rxQueue
// forever. The second line is what makes that fatal rather than merely untidy:
//
//	transport.go:420  m := xport.rxQueue[0]   // inside `for i := ...`
//
// The loop indexes with i but always inspects element 0, so it cannot look past
// a stuck head. Every later message piles up behind the ACK, Nr never advances,
// nothing is ever acknowledged again, and the tunnel dies on the retry limit.
//
// It is order-dependent, which is why the first reading of this looked
// intermittent: if ql2tpd happens to process a HELLO before the ACK, its Nr
// catches up and the ACK is merely in sequence.
//
// # Why veepin does not work around it
//
// There is nothing conforming to change. Sending the ACK with a lower Ns would
// misstate the next sequence number, and sending a HELLO in place of an ACK
// would put a message that consumes a sequence number where the RFC calls for
// one that does not. The earlier hypothesis recorded here -- that go-l2tp ran a
// duplicate check on Ns before its acknowledgement handling -- was disproven by
// reading the source: the ack path (processAckQueue, reached through nrChan)
// never consults the duplicate check at all.
//
// So veepin's quiescent control connection stays covered by unit tests plus the
// kernel data-path cells, and internal/l2tpv3/README.md says so rather than
// implying an interop guarantee no available peer can give.
// TestAckCarriesTheNextSequenceNumber in internal/l2tpv3 pins the behaviour
// this depends on, so a future "fix" cannot quietly make veepin wrong in order
// to make this peer happy.
func TestPendingQl2tpdKeepalive(t *testing.T) {
	t.Skip("reproduction only: go-l2tp v0.1.8 wedges its rxQueue on a conforming ACK; see the comment above")
}

// requireL2TPModules skips a cell when the host kernel cannot provide an L2TP
// data plane.
//
// The peer for these cells IS the kernel: `ip l2tp` needs l2tp_core, l2tp_eth
// and l2tp_netlink, and the containers use the HOST's kernel, so the modules
// have to be present there. Absent them the peer container reports "the kernel
// has no L2TP support" and nothing can be tested.
//
// Skipping is the honest outcome on a developer's machine: it says the
// environment cannot host the peer, where failing would claim veepin is broken.
//
// It is no longer the outcome in CI, and that is the point of the change that
// wrote this paragraph. The runners boot an Azure kernel whose l2tp modules are
// packaged separately, so for as long as nobody installed them these two cells
// skipped on every run -- and a skip is reported as not-passed, which put a ✗
// against a peer that had never started. The interop workflow now installs and
// loads them from the manifest's own Modules list, and FAILS the shard if they
// are still missing, so the skip below can no longer be reached there.
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
		"Linux kernel itself, so there is nothing to test against. On Debian and " +
		"Ubuntu it is in linux-modules-extra-$(uname -r), which is what CI installs")
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
