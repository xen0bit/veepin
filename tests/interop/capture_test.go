//go:build interop

package interop

// The live half of the golden-corpus pairing in internal/capture/goldens.
//
// The committed corpora are replayed offline by `go test ./...` in
// milliseconds. That is fast and it is also, on its own, a memory: a recording
// pins the peer as it was on the capture date and cannot notice that the peer
// changed. These cells close that gap by running the *identical* check against
// a capture taken seconds ago from a live peer.
//
// So the division of labour is: the offline test says "veepin still agrees with
// what strongSwan sent in August", and this one says "and strongSwan still
// sends it". Neither is asked to be the other, which is the whole reason the
// checks are exported functions rather than test bodies.
//
// Set VEEPIN_UPDATE_GOLDENS=1 to rewrite the committed corpus from the fresh
// capture. That is the only supported way to produce one — a corpus must come
// from a live cell or it is not evidence of anything.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/capture"
	"github.com/xen0bit/veepin/internal/capture/goldens"
)

// captureSpec describes how to record one cell.
type captureSpec struct {
	// name is the corpus's name in goldens.Registry.
	name string
	// composeFile is the cell. It is read from the registry entry rather than
	// repeated here, so the corpus and the cell cannot drift.

	// captureSvc is brought up first and runs tcpdump. It must be the side that
	// listens: tcpdump has to be recording before the first handshake message,
	// and only the listener can be started early without the exchange starting
	// without it.
	captureSvc string
	// dialSvc is brought up second and starts the exchange.
	dialSvc string
	// pingSvc pings target once the tunnel should be up, so the capture covers
	// a handshake that actually completed.
	pingSvc string
	target  string
	// filter is the tcpdump expression bounding the capture.
	filter string
}

// TestInteropIKEv2CorpusStillMatchesTheLivePeer records Direction A of the IKEv2
// row and requires the live strongSwan to satisfy everything the committed
// corpus claims of it — including that it still advertises RFC 7383
// fragmentation, without which veepin silently stops fragmenting its own IKE
// output and certificate authentication regresses.
func TestInteropIKEv2CorpusStillMatchesTheLivePeer(t *testing.T) {
	runCapture(t, captureSpec{
		name:       "ikev2-strongswan",
		captureSvc: "strongswan-server",
		dialSvc:    "veepin-client",
		pingSvc:    "veepin-client",
		target:     "10.20.30.254",
		filter:     "udp port 500 or udp port 4500",
	})
}

// TestInteropWireguardCorpusStillMatchesTheLivePeer records Direction B of the
// WireGuard row, where the *peer* sends the handshake initiation — the message
// with the MACs and the encrypted static key in it. The check hands that
// message to veepin's own Noise responder, so what this cell keeps honest is a
// full cryptographic verification against somebody else's arithmetic.
func TestInteropWireguardCorpusStillMatchesTheLivePeer(t *testing.T) {
	runCapture(t, captureSpec{
		name:       "wireguard-wgge",
		captureSvc: "veepin-wg-server",
		dialSvc:    "wg-client",
		pingSvc:    "wg-client",
		target:     "10.10.10.1",
		filter:     "udp port 51820",
	})
}

// captureDeadline bounds waiting for the listener to be up enough to attach
// tcpdump to it. It only covers image build and container start.
const captureDeadline = 90 * time.Second

func runCapture(t *testing.T, spec captureSpec) {
	t.Helper()
	requireDocker(t)

	golden, ok := goldens.Registry[spec.name]
	if !ok {
		t.Fatalf("no golden named %q; tests/interop and internal/capture/goldens disagree", spec.name)
	}
	file := golden.Cell

	if out, err := compose(t, file, "up", "--build", "-d", spec.captureSvc); err != nil {
		t.Fatalf("compose up %s: %v\n%s", spec.captureSvc, err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			if logs, err := compose(t, file, "logs", "--no-color"); err == nil {
				t.Logf("--- compose logs (%s) ---\n%s", file, logs)
			}
		}
		_, _ = compose(t, file, "down", "-v", "--timeout", "5")
	})

	// tcpdump must be recording before the first handshake message, so start it
	// while only the listener is up and nothing has dialled yet.
	startTCPDump(t, file, spec)

	if out, err := compose(t, file, "up", "--build", "-d", spec.dialSvc); err != nil {
		t.Fatalf("compose up %s: %v\n%s", spec.dialSvc, err, out)
	}
	if !waitPing(t, file, spec.pingSvc, spec.target) {
		t.Fatalf("the tunnel never came up, so the capture holds a failed handshake")
	}

	pcapFile := filepath.Join(t.TempDir(), spec.name+".pcap")
	stopTCPDump(t, file, spec, pcapFile)

	raw, err := os.ReadFile(pcapFile)
	if err != nil {
		t.Fatalf("reading the capture: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("the capture is empty; tcpdump did not attach in time")
	}

	fresh, err := goldens.Build(spec.name, raw, time.Now().UTC().Format(time.DateOnly))
	if err != nil {
		t.Fatalf("building a corpus from the fresh capture: %v", err)
	}

	// The assertion this cell exists for: the live peer still satisfies
	// everything the committed corpus claims.
	if err := golden.Check(fresh); err != nil {
		t.Fatalf("the live peer no longer satisfies the check the committed corpus passes:\n%v\n\n"+
			"That is the corpus doing its job. Either the peer changed and veepin must follow, "+
			"or the check was too strict. Do not silence it by regenerating the corpus without "+
			"deciding which.", err)
	}

	// And the exchange still has the same shape. A peer that stopped sending
	// one of these would pass every per-message check by simply not sending the
	// message.
	committed, err := goldens.Load(spec.name)
	if err != nil {
		t.Fatalf("loading the committed corpus: %v", err)
	}
	if got, want := fresh.Labels(), committed.Labels(); !equalStrings(got, want) {
		t.Errorf("the live exchange is %v, the committed corpus records %v", got, want)
	}

	if os.Getenv("VEEPIN_UPDATE_GOLDENS") == "1" {
		writeCorpus(t, spec.name, fresh)
	}
}

// startTCPDump launches tcpdump inside the capture service, recording its pid
// so it can be stopped again. The pid file is needed because the peer images
// are minimal and several have no pkill.
func startTCPDump(t *testing.T, file string, spec captureSpec) {
	t.Helper()
	deadline := time.Now().Add(captureDeadline)
	var last string
	for time.Now().Before(deadline) {
		out, err := compose(t, file, "exec", "-T", spec.captureSvc, "sh", "-c", "command -v tcpdump")
		if err == nil && strings.Contains(out, "tcpdump") {
			break
		}
		last = out
		time.Sleep(2 * time.Second)
	}
	if time.Now().After(deadline) {
		t.Fatalf("%s never produced a usable tcpdump within %s:\n%s", spec.captureSvc, captureDeadline, last)
	}

	cmd := fmt.Sprintf("tcpdump -i eth0 -s 0 -U -w /tmp/capture.pcap %q & echo $! > /tmp/tcpdump.pid; wait", spec.filter)
	if out, err := compose(t, file, "exec", "-T", "-d", spec.captureSvc, "sh", "-c", cmd); err != nil {
		t.Fatalf("starting tcpdump in %s: %v\n%s", spec.captureSvc, err, out)
	}
	// -U writes each packet as it arrives, but the process still has to reach
	// its capture loop before the dialler starts.
	time.Sleep(2 * time.Second)
}

func stopTCPDump(t *testing.T, file string, spec captureSpec, dst string) {
	t.Helper()
	// SIGINT rather than SIGKILL: tcpdump flushes on the way out.
	if out, err := compose(t, file, "exec", "-T", spec.captureSvc, "sh", "-c",
		"kill -INT $(cat /tmp/tcpdump.pid)"); err != nil {
		t.Logf("stopping tcpdump: %v\n%s", err, out)
	}
	time.Sleep(1 * time.Second)
	if out, err := compose(t, file, "cp", spec.captureSvc+":/tmp/capture.pcap", dst); err != nil {
		t.Fatalf("copying the capture out: %v\n%s", err, out)
	}
}

// writeCorpus rewrites the committed corpus. It writes into the source tree, so
// it is guarded by an environment variable rather than a flag: regenerating a
// golden file is a deliberate act whose diff a human reads.
func writeCorpus(t *testing.T, name string, c *capture.Corpus) {
	t.Helper()
	enc, err := c.Marshal()
	if err != nil {
		t.Fatalf("marshalling the corpus: %v", err)
	}
	path := filepath.Join("..", "..", "internal", "capture", "goldens", "corpora", name+".corpus")
	if err := os.WriteFile(path, enc, 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	t.Logf("rewrote %s from a fresh capture (%d records)", path, len(c.Records))
}

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
