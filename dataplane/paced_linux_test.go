//go:build linux

package dataplane

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// pacedRecorder is a PacedTunnel that records what it is offered and fails the
// test if anything is ever sent around it.
type pacedRecorder struct {
	t      *testing.T
	mu     sync.Mutex
	queued [][]byte
	done   chan struct{}
	want   int
}

func (r *pacedRecorder) InboundKey() uint32 { return 1 }
func (r *pacedRecorder) Routes() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("10.99.0.7/32")}
}
func (r *pacedRecorder) PeerAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}
}
func (r *pacedRecorder) Encapsulate(p []byte) ([]byte, error) {
	r.t.Error("a paced tunnel's Encapsulate was called by the pump: the packet went around the pacer")
	return append([]byte{0xEE}, p...), nil
}
func (r *pacedRecorder) Decapsulate(p []byte) ([]byte, error) { return p, nil }
func (r *pacedRecorder) StartPacing(Sender)                   {}
func (r *pacedRecorder) StopPacing()                          {}
func (r *pacedRecorder) Enqueue(p []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queued = append(r.queued, append([]byte(nil), p...))
	if len(r.queued) == r.want {
		close(r.done)
	}
	return true
}

// TestAGSOSuperFrameGoesThroughThePacer. Constant-rate IP-TFS is a claim about
// the datagram stream as a whole: its timing says nothing about the traffic
// inside. The GSO egress path encapsulated and sent super-frame segments
// directly, never asking whether the tunnel paces -- so on any veepin client,
// which negotiates GSO, bulk TCP left at its own rate beside the pacer. If this
// fails, the tunnel's heaviest flows are the ones it does not hide.
func TestAGSOSuperFrameGoesThroughThePacer(t *testing.T) {
	super := buildTCP4(t, 7, 5000, 0x18, patterned(2500))
	tun := newFakeGSOTUN(vnetFrame(virtioNetHdr{gsoType: vnetGSOTCPv4, gsoSize: 1000, hdrLen: 40}, super))
	defer close(tun.closed)

	rec := &pacedRecorder{t: t, done: make(chan struct{}), want: 3}
	pump := NewPump(tun, func([]byte, *net.UDPAddr) {
		t.Error("the pump sent a datagram for a paced tunnel itself")
	}, SPIDemux, nil)
	pump.SetBatchSender(func([][]byte, *net.UDPAddr) {
		t.Error("the pump batch-sent datagrams for a paced tunnel itself")
	})
	pump.AddTunnel(rec)
	go pump.Run()
	select {
	case <-rec.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the super-frame's segments never reached the pacer")
	}

	if got := pump.Stats().Total.TxPackets; got != 3 {
		t.Errorf("TxPackets = %d, want 3: one per segment offered to the pacer", got)
	}
}
