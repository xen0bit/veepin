//go:build linux

package dataplane

import (
	"bytes"
	"net"
	"testing"
)

// TestAGSOBurstGivesEverySegmentItsOwnBuffer. A burst holds every
// encapsulated segment until one batched send flushes them, so an
// AppendTunnel's segments cannot share the pump's single output buffer: they
// would all be the last one by the time the flush read them, and the receiver
// would see one segment N times and the rest never.
func TestAGSOBurstGivesEverySegmentItsOwnBuffer(t *testing.T) {
	super := buildTCP4(t, 7, 5000, 0x18, patterned(2500))
	tun := newFakeGSOTUN(vnetFrame(virtioNetHdr{gsoType: vnetGSOTCPv4, gsoSize: 1000, hdrLen: 40}, super))
	defer close(tun.closed)

	serverSA, clientSA := espPair(t)
	done := make(chan [][]byte, 1)
	pump := NewPump(tun, func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
	pump.SetBatchSender(func(pkts [][]byte, _ *net.UDPAddr) {
		cp := make([][]byte, len(pkts))
		for i, p := range pkts {
			cp[i] = append([]byte(nil), p...)
		}
		done <- cp
	})
	pump.AddTunnel(&benchTunnel{sa: serverSA, in: serverSA.SPIIn, ip: net.IPv4(10, 99, 0, 7).To4()})
	go pump.Run()
	burst := <-done

	if len(burst) != 3 {
		t.Fatalf("got a burst of %d, want 3 segments", len(burst))
	}
	var payload []byte
	for i, d := range burst {
		inner, _, err := clientSA.Decapsulate(d)
		if err != nil {
			t.Fatalf("segment %d does not open: %v", i, err)
		}
		payload = append(payload, inner[40:]...)
	}
	if !bytes.Equal(payload, patterned(2500)) {
		t.Fatal("the segments do not reassemble to the super-frame: they shared a buffer")
	}
}
