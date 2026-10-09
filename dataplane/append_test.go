package dataplane

import (
	"bytes"
	"net"
	"testing"
)

// TestTheESPDataPathAllocatesNothing is what the scaling profile asked for: the
// one allocation each direction made was what capped throughput across cores,
// and with it gone both directions of the pump cost nothing per packet. If this
// fails, someone has put a buffer back on the path -- an Encapsulate that
// returns a fresh slice to an AppendTunnel-aware pump, a Decapsulate that opens
// into a copy -- and the parallel scaling the change bought goes with it.
func TestTheESPDataPathAllocatesNothing(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are perturbed by the race detector")
	}
	serverSA, clientSA := espPair(t)
	client := net.IPv4(10, 0, 0, 2).To4()
	tun := &discardTUN{}
	pump := NewPump(tun, func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
	pump.AddTunnel(&benchTunnel{sa: serverSA, in: serverSA.SPIIn, ip: client})

	out := makeIPv4(client, bytes.Repeat([]byte{0x5a}, 1380))
	pump.routeOutbound(out) // warm the crypter and the pump's buffer
	if n := testing.AllocsPerRun(200, func() { pump.routeOutbound(out) }); n != 0 {
		t.Errorf("outbound allocs/op = %v, want 0", n)
	}

	in, err := clientSA.Encapsulate(makeIPv4(net.IPv4(10, 0, 0, 1), bytes.Repeat([]byte{0xa5}, 1380)), 4)
	if err != nil {
		t.Fatal(err)
	}
	work := make([]byte, len(in))
	if n := testing.AllocsPerRun(200, func() {
		copy(work, in)
		serverSA.ResetReplayWindow()
		pump.HandleInbound(work, nil)
	}); n != 0 {
		t.Errorf("inbound allocs/op = %v, want 0", n)
	}
	if tun.writes == 0 {
		t.Fatal("no inbound packet reached the TUN: the measurement was of the drop path")
	}
}

// TestAReusedBufferStillCarriesEachPacket: the pump builds every datagram in
// one buffer it keeps, so a sender that copies before it returns (as every
// sender here does) must see each packet whole, and never the previous one.
func TestAReusedBufferStillCarriesEachPacket(t *testing.T) {
	serverSA, clientSA := espPair(t)
	client := net.IPv4(10, 0, 0, 2).To4()
	var sent [][]byte
	pump := NewPump(&discardTUN{}, func(p []byte, _ *net.UDPAddr) {
		sent = append(sent, append([]byte(nil), p...))
	}, SPIDemux, nil)
	pump.AddTunnel(&benchTunnel{sa: serverSA, in: serverSA.SPIIn, ip: client})

	var want [][]byte
	for i, size := range []int{1400, 60, 700} {
		pkt := makeIPv4(client, bytes.Repeat([]byte{byte(i + 1)}, size))
		want = append(want, pkt)
		pump.routeOutbound(pkt)
	}
	if len(sent) != len(want) {
		t.Fatalf("sent %d datagrams, want %d", len(sent), len(want))
	}
	for i, d := range sent {
		inner, _, err := clientSA.Decapsulate(d)
		if err != nil {
			t.Fatalf("datagram %d does not open: %v", i, err)
		}
		if !bytes.Equal(inner, want[i]) {
			t.Fatalf("datagram %d carried the wrong packet", i)
		}
	}
}
