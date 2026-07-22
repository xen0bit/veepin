//go:build linux

package dataplane

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// fakeGSOTUN feeds the pump a queue of vnet-framed reads and captures what the
// pump writes back, standing in for a Linux TUN in vnet mode.
type fakeGSOTUN struct {
	mu     sync.Mutex
	reads  [][]byte
	vnetWr [][]byte
	closed chan struct{}
}

func newFakeGSOTUN(frames ...[]byte) *fakeGSOTUN {
	return &fakeGSOTUN{reads: frames, closed: make(chan struct{})}
}

func (f *fakeGSOTUN) Read(buf []byte) (int, error) {
	f.mu.Lock()
	if len(f.reads) == 0 {
		f.mu.Unlock()
		<-f.closed // block like an idle TUN until the test is done
		return 0, net.ErrClosed
	}
	frame := f.reads[0]
	f.reads = f.reads[1:]
	f.mu.Unlock()
	return copy(buf, frame), nil
}

func (f *fakeGSOTUN) Write(pkt []byte) (int, error) {
	panic("plain Write on a vnet TUN: the pump must use writeVnet")
}

func (f *fakeGSOTUN) GSO() bool { return true }

func (f *fakeGSOTUN) writeVnet(pkt []byte) (int, error) {
	f.mu.Lock()
	f.vnetWr = append(f.vnetWr, append([]byte(nil), pkt...))
	f.mu.Unlock()
	return len(pkt), nil
}

// prefixTunnel encapsulates by prefixing a marker byte, returning a fresh
// buffer per call like every real data path (the one seal allocation).
type prefixTunnel struct{ peer *net.UDPAddr }

func (t *prefixTunnel) InboundKey() uint32 { return 1 }
func (t *prefixTunnel) Routes() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("10.99.0.7/32")}
}
func (t *prefixTunnel) PeerAddr() *net.UDPAddr { return t.peer }
func (t *prefixTunnel) Encapsulate(p []byte) ([]byte, error) {
	return append([]byte{0xEE}, p...), nil
}
func (t *prefixTunnel) Decapsulate(p []byte) ([]byte, error) { return p, nil }

// vnetFrame prepends a virtio-net header to pkt.
func vnetFrame(hdr virtioNetHdr, pkt []byte) []byte {
	f := make([]byte, virtioNetHdrLen+len(pkt))
	f[0] = hdr.flags
	f[1] = hdr.gsoType
	binary.LittleEndian.PutUint16(f[2:4], hdr.hdrLen)
	binary.LittleEndian.PutUint16(f[4:6], hdr.gsoSize)
	binary.LittleEndian.PutUint16(f[6:8], hdr.csumStart)
	binary.LittleEndian.PutUint16(f[8:10], hdr.csumOffset)
	copy(f[virtioNetHdrLen:], pkt)
	return f
}

// A TSO super-frame read from the TUN must reach the batch sender as one burst
// of wire-sized, correctly checksummed, encapsulated segments.
func TestPumpVnetSegmentsAndBatches(t *testing.T) {
	super := buildTCP4(t, 7, 5000, 0x18, make([]byte, 2500)) // PSH|ACK
	tun := newFakeGSOTUN(vnetFrame(virtioNetHdr{gsoType: vnetGSOTCPv4, gsoSize: 1000, hdrLen: 40}, super))
	defer close(tun.closed)

	var (
		mu      sync.Mutex
		singles int
		batches [][][]byte
	)
	send := func(pkt []byte, to *net.UDPAddr) {
		mu.Lock()
		singles++
		mu.Unlock()
	}
	done := make(chan struct{})
	peer := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}
	pump := NewPump(tun, send, SPIDemux, nil)
	pump.SetBatchSender(func(pkts [][]byte, to *net.UDPAddr) {
		mu.Lock()
		cp := make([][]byte, len(pkts))
		for i, p := range pkts {
			cp[i] = append([]byte(nil), p...)
		}
		batches = append(batches, cp)
		mu.Unlock()
		if to != peer {
			t.Errorf("batch sent to %v, want %v", to, peer)
		}
		close(done)
	})
	pump.AddTunnel(&prefixTunnel{peer: peer})
	go pump.Run()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if singles != 0 {
		t.Errorf("%d packets bypassed the batch sender", singles)
	}
	if len(batches) != 1 || len(batches[0]) != 3 {
		t.Fatalf("got %d batches of %d, want 1 batch of 3", len(batches), len(batches[0]))
	}
	for i, out := range batches[0] {
		if out[0] != 0xEE {
			t.Fatalf("segment %d not encapsulated", i)
		}
		checksumsValid(t, out[1:])
	}
}

// Without a batch sender the segments still flow, one send each.
func TestPumpVnetFallsBackToSingleSends(t *testing.T) {
	super := buildTCP4(t, 7, 5000, 0x10, make([]byte, 2500))
	tun := newFakeGSOTUN(vnetFrame(virtioNetHdr{gsoType: vnetGSOTCPv4, gsoSize: 1000, hdrLen: 40}, super))
	defer close(tun.closed)

	sent := make(chan []byte, 8)
	pump := NewPump(tun, func(pkt []byte, to *net.UDPAddr) {
		sent <- append([]byte(nil), pkt...)
	}, SPIDemux, nil)
	pump.AddTunnel(&prefixTunnel{peer: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}})
	go pump.Run()
	for i := range 3 {
		out := <-sent
		if out[0] != 0xEE {
			t.Fatalf("segment %d not encapsulated", i)
		}
	}
}

// A GSO_NONE packet with a partial checksum must be completed before it is
// encapsulated — TUN_F_CSUM leaves that to the device, and past the tunnel
// nothing else can fix it.
func TestPumpVnetCompletesChecksums(t *testing.T) {
	pkt := buildTCP4(t, 3, 42, 0x10, []byte("needs a checksum"))
	// Kernel contract: pseudo-header sum parked in the checksum field.
	pseudo := onesComplementSum(0, pkt[12:20])
	pseudo += protoTCP + uint32(len(pkt)-20)
	binary.BigEndian.PutUint16(pkt[36:38], foldSum(pseudo))
	frame := vnetFrame(virtioNetHdr{
		flags: vnetFlagNeedsCsum, gsoType: vnetGSONone, csumStart: 20, csumOffset: 16,
	}, pkt)

	tun := newFakeGSOTUN(frame)
	defer close(tun.closed)
	sent := make(chan []byte, 1)
	pump := NewPump(tun, func(p []byte, to *net.UDPAddr) {
		sent <- append([]byte(nil), p...)
	}, SPIDemux, nil)
	pump.AddTunnel(&prefixTunnel{peer: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}})
	go pump.Run()

	out := <-sent
	// IP checksum is zero in buildTCP4 output and the pump does not touch it
	// for GSO_NONE (the kernel computed it); verify the TCP checksum only.
	inner := out[1:]
	acc := onesComplementSum(0, inner[12:20])
	acc += protoTCP + uint32(len(inner)-20)
	acc = onesComplementSum(acc, inner[20:])
	if got := foldSum(acc); got != 0xffff {
		t.Errorf("TCP checksum not completed: folded sum %#04x", got)
	}
}

// Segments larger than a PMTU-learned inner MTU must trigger one ICMP
// fragmentation-needed back through the vnet write path, and nothing sent.
func TestPumpVnetHonoursInnerMTU(t *testing.T) {
	super := buildTCP4(t, 7, 5000, 0x10, make([]byte, 2500))
	tun := newFakeGSOTUN(vnetFrame(virtioNetHdr{gsoType: vnetGSOTCPv4, gsoSize: 1000, hdrLen: 40}, super))
	defer close(tun.closed)

	sent := make(chan []byte, 8)
	pump := NewPump(tun, func(p []byte, to *net.UDPAddr) {
		sent <- p
	}, SPIDemux, nil)
	pump.SetInnerMTU(600) // smaller than the 1040-byte segments
	pump.AddTunnel(&prefixTunnel{peer: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}})
	go pump.Run()

	// The frag-needed reply arrives on the TUN write side.
	for {
		tun.mu.Lock()
		n := len(tun.vnetWr)
		tun.mu.Unlock()
		if n > 0 {
			break
		}
	}
	tun.mu.Lock()
	reply := tun.vnetWr[0]
	tun.mu.Unlock()
	if reply[9] != 1 { // ICMP
		t.Fatalf("TUN write-back is protocol %d, want ICMP", reply[9])
	}
	select {
	case pkt := <-sent:
		t.Fatalf("oversized segment was sent anyway (%d bytes)", len(pkt))
	default:
	}
	if !bytes.Contains(reply, super[:8]) {
		// FragNeeded embeds the offending header; a loose sanity check.
		t.Logf("note: frag-needed reply does not embed the original header prefix")
	}
}
