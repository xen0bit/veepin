//go:build linux

package dataplane

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// multiSPITunnel is spiTunnel plus MultiTunnel: one datagram carries a run of
// length-prefixed inner packets, and Decapsulate -- the single-packet method --
// REFUSES to open it.
//
// The refusal is the point. A tunnel whose aggregating format is merely
// inefficient to read one packet at a time would hide the bug this file exists
// for; IKEv2's AGGFRAG tunnel is not that. espTunnel.Decapsulate rejects ESP
// next header 144 outright, so a receive path that reached for the wrong method
// dropped every packet while the handshake reported IP-TFS negotiated and
// working. This fake reproduces that shape exactly.
type multiSPITunnel struct{ peer *net.UDPAddr }

func (t *multiSPITunnel) InboundKey() uint32 { return 1 }
func (t *multiSPITunnel) Routes() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
}
func (t *multiSPITunnel) PeerAddr() *net.UDPAddr { return t.peer }
func (t *multiSPITunnel) Encapsulate(p []byte) ([]byte, error) {
	return append([]byte{0, 0, 0, 1}, p...), nil
}

var errNotSinglePacket = errors.New("this datagram carries several packets")

func (t *multiSPITunnel) Decapsulate([]byte) ([]byte, error) { return nil, errNotSinglePacket }

func (t *multiSPITunnel) DecapsulateMulti(pkt []byte, out [][]byte) ([][]byte, error) {
	body := pkt[4:]
	for len(body) >= 2 {
		n := int(body[0])<<8 | int(body[1])
		body = body[2:]
		if n == 0 || n > len(body) {
			break
		}
		out = append(out, body[:n])
		body = body[n:]
	}
	return out, nil
}

// buildUDP4 is a well-formed IPv4/UDP packet of the given total length, which
// GRO deliberately does not coalesce -- so each one reaches the TUN as its own
// write and the test can see them individually.
func buildUDP4(t *testing.T, srcPort uint16, total int) []byte {
	t.Helper()
	if total < 28 {
		t.Fatalf("buildUDP4: %d octets is shorter than an IPv4+UDP header", total)
	}
	p := make([]byte, total)
	p[0] = 0x45
	p[2], p[3] = byte(total>>8), byte(total)
	p[8] = 64 // TTL
	p[9] = 17 // UDP
	copy(p[12:16], []byte{10, 0, 0, 1})
	copy(p[16:20], []byte{10, 0, 0, 2})
	p[20], p[21] = byte(srcPort>>8), byte(srcPort)
	p[22], p[23] = 0, 53
	udpLen := total - 20
	p[24], p[25] = byte(udpLen>>8), byte(udpLen)
	for i := 28; i < total; i++ {
		p[i] = byte(i)
	}
	return p
}

// aggregate builds one datagram carrying every packet given.
func aggregate(pkts ...[]byte) []byte {
	out := []byte{0, 0, 0, 1}
	for _, p := range pkts {
		out = append(out, byte(len(p)>>8), byte(len(p)))
		out = append(out, p...)
	}
	return out
}

func groMultiPump(t *testing.T) (*Pump, *fakeGSOTUN) {
	t.Helper()
	tun := newFakeGSOTUN()
	pump := NewPump(tun, func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
	pump.AddTunnel(&multiSPITunnel{peer: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}})
	return pump, tun
}

// TestTheGROBatchPathHonoursMultiTunnel is a regression test for a bug that
// three separate test suites were structurally unable to see.
//
// The vnet batch path called decapInbound unconditionally -- the
// one-datagram-one-packet decapsulator -- so on any TUN that negotiated the
// virtio-net header, an aggregating tunnel's inbound packets went to the wrong
// method and were dropped. HandleInbound checked (and still does), which is why
// dataplane's own tests passed: they use a plain TUN. The veepin client
// negotiates GSO, so the real path was this one. And a veepin-to-veepin cell
// breaks identically at both ends, which reads as a dead tunnel rather than as
// a wrong receive path.
func TestTheGROBatchPathHonoursMultiTunnel(t *testing.T) {
	pump, tun := groMultiPump(t)

	first := buildUDP4(t, 1111, 40)
	second := buildUDP4(t, 2222, 60)
	pump.HandleInboundBatch([][]byte{aggregate(first, second)}, nil)

	got := tun.vnetWrites()
	if len(got) == 0 {
		t.Fatal("nothing reached the TUN: the aggregated datagram went to Decapsulate, " +
			"which cannot open it, so every inner packet was dropped")
	}
	var all []byte
	for _, w := range got {
		all = append(all, w...)
	}
	if !bytes.Contains(all, first) {
		t.Error("the first inner packet never reached the TUN")
	}
	if !bytes.Contains(all, second) {
		t.Error("the second inner packet never reached the TUN — only the first was delivered")
	}
}

// TestTheGROBatchPathCountsEveryInnerPacket. An aggregating tunnel carries
// several packets per datagram, so counting datagrams would report an IP-TFS
// tunnel moving a fraction of what it moved — the same reasoning
// handleInboundMulti already carries.
func TestTheGROBatchPathCountsEveryInnerPacket(t *testing.T) {
	pump, _ := groMultiPump(t)

	first := buildUDP4(t, 1111, 40)
	second := buildUDP4(t, 2222, 60)
	pump.HandleInboundBatch([][]byte{aggregate(first, second)}, nil)

	total := pump.Stats().Total
	if total.RxPackets != 2 {
		t.Errorf("RxPackets = %d, want 2 (one per inner packet, not one per datagram)",
			total.RxPackets)
	}
	if want := uint64(len(first) + len(second)); total.RxBytes != want {
		t.Errorf("RxBytes = %d, want %d", total.RxBytes, want)
	}
}

// TestTheGROBatchPathStillMarksTheTunnelAlive. Liveness is what `veepin connect`
// re-dials on, so an aggregating tunnel whose inbound traffic did not count as
// proof of life would be torn down and rebuilt while it was working.
func TestTheGROBatchPathStillMarksTheTunnelAlive(t *testing.T) {
	pump, _ := groMultiPump(t)
	pump.HandleInboundBatch([][]byte{aggregate(buildUDP4(t, 1111, 40))}, nil)

	if idle := pump.IdleFor(); idle > time.Second {
		t.Errorf("IdleFor() = %v after an aggregated datagram arrived; the pump did not "+
			"count it as proof of life", idle)
	}
}
