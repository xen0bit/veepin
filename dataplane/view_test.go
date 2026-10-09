package dataplane

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

// TestARouteTableSnapshotNeverChanges is the property the lock-free packet path
// stands on. The pump publishes a routeTable value and readers walk it with no
// lock while the next one is built; if insert or remove wrote through a node
// the published value can reach, a reader would see a route appear or vanish
// mid-walk -- a race the detector catches only if a test happens to schedule
// it, and a misrouted packet in production when it does not.
func TestARouteTableSnapshotNeverChanges(t *testing.T) {
	a, b := &namedTunnel{name: "a"}, &namedTunnel{name: "b"}
	var rt routeTable
	rt.insert(mustPrefix(t, "10.0.0.0/8"), bound{t: a})
	rt.insert(mustPrefix(t, "2001:db8::/32"), bound{t: a})
	before := rt // what a reader holds

	rt.insert(mustPrefix(t, "10.1.0.0/16"), bound{t: b})
	rt.insert(mustPrefix(t, "2001:db8::1/128"), bound{t: b})
	rt.remove(mustPrefix(t, "10.0.0.0/8"))
	rt.removeOwned(mustPrefix(t, "2001:db8::/32"), a)

	for _, ip := range []string{"10.1.2.3", "10.9.9.9", "2001:db8::1", "2001:db8::2"} {
		if got := before.lookup(mustIP(t, ip)).t; got != Tunnel(a) {
			t.Errorf("the snapshot taken before the changes now routes %s to %v, want a", ip, got)
		}
	}
	if got := rt.lookup(mustIP(t, "10.1.2.3")).t; got != Tunnel(b) {
		t.Errorf("the new table does not route 10.1.2.3 to b")
	}
	if got := rt.lookup(mustIP(t, "10.9.9.9")).t; got != nil {
		t.Errorf("the new table still routes 10.9.9.9 after its /8 was removed")
	}
}

// TestAnInboundPacketIsDemuxedOnce. The aggregating branch used to demux and
// look a packet up, find it was not for an aggregating tunnel, and leave the
// ordinary path to do both again -- on every packet, for every protocol, to
// serve the one tunnel type that needed the check.
func TestAnInboundPacketIsDemuxedOnce(t *testing.T) {
	var calls atomic.Int64
	demux := func(pkt []byte) (uint32, bool) {
		calls.Add(1)
		return SPIDemux(pkt)
	}
	pump := NewPump(newFakeTUN(), func([]byte, *net.UDPAddr) {}, demux, nil)
	pump.AddTunnel(newRoamTunnel(7, roamHome))

	pump.HandleInbound(roamDatagram(7, 0x00), nil) // fails to authenticate
	pump.HandleInboundBatch([][]byte{roamDatagram(7, 0x00), roamDatagram(9, 0x00)}, nil)
	if n := calls.Load(); n != 3 {
		t.Fatalf("three datagrams cost %d demux calls, want 3", n)
	}
}

// TestRegistrationRacesThePacketPathSafely runs both directions of the packet
// path flat out while tunnels are added and removed underneath them. It
// asserts nothing on its own: it exists for -race, which is where a snapshot
// that was modified after publication, or a reader that held a pointer into the
// writer's working copy, shows up.
func TestRegistrationRacesThePacketPathSafely(t *testing.T) {
	pump := NewPump(newFakeTUN(), func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() { // the inbound goroutine
		defer wg.Done()
		pkt := roamDatagram(7, 0x00)
		for {
			select {
			case <-stop:
				return
			default:
				pump.HandleInboundBatch([][]byte{pkt, pkt}, nil)
			}
		}
	}()
	wg.Add(1)
	go func() { // the TUN reader
		defer wg.Done()
		pkt := makeIPv4(net.IPv4(10, 0, 0, 2), []byte("x"))
		for {
			select {
			case <-stop:
				return
			default:
				pump.routeOutbound(pkt)
			}
		}
	}()

	for i := range 500 {
		tun := &routedRoamTunnel{roamTunnel: *newRoamTunnel(7, roamHome),
			prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i), 2}), 32)}
		pump.AddTunnel(tun)
		pump.AddInboundKey(uint32(1000+i), tun)
		pump.SetInnerMTU(1400 - i%2)
		pump.RemoveInboundKey(uint32(1000 + i))
		pump.RemoveTunnel(tun)
	}
	close(stop)
	wg.Wait()
}

type routedRoamTunnel struct {
	roamTunnel
	prefix netip.Prefix
}

func (t *routedRoamTunnel) Routes() []netip.Prefix {
	return []netip.Prefix{t.prefix, netip.MustParsePrefix("10.0.0.2/32")}
}
