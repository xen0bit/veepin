package nebula

import (
	"net"
	"testing"

	"github.com/xen0bit/veepin/dataplane"
)

// Nebula spent its whole existence as the one UDP server in this tree replying
// from a kernel-chosen source address, because its socket interface used short
// method names that dataplane.PacketConn does not have. The facade papered over
// that with a private adapter around a bare *net.UDPConn, so the wrapper every
// other server adopted was silently bypassed -- and nothing failed, because the
// symptom only appears on a multi-homed host.
//
// These assertions are the guard: if the interface drifts back to names that
// PacketConn does not satisfy, this stops compiling rather than quietly
// reintroducing an adapter.
var (
	_ packetConn = (*dataplane.PacketConn)(nil)
	_ packetConn = (*net.UDPConn)(nil)
)

func TestPacketConnIsUsableDirectly(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer c.Close()

	// The point is that this needs no adapter at all.
	var pc packetConn = dataplane.NewPacketConn(c)
	if pc.LocalAddr() == nil {
		t.Error("wrapped socket reports no local address")
	}
}
