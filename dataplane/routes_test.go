package dataplane

import (
	"net"
	"net/netip"
	"testing"
)

// namedTunnel is a Tunnel that only needs to be distinguishable by identity.
type namedTunnel struct {
	name   string
	routes []netip.Prefix
}

func (t *namedTunnel) InboundKey() uint32                   { return 0 }
func (t *namedTunnel) Routes() []netip.Prefix               { return t.routes }
func (t *namedTunnel) PeerAddr() *net.UDPAddr               { return nil }
func (t *namedTunnel) Encapsulate(p []byte) ([]byte, error) { return p, nil }
func (t *namedTunnel) Decapsulate(p []byte) ([]byte, error) { return p, nil }

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix %q: %v", s, err)
	}
	return p
}

func mustIP(t *testing.T, s string) uint32 {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return addrBits(a)
}

// TestRouteTableLongestPrefixWins is the property WireGuard's cryptokey routing
// depends on: the most specific matching AllowedIPs entry selects the peer.
func TestRouteTableLongestPrefixWins(t *testing.T) {
	def := &namedTunnel{name: "default"}
	lan := &namedTunnel{name: "lan"}
	host := &namedTunnel{name: "host"}

	var rt routeTable
	rt.insert(mustPrefix(t, "0.0.0.0/0"), def)
	rt.insert(mustPrefix(t, "10.0.0.0/8"), lan)
	rt.insert(mustPrefix(t, "10.1.2.3/32"), host)

	for _, tc := range []struct {
		ip   string
		want *namedTunnel
	}{
		{"10.1.2.3", host}, // exact /32 beats /8 and /0
		{"10.9.9.9", lan},  // inside /8, no /32
		{"192.0.2.1", def}, // only the default matches
		{"10.1.2.4", lan},  // neighbour of the /32 falls back to /8
		{"255.255.255.255", def},
	} {
		got := rt.lookup(mustIP(t, tc.ip))
		if got != Tunnel(tc.want) {
			gotName := "<nil>"
			if g, ok := got.(*namedTunnel); ok {
				gotName = g.name
			}
			t.Errorf("lookup(%s) = %s, want %s", tc.ip, gotName, tc.want.name)
		}
	}
}

// TestRouteTableNoDefaultDropsUnmatched checks that without a 0.0.0.0/0 route an
// unmatched destination is dropped rather than sent somewhere arbitrary. This is
// what makes a narrow AllowedIPs actually restrictive.
func TestRouteTableNoDefaultDropsUnmatched(t *testing.T) {
	var rt routeTable
	if !rt.empty() {
		t.Fatal("fresh table reports non-empty")
	}
	peer := &namedTunnel{name: "peer"}
	rt.insert(mustPrefix(t, "10.0.0.0/24"), peer)

	if got := rt.lookup(mustIP(t, "10.0.0.5")); got != Tunnel(peer) {
		t.Error("in-range address did not match")
	}
	if got := rt.lookup(mustIP(t, "10.0.1.5")); got != nil {
		t.Error("out-of-range address matched; a narrow AllowedIPs must drop it")
	}
	if got := rt.lookup(mustIP(t, "8.8.8.8")); got != nil {
		t.Error("unrelated address matched")
	}
}

func TestRouteTableRemove(t *testing.T) {
	a := &namedTunnel{name: "a"}
	b := &namedTunnel{name: "b"}
	var rt routeTable
	rt.insert(mustPrefix(t, "10.0.0.0/8"), a)
	rt.insert(mustPrefix(t, "10.1.0.0/16"), b)

	if got := rt.lookup(mustIP(t, "10.1.2.3")); got != Tunnel(b) {
		t.Fatal("more specific route did not win before removal")
	}
	// Removing the /16 must fall back to the /8, not to nothing.
	rt.remove(mustPrefix(t, "10.1.0.0/16"))
	if got := rt.lookup(mustIP(t, "10.1.2.3")); got != Tunnel(a) {
		t.Fatal("after removing the /16, the /8 should carry the address")
	}
	rt.remove(mustPrefix(t, "10.0.0.0/8"))
	if got := rt.lookup(mustIP(t, "10.1.2.3")); got != nil {
		t.Fatal("after removing both routes the address should be unmatched")
	}
	// Removing a route that was never inserted is a no-op, not a panic.
	rt.remove(mustPrefix(t, "192.0.2.0/24"))
}

// TestRouteTableInsertReplaces covers a peer's prefix moving to another tunnel,
// which is what a rekey or a reconfigured peer looks like.
func TestRouteTableInsertReplaces(t *testing.T) {
	old := &namedTunnel{name: "old"}
	new := &namedTunnel{name: "new"}
	var rt routeTable
	p := mustPrefix(t, "10.0.0.0/24")
	rt.insert(p, old)
	rt.insert(p, new)
	if got := rt.lookup(mustIP(t, "10.0.0.1")); got != Tunnel(new) {
		t.Fatal("re-inserting a prefix did not replace its tunnel")
	}
}

// TestRouteTableMasksHostBits accepts a prefix written with host bits set (as a
// hand-edited wg-quick AllowedIPs might be) and treats it as the network.
func TestRouteTableMasksHostBits(t *testing.T) {
	peer := &namedTunnel{name: "peer"}
	var rt routeTable
	// 10.0.0.5/24 means the 10.0.0.0/24 network.
	rt.insert(netip.MustParsePrefix("10.0.0.5/24"), peer)
	if got := rt.lookup(mustIP(t, "10.0.0.200")); got != Tunnel(peer) {
		t.Fatal("prefix with host bits set was not masked to its network")
	}
}

// TestRouteTableIgnoresNonIPv4 documents that the table is IPv4-only, matching
// the data path, and that an IPv6 prefix is dropped rather than mis-stored.
func TestRouteTableIgnoresNonIPv4(t *testing.T) {
	var rt routeTable
	rt.insert(netip.MustParsePrefix("2001:db8::/32"), &namedTunnel{name: "v6"})
	if !rt.empty() {
		t.Fatal("an IPv6 prefix was stored in the IPv4 table")
	}
}
