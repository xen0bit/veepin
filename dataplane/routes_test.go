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

func mustIP(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}

// TestRouteTableLongestPrefixWins is the property WireGuard's cryptokey routing
// depends on: the most specific matching AllowedIPs entry selects the peer.
func TestRouteTableLongestPrefixWins(t *testing.T) {
	def := &namedTunnel{name: "default"}
	lan := &namedTunnel{name: "lan"}
	host := &namedTunnel{name: "host"}

	var rt routeTable
	rt.insert(mustPrefix(t, "0.0.0.0/0"), bound{t: def})
	rt.insert(mustPrefix(t, "10.0.0.0/8"), bound{t: lan})
	rt.insert(mustPrefix(t, "10.1.2.3/32"), bound{t: host})

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
		got := rt.lookup(mustIP(t, tc.ip)).t
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
	rt.insert(mustPrefix(t, "10.0.0.0/24"), bound{t: peer})

	if got := rt.lookup(mustIP(t, "10.0.0.5")).t; got != Tunnel(peer) {
		t.Error("in-range address did not match")
	}
	if got := rt.lookup(mustIP(t, "10.0.1.5")).t; got != nil {
		t.Error("out-of-range address matched; a narrow AllowedIPs must drop it")
	}
	if got := rt.lookup(mustIP(t, "8.8.8.8")).t; got != nil {
		t.Error("unrelated address matched")
	}
}

func TestRouteTableRemove(t *testing.T) {
	a := &namedTunnel{name: "a"}
	b := &namedTunnel{name: "b"}
	var rt routeTable
	rt.insert(mustPrefix(t, "10.0.0.0/8"), bound{t: a})
	rt.insert(mustPrefix(t, "10.1.0.0/16"), bound{t: b})

	if got := rt.lookup(mustIP(t, "10.1.2.3")).t; got != Tunnel(b) {
		t.Fatal("more specific route did not win before removal")
	}
	// Removing the /16 must fall back to the /8, not to nothing.
	rt.remove(mustPrefix(t, "10.1.0.0/16"))
	if got := rt.lookup(mustIP(t, "10.1.2.3")).t; got != Tunnel(a) {
		t.Fatal("after removing the /16, the /8 should carry the address")
	}
	rt.remove(mustPrefix(t, "10.0.0.0/8"))
	if got := rt.lookup(mustIP(t, "10.1.2.3")).t; got != nil {
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
	rt.insert(p, bound{t: old})
	rt.insert(p, bound{t: new})
	if got := rt.lookup(mustIP(t, "10.0.0.1")).t; got != Tunnel(new) {
		t.Fatal("re-inserting a prefix did not replace its tunnel")
	}
}

// TestRouteTableMasksHostBits accepts a prefix written with host bits set (as a
// hand-edited wg-quick AllowedIPs might be) and treats it as the network.
func TestRouteTableMasksHostBits(t *testing.T) {
	peer := &namedTunnel{name: "peer"}
	var rt routeTable
	// 10.0.0.5/24 means the 10.0.0.0/24 network.
	rt.insert(netip.MustParsePrefix("10.0.0.5/24"), bound{t: peer})
	if got := rt.lookup(mustIP(t, "10.0.0.200")).t; got != Tunnel(peer) {
		t.Fatal("prefix with host bits set was not masked to its network")
	}
}

// TestRouteTableDualStack covers the v6 trie living alongside the v4 one: a
// dual-stack tunnel owns a prefix in each family, longest-prefix match works
// independently per family, and a lookup never crosses families.
func TestRouteTableDualStack(t *testing.T) {
	def6 := &namedTunnel{name: "def6"}
	host6 := &namedTunnel{name: "host6"}
	v4 := &namedTunnel{name: "v4"}

	var rt routeTable
	rt.insert(mustPrefix(t, "10.0.0.0/8"), bound{t: v4})
	rt.insert(mustPrefix(t, "::/0"), bound{t: def6})
	rt.insert(mustPrefix(t, "2001:db8::1/128"), bound{t: host6})

	for _, tc := range []struct {
		ip   string
		want *namedTunnel
	}{
		{"2001:db8::1", host6}, // exact /128 beats ::/0
		{"2001:db8::2", def6},  // neighbour falls back to the v6 default
		{"fe80::1", def6},      // any other v6 address hits ::/0
		{"10.9.9.9", v4},       // v4 lookup is unaffected by the v6 routes
	} {
		got := rt.lookup(mustIP(t, tc.ip)).t
		if got != Tunnel(tc.want) {
			gotName := "<nil>"
			if g, ok := got.(*namedTunnel); ok {
				gotName = g.name
			}
			t.Errorf("lookup(%s) = %s, want %s", tc.ip, gotName, tc.want.name)
		}
	}

	// A v4-only table must not answer a v6 lookup, and vice versa.
	var only4 routeTable
	only4.insert(mustPrefix(t, "10.0.0.0/8"), bound{t: v4})
	if got := only4.lookup(mustIP(t, "2001:db8::1")).t; got != nil {
		t.Error("v6 lookup matched in a v4-only table")
	}
}
