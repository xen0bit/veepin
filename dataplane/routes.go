package dataplane

import "net/netip"

// routeTable maps an inner IPv4 destination to the tunnel that carries it, by
// longest-prefix match.
//
// A /32 map would do for IKEv2, where every client owns exactly one assigned
// address, but WireGuard's cryptokey routing gives each peer a set of prefixes
// (AllowedIPs) and picks the most specific match. Both fit here: a /32 is just a
// full-length prefix, and a client's "everything goes to the server" is
// 0.0.0.0/0.
//
// It is an uncompressed binary trie over the 32 address bits. Depth is bounded
// by the prefix length, so the common shapes are cheap: a lone default route
// resolves at the root, and the walk stops as soon as it runs out of children.
type routeTable struct {
	root *routeNode
}

type routeNode struct {
	child [2]*routeNode
	val   Tunnel
	set   bool
}

// insert adds or replaces the tunnel for p. Only IPv4 prefixes are stored;
// anything else is ignored, since the data path tunnels IPv4 only.
func (t *routeTable) insert(p netip.Prefix, v Tunnel) {
	p = p.Masked()
	if !p.Addr().Is4() {
		return
	}
	if t.root == nil {
		t.root = &routeNode{}
	}
	n := t.root
	bits := addrBits(p.Addr())
	for i := 0; i < p.Bits(); i++ {
		b := (bits >> (31 - i)) & 1
		if n.child[b] == nil {
			n.child[b] = &routeNode{}
		}
		n = n.child[b]
	}
	n.val, n.set = v, true
}

// remove drops p's entry. Interior nodes are left in place: route sets are small
// and churn with SA lifetime, not per packet, so pruning would buy nothing.
func (t *routeTable) remove(p netip.Prefix) {
	p = p.Masked()
	if !p.Addr().Is4() || t.root == nil {
		return
	}
	n := t.root
	bits := addrBits(p.Addr())
	for i := 0; i < p.Bits(); i++ {
		b := (bits >> (31 - i)) & 1
		if n.child[b] == nil {
			return
		}
		n = n.child[b]
	}
	n.val, n.set = nil, false
}

// lookup returns the tunnel whose prefix matches ip most specifically, or nil.
func (t *routeTable) lookup(ip uint32) Tunnel {
	n := t.root
	var best Tunnel
	for i := 0; n != nil; i++ {
		if n.set {
			best = n.val
		}
		if i == 32 {
			break
		}
		n = n.child[(ip>>(31-i))&1]
	}
	return best
}

// empty reports whether any route is installed.
func (t *routeTable) empty() bool { return t.root == nil }

// addrBits returns an IPv4 address as a big-endian uint32.
func addrBits(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
