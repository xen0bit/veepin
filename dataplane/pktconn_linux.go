//go:build linux

package dataplane

// Replying from the address a packet arrived on.
//
// Every UDP server here binds the wildcard by default, which is what you want:
// one socket serving whatever addresses the host has. The problem is the reply.
// A socket bound to 0.0.0.0 has no source address of its own, so the kernel
// picks one by route lookup at send time — and on a multi-homed host that is
// frequently not the address the client sent to. The client sees a reply from an
// address it never contacted and drops it.
//
// Every protocol in this tree is affected, and none of the tests can see it: the
// interop matrix runs on single-homed containers, where the route lookup picks
// the only address there is. It stays invisible until someone deploys on a host
// with two interfaces, where it looks like the protocol is broken.
//
// IP_PKTINFO fixes it: the kernel attaches the destination address to each
// received datagram, and the same address can be pinned as the source on the
// reply. That is one socket option and a control message — not a new dependency,
// since golang.org/x/sys was already in the module graph.
//
// # Why the local address is remembered rather than passed
//
// The obvious API takes the local address as a parameter, which has no hidden
// state and is honest about what is happening. It also means threading a new
// argument through every send path in nine servers, which is a large enough
// change that in practice only some of them would adopt it.
//
// So the local address is remembered per peer instead, and the write path looks
// it up: "reply to a peer from wherever it last reached us" is what every one of
// these servers wants, and it makes this a drop-in replacement for *net.UDPConn.
// The cost is a map, bounded the same way the admission gate's is — an unbounded
// one would be the very denial of service that gate exists to prevent.

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// peerAddrIdle is how long a peer's local-address association is kept after
	// it goes quiet.
	peerAddrIdle = 10 * time.Minute
	// peerAddrMax caps the association table regardless of idleness, so a flood
	// from many sources cannot grow it without bound between sweeps.
	peerAddrMax = 8192
)

// PacketConn is a UDP socket that replies from the address a request arrived on.
// It is a drop-in for the subset of *net.UDPConn these servers use.
type PacketConn struct {
	conn *net.UDPConn
	// pktInfo is false when the socket option is unavailable, in which case
	// this behaves exactly as the bare socket did.
	pktInfo bool

	mu     sync.Mutex
	locals map[netip.AddrPort]localEntry
	lastGC time.Time
	now    func() time.Time
}

type localEntry struct {
	addr netip.Addr
	seen time.Time
}

// NewPacketConn wraps a UDP socket.
//
// Failure to enable the option is not an error. The socket keeps its previous
// behaviour, which is correct on the single-homed hosts that cover most
// deployments; PreservesSource reports which case is in effect.
func NewPacketConn(conn *net.UDPConn) *PacketConn {
	p := &PacketConn{
		conn:   conn,
		locals: map[netip.AddrPort]localEntry{},
		now:    time.Now,
	}
	p.lastGC = p.now()

	if raw, err := conn.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err == nil {
				p.pktInfo = true
			}
		})
	}
	return p
}

// Conn exposes the underlying socket for paths that need it directly.
func (p *PacketConn) Conn() *net.UDPConn { return p.conn }

// PreservesSource reports whether source addresses are actually being pinned, so
// a server can say so at startup rather than assume it.
func (p *PacketConn) PreservesSource() bool { return p.pktInfo }

// ReadFromUDP reads one datagram, recording which local address it was sent to.
func (p *PacketConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	if !p.pktInfo {
		return p.conn.ReadFromUDP(b)
	}

	oob := make([]byte, 512)
	n, oobn, _, from, err := p.conn.ReadMsgUDP(b, oob)
	if err != nil {
		return n, from, err
	}
	if local := localFromControl(oob[:oobn]); local.IsValid() && from != nil {
		p.remember(from, local)
	}
	return n, from, nil
}

// WriteToUDP sends a datagram, from the address this peer last reached us on
// when that is known. A peer we have not heard from falls back to the kernel's
// choice, which is all that is available and is correct for an unsolicited send.
func (p *PacketConn) WriteToUDP(b []byte, to *net.UDPAddr) (int, error) {
	if !p.pktInfo || to == nil {
		return p.conn.WriteToUDP(b, to)
	}

	local, ok := p.lookup(to)
	if !ok || !local.Is4() {
		return p.conn.WriteToUDP(b, to)
	}
	info := unix.Inet4Pktinfo{Spec_dst: local.As4()}
	n, _, err := p.conn.WriteMsgUDP(b, unix.PktInfo4(&info), to)
	return n, err
}

// ReadFromUDPAddrPort and WriteToUDPAddrPort are the netip forms, for engines
// that speak netip.AddrPort rather than *net.UDPAddr. They are not a second
// implementation — they convert and delegate — so a protocol does not have to
// choose between the address type it wants and having its source address
// preserved. Nebula wanted exactly that, and for a while had a private adapter
// over a bare socket instead, which quietly opted it out of this whole file.
func (p *PacketConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	n, from, err := p.ReadFromUDP(b)
	if from == nil {
		return n, netip.AddrPort{}, err
	}
	ap, ok := addrPortOf(from)
	if !ok {
		return n, netip.AddrPort{}, err
	}
	return n, ap, err
}

func (p *PacketConn) WriteToUDPAddrPort(b []byte, to netip.AddrPort) (int, error) {
	return p.WriteToUDP(b, net.UDPAddrFromAddrPort(to))
}

// Close closes the socket.
func (p *PacketConn) Close() error { return p.conn.Close() }

// LocalAddr is the socket's bound address.
func (p *PacketConn) LocalAddr() net.Addr { return p.conn.LocalAddr() }

// SetReadDeadline forwards to the socket.
func (p *PacketConn) SetReadDeadline(t time.Time) error { return p.conn.SetReadDeadline(t) }

func (p *PacketConn) remember(from *net.UDPAddr, local netip.Addr) {
	ap, ok := addrPortOf(from)
	if !ok {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.gc(now)
	p.locals[ap] = localEntry{addr: local, seen: now}
}

func (p *PacketConn) lookup(to *net.UDPAddr) (netip.Addr, bool) {
	ap, ok := addrPortOf(to)
	if !ok {
		return netip.Addr{}, false
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.locals[ap]
	return e.addr, ok
}

// gc bounds the association table. Caller holds p.mu.
func (p *PacketConn) gc(now time.Time) {
	// Size is checked every call, because a flood can outrun the timer between
	// sweeps and the point of this table is not to become the leak that the
	// admission gate exists to prevent.
	overSize := len(p.locals) > peerAddrMax
	if !overSize && now.Sub(p.lastGC) < peerAddrIdle {
		return
	}
	p.lastGC = now

	for ap, e := range p.locals {
		if now.Sub(e.seen) > peerAddrIdle {
			delete(p.locals, ap)
		}
	}
	// If idle eviction was not enough, entries are arriving faster than they
	// age out. Dropping the table is safe: every entry is a cache that the next
	// datagram from that peer re-establishes, and the behaviour while it is
	// empty is exactly what this wrapper replaces.
	if len(p.locals) > peerAddrMax {
		p.locals = map[netip.AddrPort]localEntry{}
	}
}

func addrPortOf(a *net.UDPAddr) (netip.AddrPort, bool) {
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port)), true
}

// localFromControl extracts the destination address from a datagram's control
// messages, returning the zero Addr when absent.
func localFromControl(oob []byte) netip.Addr {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}
	}
	for _, m := range msgs {
		if m.Header.Level != unix.IPPROTO_IP || m.Header.Type != unix.IP_PKTINFO {
			continue
		}
		// struct in_pktinfo is { int32 ifindex; be32 spec_dst; be32 addr },
		// decoded by offset rather than through unsafe: the layout is fixed by
		// the kernel ABI, and x/sys ships an encoder but no parser.
		if len(m.Data) < 12 {
			continue
		}
		// spec_dst is the address the datagram was addressed to, which is what a
		// reply must come from. addr is the interface's primary address, which
		// differs on a host with several addresses on one interface.
		return netip.AddrFrom4([4]byte(m.Data[4:8]))
	}
	return netip.Addr{}
}
