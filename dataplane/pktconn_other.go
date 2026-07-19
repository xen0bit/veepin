//go:build !linux

package dataplane

// The non-Linux PacketConn: a pass-through.
//
// IP_PKTINFO is a Linux socket option. Elsewhere this keeps the plain socket
// behaviour, which is what every server did before the wrapper existed and is
// correct on a single-homed host. PreservesSource reports false so a server can
// say which case it is in rather than assume.

import (
	"net"
	"net/netip"
	"time"
)

// PacketConn wraps a UDP socket without altering source-address selection.
type PacketConn struct{ conn *net.UDPConn }

// NewPacketConn wraps a UDP socket.
func NewPacketConn(conn *net.UDPConn) *PacketConn { return &PacketConn{conn: conn} }

// Conn exposes the underlying socket.
func (p *PacketConn) Conn() *net.UDPConn { return p.conn }

// PreservesSource is false: the platform offers no way to pin a reply's source.
func (p *PacketConn) PreservesSource() bool { return false }

// ReadFromUDP reads one datagram.
func (p *PacketConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	return p.conn.ReadFromUDP(b)
}

// WriteToUDP sends one datagram, letting the kernel choose the source.
func (p *PacketConn) WriteToUDP(b []byte, to *net.UDPAddr) (int, error) {
	return p.conn.WriteToUDP(b, to)
}

// ReadFromUDPAddrPort and WriteToUDPAddrPort are the netip forms, matching the
// Linux build's surface so a protocol that speaks netip.AddrPort compiles the
// same either way. Here they go straight to the socket.
func (p *PacketConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	return p.conn.ReadFromUDPAddrPort(b)
}

func (p *PacketConn) WriteToUDPAddrPort(b []byte, to netip.AddrPort) (int, error) {
	return p.conn.WriteToUDPAddrPort(b, to)
}

// Close closes the socket.
func (p *PacketConn) Close() error { return p.conn.Close() }

// LocalAddr is the socket's bound address.
func (p *PacketConn) LocalAddr() net.Addr { return p.conn.LocalAddr() }

// SetReadDeadline forwards to the socket.
func (p *PacketConn) SetReadDeadline(t time.Time) error { return p.conn.SetReadDeadline(t) }
