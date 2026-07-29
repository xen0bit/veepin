package l2tpv3

import "net"

// SessionConfig holds the per-session parameters for an L2TPv3 Ethernet
// pseudowire. The cookie and sublayer presence are chosen by the receiver and
// advertised to the sender; the two directions may differ.
type SessionConfig struct {
	LocalSessionID  uint32
	RemoteSessionID uint32
	LocalCookie     []byte // 0, 4 or 8 octets; what we expect on inbound
	RemoteCookie    []byte // 0, 4 or 8 octets; what we send on outbound
	Sublayer        bool   // whether the Default L2-Specific Sublayer is present
	PeerAddr        *net.UDPAddr
}
