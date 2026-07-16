package wireguard

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/internal/wireguard/transport"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// Rekey timing (protocol paper §6.1). A session's keys are replaced well before
// they would be rejected, so traffic never stops: the initiator re-handshakes
// every rekeyAfterTime, and a key is refused for sending once it is older than
// rejectAfterTime.
const (
	rekeyAfterTime  = 120 * time.Second
	rejectAfterTime = 180 * time.Second
)

var (
	// errNoSession means no handshake has completed yet; the caller should start
	// one rather than send.
	errNoSession = errors.New("wireguard: no live session")
	// errSessionExpired means the current keypair is past rejectAfterTime and
	// must be replaced before more can be sent.
	errSessionExpired = errors.New("wireguard: session expired, rekey needed")
	// errUnknownIndex means a transport packet's receiver index matches neither
	// the current nor the previous keypair — a stale or stray packet.
	errUnknownIndex = errors.New("wireguard: transport packet for an unknown session")
	// errSourceNotAllowed means a decrypted packet's source is outside the peer's
	// AllowedIPs (the inbound half of cryptokey routing).
	errSourceNotAllowed = errors.New("wireguard: inner source not in peer AllowedIPs")
)

// wgTunnel is the data-path view of one peer: it encrypts with the current
// keypair and decrypts with the current or the previous one, so a rekey can swap
// keys without dropping packets still in flight under the old one. It implements
// dataplane.Tunnel.
//
// A peer's receiver index changes on every rekey, so a wgTunnel is reachable
// under more than one inbound key at once; the client and server register and
// retire those keys with the pump as the session rotates (see install).
//
// The peer address is atomic because a server's peer roams: WireGuard lets a
// client's source address change, and the pump updates it (via SetPeerAddr) from
// the source of each inbound transport packet so replies follow. A client sets
// it once and it never moves.
type wgTunnel struct {
	routes []netip.Prefix
	peer   atomic.Pointer[net.UDPAddr]

	// verifySource enables the inbound half of cryptokey routing: a decrypted
	// packet whose source is not within this peer's AllowedIPs is dropped, so one
	// peer cannot spoof another's address. A client trusts its single server for
	// everything and leaves this off.
	verifySource bool

	mu          sync.RWMutex
	current     *transport.Session
	previous    *transport.Session
	established time.Time // when current was installed
}

// newTunnel builds a wgTunnel with its first session and peer address set.
func newTunnel(sess *transport.Session, routes []netip.Prefix, peer *net.UDPAddr, verifySource bool) *wgTunnel {
	t := &wgTunnel{routes: routes, verifySource: verifySource, current: sess, established: time.Now()}
	t.peer.Store(peer)
	return t
}

// install rotates a freshly negotiated session in as current, demoting the old
// current to previous and returning the session that fell out (the old previous)
// so the caller can retire its inbound index from the pump. The previous keypair
// stays live for decryption to cover packets still in flight under it.
func (t *wgTunnel) install(sess *transport.Session) (evicted *transport.Session) {
	t.mu.Lock()
	evicted = t.previous
	t.previous = t.current
	t.current = sess
	t.established = time.Now()
	t.mu.Unlock()
	return evicted
}

func (t *wgTunnel) Routes() []netip.Prefix { return t.routes }
func (t *wgTunnel) PeerAddr() *net.UDPAddr { return t.peer.Load() }

// InboundKey is the current session's receiver index — the pump's first
// registration for this tunnel. Later indices are added with pump.AddInboundKey
// as the session rotates on rekey.
func (t *wgTunnel) InboundKey() uint32 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.current == nil {
		return 0
	}
	return t.current.LocalIndex()
}

// SetPeerAddr updates the return address, skipping the store when it is
// unchanged so the hot inbound path does not churn the atomic on every packet.
func (t *wgTunnel) SetPeerAddr(a *net.UDPAddr) {
	if cur := t.peer.Load(); cur != nil && cur.Port == a.Port && cur.IP.Equal(a.IP) {
		return
	}
	t.peer.Store(a)
}

// Encapsulate seals an outbound packet under the current keypair, refusing once
// it is past rejectAfterTime — a peer would reject a packet under a dead key, so
// dropping it here (and letting the rekey loop re-establish) is the honest thing.
func (t *wgTunnel) Encapsulate(p []byte) ([]byte, error) {
	t.mu.RLock()
	sess := t.current
	expired := sess != nil && time.Since(t.established) >= rejectAfterTime
	t.mu.RUnlock()
	if sess == nil {
		return nil, errNoSession
	}
	if expired {
		return nil, errSessionExpired
	}
	return sess.Seal(p)
}

// Decapsulate opens an inbound transport packet with whichever keypair its
// receiver index names — current or previous — so a rekey does not drop packets
// still arriving under the old key.
func (t *wgTunnel) Decapsulate(p []byte) ([]byte, error) {
	idx, ok := wire.Demux(p)
	if !ok {
		return nil, errUnknownIndex
	}
	t.mu.RLock()
	var sess *transport.Session
	switch {
	case t.current != nil && t.current.LocalIndex() == idx:
		sess = t.current
	case t.previous != nil && t.previous.LocalIndex() == idx:
		sess = t.previous
	}
	t.mu.RUnlock()
	if sess == nil {
		return nil, errUnknownIndex
	}
	inner, err := sess.Open(p)
	if err != nil || len(inner) == 0 {
		return inner, err // error, or a keepalive the pump will drop
	}
	if t.verifySource && !t.sourceAllowed(inner) {
		return nil, errSourceNotAllowed
	}
	return inner, nil
}

// sourceAllowed reports whether an inbound inner packet's source address falls
// within this peer's routes — the inbound direction of cryptokey routing.
func (t *wgTunnel) sourceAllowed(inner []byte) bool {
	if len(inner) < 20 || inner[0]>>4 != 4 {
		return false // IPv4 only in this build
	}
	src, ok := netip.AddrFromSlice(inner[12:16])
	if !ok {
		return false
	}
	for _, r := range t.routes {
		if r.Contains(src) {
			return true
		}
	}
	return false
}
