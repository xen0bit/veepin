// Package l2tpv3 implements an L2TPv3 Ethernet pseudowire (RFC 3931 and
// RFC 4719), client and server.
//
// It is the tree's only layer-2 data path: the tunnel carries Ethernet frames
// on a TAP device rather than IP packets on a TUN, so the interface joins a
// bridged segment and takes its address from DHCP or ARP inside the tunnel.
// client.Result.Layer2 marks that, and is why no address is returned here.
//
// This package speaks the STATIC pseudowire only -- sessions and cookies are
// configured at both ends, as `ip l2tp add tunnel` / `ip l2tp add session`
// configure them on Linux. There is no control plane; SCCRQ/ICRQ negotiation is
// separate work.
//
// SECURITY: L2TPv3 provides no authentication and no encryption. The cookie is
// a check value against mis-delivery and blind insertion, not a key. Run it
// over something, or on a network you trust. See doc/security.md.
package l2tpv3

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/l2tpv3"
	"github.com/xen0bit/veepin/internal/vlog"
)

// Client option keys.
const (
	OptGateway     = "gateway"         // peer host or IP (required)
	OptPort        = "port"            // peer UDP port (default 1701)
	OptLocalPort   = "local-port"      // local UDP port to bind (default: same as port)
	OptTUN         = "tun"             // TAP interface name (empty = kernel picks)
	OptShape       = "shape"           // per-flow shaping budget in bytes (0 = off)
	OptSessionID   = "session-id"      // our Session ID: what the peer sends to (required)
	OptPeerSession = "peer-session-id" // the peer's Session ID: what we send to (required)
	OptCookie      = "cookie"          // hex cookie WE chose, verified on inbound
	OptPeerCookie  = "peer-cookie"     // hex cookie the PEER chose, written on outbound
	OptSublayer    = "sublayer"        // carry the Default L2-Specific Sublayer
	OptCCID        = "ccid"            // our Control Connection ID; enables HELLO keepalives
	OptPeerCCID    = "peer-ccid"       // the peer's Control Connection ID
	OptKeepalive   = "keepalive"       // HELLO interval in seconds (default 30)
)

// Server option keys.
const (
	OptServerListen = "listen" // local IP to bind (default 0.0.0.0)
	OptServerShape  = "shape"  // per-flow downstream shaping budget in bytes
)

// defaultPort is the IANA port for L2TP; L2TPv3 over UDP uses it too.
const defaultPort = 1701

// ethHeaderLen is the Ethernet header a TAP frame carries on top of the IP MTU.
const ethHeaderLen = 14

// Config configures an L2TPv3 pseudowire client.
type Config struct {
	Server string // peer host or IP
	Port   int    // peer UDP port (default 1701)
	// LocalPort is the port to bind locally. It defaults to Port, NOT to an
	// ephemeral port: a static pseudowire has no control plane to tell the peer
	// where to reply, so the peer's configuration fixes both ends (Linux
	// `udp_sport`/`udp_dport`) and a client that dialled from an ephemeral port
	// would transmit perfectly and never hear anything back.
	LocalPort int
	TUNName   string // TAP interface name
	Shape     int    // per-flow upstream shaping budget in bytes

	SessionID   uint32 // ours: what the peer sends to
	PeerSession uint32 // the peer's: what we send to
	Cookie      string // hex, chosen by us, verified inbound
	PeerCookie  string // hex, chosen by the peer, written outbound
	Sublayer    bool

	// CCID and PeerCCID enable the quiescent control connection: HELLO
	// keepalives over RFC 3931's reliable transport, on the same UDP port as
	// the data. Both must be non-zero, since a Control Connection ID of 0 is
	// reserved. Zero means no control plane at all, which is a bare static
	// pseudowire -- correct, but silent, so a dead peer looks like an idle one.
	CCID     uint32
	PeerCCID uint32
	// Keepalive is the HELLO interval (default 30s).
	Keepalive time.Duration
}

// Dial brings up a static L2TPv3 Ethernet pseudowire.
//
// Per the package contract it installs no routes and no addresses; the returned
// Result carries Layer2, so the caller knows the interface takes its address
// from inside the bridged segment rather than from here.
func Dial(ctx context.Context, cfg Config) (*Session, client.Result, error) {
	sessCfg, err := sessionConfig(cfg.SessionID, cfg.PeerSession, cfg.Cookie, cfg.PeerCookie, cfg.Sublayer)
	if err != nil {
		return nil, client.Result{}, err
	}
	if cfg.Server == "" {
		return nil, client.Result{}, fmt.Errorf("l2tpv3: %s is required", OptGateway)
	}

	port := cfg.Port
	if port == 0 {
		port = defaultPort
	}

	peer, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.Server, strconv.Itoa(port)))
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("l2tpv3: resolve %q: %w", cfg.Server, err)
	}
	sessCfg.PeerAddr = peer

	localPort := cfg.LocalPort
	if localPort == 0 {
		localPort = port
	}
	conn, err := net.DialUDP("udp", &net.UDPAddr{Port: localPort}, peer)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("l2tpv3: bind :%d: %w", localPort, err)
	}

	tap, err := dataplane.OpenTAP(cfg.TUNName)
	if err != nil {
		conn.Close()
		return nil, client.Result{}, fmt.Errorf("l2tpv3: open TAP: %w", err)
	}

	logger := vlog.Text(os.Stderr)
	pump := l2tpv3.NewPump(tap, func(pkt []byte, _ *net.UDPAddr) {
		// The socket is connected, so the destination is already fixed and the
		// pump's learned reply address is unused on this side.
		_, _ = conn.Write(pkt)
	}, sessCfg, logger)

	mtu := innerMTU(sessCfg, peer.IP)
	if cfg.Shape > 0 {
		pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape}), mtu+ethHeaderLen)
	}

	s := &Session{conn: conn, tap: tap, pump: pump, done: make(chan struct{})}
	if cfg.CCID != 0 && cfg.PeerCCID != 0 {
		s.ctl = l2tpv3.NewControlConn(l2tpv3.ControlConfig{
			LocalCCID: cfg.CCID, RemoteCCID: cfg.PeerCCID,
			HelloInterval: cfg.Keepalive, PeerAddr: peer,
		}, func(pkt []byte, _ *net.UDPAddr) { _, _ = conn.Write(pkt) },
			func() { logger.Printf("l2tpv3: control connection lost (peer stopped acknowledging)") })
		go s.ctl.Run()
	}
	go pump.Run()
	go s.readLoop()

	logger.Printf("l2tpv3: pseudowire up on %s: :%d -> %s, session %d -> %d, cookie %d/%d octets, sublayer %v, MTU %d",
		tap.Name(), localPort, peer, sessCfg.LocalSessionID, sessCfg.RemoteSessionID,
		len(sessCfg.LocalCookie), len(sessCfg.RemoteCookie), sessCfg.Sublayer, mtu)

	return s, client.Result{
		TUNName: tap.Name(),
		Layer2:  true,
		// The RESOLVED peer address, not cfg.Server: net.ParseIP of a hostname
		// is nil, and a nil Gateway silently means "no host route", so a
		// hostname would leave the tunnel's own packets free to recurse into it.
		Gateway: peer.IP,
		MTU:     mtu,
	}, nil
}

// innerMTU is the largest IP packet that fits without fragmenting the outer
// datagram:
//
//	1500 outer
//	 -20 IPv4 (or -40 IPv6) underlay header
//	  -8 UDP
//	  -8 L2TPv3 flags/ver, reserved and Session ID
//	  -N cookie WE SEND (RemoteCookie -- the peer's, on our outbound packets)
//	  -4 sublayer, when the session carries one
//	 -14 Ethernet header inside the tunnel
//
// which is 1446 for a cookieless session with a sublayer, and 1438 when it
// carries an 8-octet cookie.
func innerMTU(c *l2tpv3.SessionConfig, peer net.IP) int {
	underlay := 20
	if peer != nil && peer.To4() == nil {
		underlay = 40
	}
	return 1500 - underlay - 8 - c.Overhead() - ethHeaderLen
}

// sessionConfig validates and assembles the session shared by both roles.
func sessionConfig(local, remote uint32, cookie, peerCookie string, sublayer bool) (*l2tpv3.SessionConfig, error) {
	localCookie, err := parseCookie(OptCookie, cookie)
	if err != nil {
		return nil, err
	}
	remoteCookie, err := parseCookie(OptPeerCookie, peerCookie)
	if err != nil {
		return nil, err
	}
	c := &l2tpv3.SessionConfig{
		LocalSessionID:  local,
		RemoteSessionID: remote,
		LocalCookie:     localCookie,
		RemoteCookie:    remoteCookie,
		Sublayer:        sublayer,
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// parseCookie decodes a hex cookie. A malformed one is an error rather than a
// silently shortened cookie: the cookie is the session's only check value, and
// quietly dropping half of it would weaken the tunnel without saying so.
func parseCookie(opt, s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("l2tpv3: bad %s %q: %w", opt, s, err)
	}
	if !l2tpv3.ValidCookieLen(len(b)) {
		return nil, fmt.Errorf("l2tpv3: %s is %d octets: %w", opt, len(b), l2tpv3.ErrCookieLen)
	}
	return b, nil
}

// Session is an established pseudowire.
type Session struct {
	conn *net.UDPConn
	tap  *dataplane.TUN
	pump *l2tpv3.Pump
	// ctl is the quiescent control connection, or nil for a bare static
	// pseudowire.
	ctl  *l2tpv3.ControlConn
	done chan struct{}
}

func (s *Session) readLoop() {
	// The pump writes the frame to the TAP before returning and retains
	// nothing, so the read buffer is reused rather than copied per packet.
	buf := make([]byte, 65535)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			// Only a closed socket ends the loop. Everything else is transient
			// and must not: this socket is CONNECTED, so Linux reports an ICMP
			// port-unreachable for an earlier send as an error on the next read.
			// A pseudowire whose peer has not finished configuring its tunnel
			// generates exactly that, and returning here would kill the receive
			// path permanently for a condition that resolves in a second. It
			// cost an interop cell to find, because a veepin-to-veepin test has
			// both ends bound before either sends and never produces the ICMP.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-s.done:
				return
			default:
			}
			continue
		}
		// Control and data share the port; only the T bit separates them.
		if l2tpv3.IsControl(buf[:n]) {
			if s.ctl != nil {
				s.ctl.HandleControl(buf[:n], nil)
			}
			continue
		}
		s.pump.HandleInbound(buf[:n], nil)
	}
}

// Wait blocks until the context is cancelled or the session is closed.
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return nil
	}
}

// Probe reports how long the pseudowire has been silent, implementing
// client.Prober. A static pseudowire sends nothing of its own, so without this
// a dead peer is indistinguishable from an idle one.
func (s *Session) Probe(context.Context) (time.Duration, error) {
	idle := s.pump.IdleFor()
	if s.ctl != nil {
		// With keepalives running, the control connection is the real liveness
		// signal: it produces traffic on a schedule, so silence there means
		// something. The data path may legitimately be idle for hours.
		if c := s.ctl.IdleFor(); c < idle {
			idle = c
		}
	}
	return idle, nil
}

// Close tears the pseudowire down. It is safe to call more than once.
func (s *Session) Close() error {
	select {
	case <-s.done:
		return nil
	default:
		close(s.done)
	}
	if s.ctl != nil {
		s.ctl.Close()
	}
	s.pump.Close()
	s.conn.Close()
	return s.tap.Close()
}

func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := Config{
		Server:     opts[OptGateway],
		TUNName:    opts[OptTUN],
		Cookie:     opts[OptCookie],
		PeerCookie: opts[OptPeerCookie],
		Sublayer:   opts[OptSublayer] == "true",
	}
	var err error
	if cfg.Port, err = optInt(opts, OptPort); err != nil {
		return nil, err
	}
	if cfg.LocalPort, err = optInt(opts, OptLocalPort); err != nil {
		return nil, err
	}
	if cfg.Shape, err = optInt(opts, OptShape); err != nil {
		return nil, err
	}
	if cfg.SessionID, err = optUint32(opts, OptSessionID); err != nil {
		return nil, err
	}
	if cfg.PeerSession, err = optUint32(opts, OptPeerSession); err != nil {
		return nil, err
	}
	if cfg.CCID, err = optUint32(opts, OptCCID); err != nil {
		return nil, err
	}
	if cfg.PeerCCID, err = optUint32(opts, OptPeerCCID); err != nil {
		return nil, err
	}
	secs, err := optInt(opts, OptKeepalive)
	if err != nil {
		return nil, err
	}
	cfg.Keepalive = time.Duration(secs) * time.Second
	return dialer{cfg}, nil
}

func optInt(opts map[string]string, key string) (int, error) {
	v := opts[key]
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("l2tpv3: bad %s %q", key, v)
	}
	return n, nil
}

func optUint32(opts map[string]string, key string) (uint32, error) {
	v := opts[key]
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(v, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("l2tpv3: bad %s %q: %w", key, v, err)
	}
	return uint32(n), nil
}

type dialer struct{ cfg Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, d.cfg)
}

func init() {
	client.Register("l2tpv3", parseOptions)
}
