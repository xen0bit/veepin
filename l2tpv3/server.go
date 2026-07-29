package l2tpv3

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/l2tpv3"
)

// ServerConfig configures an L2TPv3 Ethernet pseudowire server.
//
// "Server" means only "the end that waits": a static pseudowire is symmetric,
// so the two roles differ in who binds and who dials, not in what they speak.
type ServerConfig struct {
	Listen  string // local IP to bind (default 0.0.0.0)
	Port    int    // UDP port (default 1701)
	TUNName string // TAP interface name
	Shape   int    // per-flow downstream shaping budget in bytes

	SessionID   uint32 // ours: what the peer sends to
	PeerSession uint32 // the peer's: what we send to
	Cookie      string // hex, chosen by us, verified inbound
	PeerCookie  string // hex, chosen by the peer, written outbound
	Sublayer    bool

	// CCID / PeerCCID enable the quiescent control connection (HELLO
	// keepalives). Zero on either disables it, leaving a bare static pseudowire.
	CCID      uint32
	PeerCCID  uint32
	Keepalive time.Duration
}

// Server is a listening L2TPv3 pseudowire endpoint.
type Server struct {
	tap    *dataplane.TUN
	pump   *l2tpv3.Pump
	cfg    ServerConfig
	sess   *l2tpv3.SessionConfig
	logger *log.Logger

	// conn is written by ListenAndServe and read by the pump's send callback on
	// another goroutine, so it is atomic rather than a plain field.
	conn   atomic.Pointer[net.UDPConn]
	closed atomic.Bool

	// ctl is the quiescent control connection, or nil.
	ctl *l2tpv3.ControlConn
}

// NewServer opens the TAP and validates the configuration. Per the package
// contract it binds nothing -- the socket is opened in ListenAndServe, so the
// caller can configure host networking first.
func NewServer(cfg ServerConfig) (*Server, error) {
	sessCfg, err := sessionConfig(cfg.SessionID, cfg.PeerSession, cfg.Cookie, cfg.PeerCookie, cfg.Sublayer)
	if err != nil {
		return nil, err
	}

	tap, err := dataplane.OpenTAP(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("l2tpv3: open TAP: %w", err)
	}

	s := &Server{
		tap:    tap,
		cfg:    cfg,
		sess:   sessCfg,
		logger: log.New(log.Writer(), "", log.LstdFlags),
	}
	s.pump = l2tpv3.NewPump(tap, s.send, sessCfg, s.logger)
	if cfg.CCID != 0 && cfg.PeerCCID != 0 {
		// PeerAddr is left nil: a server does not know where its peer is until
		// a message arrives and verifies against the CCID it chose.
		s.ctl = l2tpv3.NewControlConn(l2tpv3.ControlConfig{
			LocalCCID: cfg.CCID, RemoteCCID: cfg.PeerCCID, HelloInterval: cfg.Keepalive,
		}, s.send, func() {
			s.logger.Printf("l2tpv3: control connection lost (peer stopped acknowledging)")
		})
	}
	if cfg.Shape > 0 {
		mtu := innerMTU(sessCfg, nil)
		s.pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape}), mtu+ethHeaderLen)
	}
	return s, nil
}

// send writes one datagram to the peer the pump learned from inbound traffic.
// A server has no configured peer address: until a packet arrives and passes
// the cookie check there is nowhere to send, and to is nil.
func (s *Server) send(pkt []byte, to *net.UDPAddr) {
	conn := s.conn.Load()
	if conn == nil || to == nil {
		return
	}
	_, _ = conn.WriteToUDP(pkt, to)
}

// ListenAndServe binds the UDP socket and serves until Close.
func (s *Server) ListenAndServe() error {
	listenIP := s.cfg.Listen
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	ip := net.ParseIP(listenIP)
	if ip == nil {
		return fmt.Errorf("l2tpv3: bad %s %q", OptServerListen, listenIP)
	}
	port := s.cfg.Port
	if port == 0 {
		port = defaultPort
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return fmt.Errorf("l2tpv3: listen: %w", err)
	}
	s.conn.Store(conn)
	defer conn.Close()

	s.logger.Printf("l2tpv3: listening on %s:%d, TAP %s, session %d -> %d, cookie %d/%d octets, sublayer %v",
		listenIP, port, s.tap.Name(), s.sess.LocalSessionID, s.sess.RemoteSessionID,
		len(s.sess.LocalCookie), len(s.sess.RemoteCookie), s.sess.Sublayer)

	go s.pump.Run()
	if s.ctl != nil {
		go s.ctl.Run()
	}

	// The pump retains nothing past the TAP write, so one buffer is reused for
	// every datagram rather than copied per packet.
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if s.closed.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// A transient read error must not take the server down. This socket
			// is unconnected, so it does not see the ICMP-port-unreachable case
			// the client's readLoop has to survive, but the principle is the
			// same: one bad datagram is not a reason to stop serving every peer.
			s.logger.Printf("l2tpv3: read: %v (continuing)", err)
			continue
		}
		// Control and data share the port; only the T bit separates them.
		if l2tpv3.IsControl(buf[:n]) {
			if s.ctl != nil {
				s.ctl.HandleControl(buf[:n], from)
			}
			continue
		}
		s.pump.HandleInbound(buf[:n], from)
	}
}

// Close stops the server. It is safe to call more than once.
func (s *Server) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.ctl != nil {
		s.ctl.Close()
	}
	s.pump.Close()
	if conn := s.conn.Load(); conn != nil {
		conn.Close()
	}
	return s.tap.Close()
}

// TUNName is the TAP interface the pseudowire is bound to.
func (s *Server) TUNName() string { return s.tap.Name() }

// Gateway is nil: a layer-2 pseudowire has no address inside the tunnel, so
// there is no gateway for a client to point at.
func (s *Server) Gateway() net.IP { return nil }

// Network is nil for the same reason -- the bridged segment's subnet is a
// property of the bridge, not of this tunnel.
func (s *Server) Network() *net.IPNet { return nil }

func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		Listen:     opts[OptServerListen],
		TUNName:    opts[OptTUN],
		Cookie:     opts[OptCookie],
		PeerCookie: opts[OptPeerCookie],
		Sublayer:   opts[OptSublayer] == "true",
	}
	var err error
	// The key is OptPort, matching what serve.go emits. Reading some other
	// spelling here would leave --port silently ignored, and flags_test would
	// not catch it: it checks that a flag reaches the option map, not that the
	// map reaches the config.
	if cfg.Port, err = optInt(opts, OptPort); err != nil {
		return nil, err
	}
	if cfg.Shape, err = optInt(opts, OptServerShape); err != nil {
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
	return NewServer(cfg)
}

func init() {
	client.RegisterServer("l2tpv3", parseServerOptions)
}
