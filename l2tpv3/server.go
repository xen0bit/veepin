package l2tpv3

import (
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/l2tpv3"
)

// ServerConfig configures an L2TPv3 Ethernet pseudowire server.
type ServerConfig struct {
	Listen    string // local IP to bind (default 0.0.0.0)
	Port      int    // UDP port (default 1701)
	TUNName   string // TAP interface name

	SessionID   uint32 // our session ID (local)
	PeerSession uint32 // peer's session ID (remote)
	Cookie      string // hex-encoded cookie for our receive side
	PeerCookie  string // hex-encoded cookie for peer's receive side
	Sublayer    bool   // enable Default L2-Specific Sublayer
}

type Server struct {
	tap    *dataplane.TUN
	pump   *l2tpv3.Pump
	conn   *net.UDPConn
	cfg    ServerConfig
	logger *log.Logger
	closed chan struct{}
}

func NewServer(cfg ServerConfig) (*Server, error) {
	localCookie := parseHex(cfg.Cookie)
	remoteCookie := parseHex(cfg.PeerCookie)

	tap, err := dataplane.OpenTAP(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("l2tpv3: open TAP: %w", err)
	}

	logger := log.New(log.Writer(), "l2tpv3: ", log.LstdFlags)

	s := &Server{
		tap:    tap,
		cfg:    cfg,
		logger: logger,
		closed: make(chan struct{}),
	}

	sessCfg := &l2tpv3.SessionConfig{
		LocalSessionID:  cfg.SessionID,
		RemoteSessionID: cfg.PeerSession,
		LocalCookie:     localCookie,
		RemoteCookie:    remoteCookie,
		Sublayer:        cfg.Sublayer,
	}

	s.pump = l2tpv3.NewPump(tap, s.send, cfg.SessionID, sessCfg, logger)

	return s, nil
}

func (s *Server) send(pkt []byte, to *net.UDPAddr) {
	if s.conn != nil {
		s.conn.WriteToUDP(pkt, to)
	}
}

func (s *Server) ListenAndServe() error {
	listenIP := s.cfg.Listen
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	port := s.cfg.Port
	if port == 0 {
		port = 1701
	}

	addr := &net.UDPAddr{IP: net.ParseIP(listenIP), Port: port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("l2tpv3: listen: %w", err)
	}
	s.conn = conn
	defer conn.Close()

	s.logger.Printf("l2tpv3: listening on %s", addr)

	go s.pump.Run()

	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
				return fmt.Errorf("l2tpv3: read: %w", err)
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.pump.HandleInbound(pkt)
	}
}

func (s *Server) Close() error {
	close(s.closed)
	s.pump.Close()
	if s.conn != nil {
		s.conn.Close()
	}
	return s.tap.Close()
}

func (s *Server) TUNName() string { return s.tap.Name() }

func (s *Server) Gateway() net.IP {
	// L2TPv3 is L2, no tunnel-internal address.
	return nil
}

func (s *Server) Network() *net.IPNet {
	// L2TPv3 is L2, no tunnel subnet.
	return nil
}

func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		Listen:     opts[OptServerListen],
		TUNName:    opts[OptTUN],
		Cookie:     opts[OptCookie],
		PeerCookie: opts[OptPeerCookie],
		Sublayer:   opts[OptSublayer] == "true",
	}
	if p := opts["listen-port"]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("l2tpv3: bad listen-port %q: %w", p, err)
		}
		cfg.Port = n
	}
	if v := opts[OptSessionID]; v != "" {
		n, err := strconv.ParseUint(v, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("l2tpv3: bad %s %q: %w", OptSessionID, v, err)
		}
		cfg.SessionID = uint32(n)
	}
	if v := opts[OptPeerSession]; v != "" {
		n, err := strconv.ParseUint(v, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("l2tpv3: bad %s %q: %w", OptPeerSession, v, err)
		}
		cfg.PeerSession = uint32(n)
	}
	return NewServer(cfg)
}

func init() {
	client.RegisterServer("l2tpv3", parseServerOptions)
}
