package toy

// The server role.
//
// One UDP socket, many clients, one shared TUN. Clients are demultiplexed by
// session ID rather than by source address, and each gets an address from a
// pool; the pump routes outbound packets to the right client by inner
// destination. That is the whole multi-client shape, and it is the part most
// worth copying when adding a real protocol.

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	itoy "github.com/xen0bit/veepin/internal/toy"
)

func init() { client.RegisterServer("toy", parseServerOptions) }

// Server option keys accepted by client.NewServer("toy", opts).
const (
	OptServerListen = "listen" // local IP to bind (default 0.0.0.0)
	OptServerPort   = "port"   // UDP port (default 5555)
	OptServerPool   = "pool"   // client address pool CIDR
	OptServerDNS    = "dns"    // comma-separated DNS servers offered to clients
	OptServerUser   = "user"   // the one username to accept (required)
	OptServerSecret = "secret" // that user's secret (required)
	OptServerMTU    = "mtu"    // inner MTU offered to clients
	OptServerTUN    = "tun"    // TUN interface name
)

// ServerConfig configures a TOY server.
type ServerConfig struct {
	// ListenIP is the local address to bind; empty means all.
	ListenIP string
	// Port is the UDP port; zero means DefaultPort.
	Port int
	// Pool is the client address pool in CIDR form.
	Pool string
	// Users maps username to secret. At least one is required.
	Users map[string]string
	// DNS is offered to clients.
	DNS []netip.Addr
	// MTU is offered to clients; zero means defaultMTU.
	MTU int
	// TUNName is the interface to open.
	TUNName string
	// Logger receives progress messages.
	Logger *log.Logger
}

// Server is a TOY server.
type Server struct {
	cfg ServerConfig

	mu      sync.Mutex
	engine  *itoy.Server
	tun     *dataplane.TUN
	pool    *dataplane.AddrPool
	started bool
	closed  bool
}

// NewServer prepares a server. Nothing binds until ListenAndServe.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Users) == 0 {
		return nil, errors.New("toy: at least one user is required")
	}
	if cfg.Pool == "" {
		return nil, errors.New("toy: an address pool is required")
	}
	return &Server{cfg: cfg}, nil
}

// ListenAndServe binds and serves until Close. It blocks.
func (s *Server) ListenAndServe() error {
	Warn(s.cfg.Logger)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("toy: server already started")
	}
	s.started = true
	s.mu.Unlock()

	pool, _, err := dataplane.NewAddrPool(s.cfg.Pool)
	if err != nil {
		return fmt.Errorf("toy: address pool %q: %w", s.cfg.Pool, err)
	}

	port := s.cfg.Port
	if port == 0 {
		port = itoy.DefaultPort
	}
	listenIP := s.cfg.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(listenIP, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("toy: resolving listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("toy: listening on %s: %w", addr, err)
	}

	tun, err := dataplane.OpenTUN(s.cfg.TUNName)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("toy: opening TUN: %w", err)
	}

	mtu := s.cfg.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	engine, err := itoy.NewServer(conn, tun, itoy.ServerConfig{
		Users:  s.cfg.Users,
		Pool:   pool,
		DNS:    s.cfg.DNS,
		MTU:    uint16(mtu),
		Logger: s.cfg.Logger,
	})
	if err != nil {
		_ = conn.Close()
		_ = tun.Close()
		return err
	}

	s.mu.Lock()
	if s.closed {
		// Close raced ahead of the bind; do not leave anything running.
		s.mu.Unlock()
		return engine.Close()
	}
	s.engine, s.tun, s.pool = engine, tun, pool
	s.mu.Unlock()

	return engine.Run()
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	engine := s.engine
	s.mu.Unlock()

	if engine == nil {
		return nil
	}
	return engine.Close()
}

// TUNName is the interface the server is bound to.
func (s *Server) TUNName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tun == nil {
		return ""
	}
	return s.tun.Name()
}

// Gateway is the server's own address inside the tunnel.
func (s *Server) Gateway() net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pool == nil {
		return nil
	}
	return s.pool.Gateway()
}

// Network is the subnet client addresses come from.
func (s *Server) Network() *net.IPNet {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pool == nil {
		return nil
	}
	return s.pool.Network()
}

// parseServerOptions turns registry options into a Server.
func parseServerOptions(opts map[string]string) (client.Server, error) {
	user, secret := opts[OptServerUser], opts[OptServerSecret]
	if user == "" || secret == "" {
		return nil, errors.New("toy: user and secret are required")
	}

	cfg := ServerConfig{
		ListenIP: opts[OptServerListen],
		Pool:     opts[OptServerPool],
		Users:    map[string]string{user: secret},
		TUNName:  opts[OptServerTUN],
		Logger:   log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
	if cfg.Pool == "" {
		cfg.Pool = "10.9.0.0/24"
	}

	for _, key := range []struct {
		name string
		dst  *int
	}{
		{OptServerPort, &cfg.Port},
		{OptServerMTU, &cfg.MTU},
	} {
		if v := opts[key.name]; v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("toy: invalid %s %q", key.name, v)
			}
			*key.dst = n
		}
	}

	for _, d := range strings.Split(opts[OptServerDNS], ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		a, err := netip.ParseAddr(d)
		if err != nil {
			return nil, fmt.Errorf("toy: invalid DNS server %q: %w", d, err)
		}
		cfg.DNS = append(cfg.DNS, a)
	}

	return NewServer(cfg)
}
