package anyconnect

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	engine "github.com/xen0bit/veepin/internal/anyconnect"
)

func init() { client.RegisterServer("anyconnect", parseServerOptions) }

// Server option keys for client.NewServer("anyconnect", opts).
const (
	OptServerCert     = "cert"
	OptServerKey      = "key"
	OptServerListen   = "listen"
	OptServerPort     = "port"
	OptServerUser     = "user"
	OptServerPassword = "password"
	OptServerPool     = "pool"
	OptServerDNS      = "dns"
	OptServerTUN      = "tun"
)

const defaultPool = "10.11.0.0/24"

// ServerConfig configures an AnyConnect responder and its userspace data path.
type ServerConfig struct {
	// Cert and Key are the server's TLS certificate and private key, PEM
	// (required). Clients verify this unless they opt out.
	Cert []byte
	Key  []byte
	// ListenIP is the local address to bind on; empty binds all interfaces.
	ListenIP string
	// ListenPort is the TCP port to accept clients on (default 443).
	ListenPort int
	// Users maps a username to its password (at least one required).
	Users map[string]string
	// Pool is the internal address pool handed to clients, CIDR (default
	// 10.11.0.0/24). Its first host is the server's tunnel address.
	Pool string
	// DNS servers assigned to clients.
	DNS []net.IP
	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string
	Logger  *log.Logger
}

func (c *ServerConfig) validate() error {
	switch {
	case len(c.Cert) == 0 || len(c.Key) == 0:
		return fmt.Errorf("anyconnect: server certificate and key are required")
	case len(c.Users) == 0:
		return fmt.Errorf("anyconnect: at least one user is required")
	}
	return nil
}

// Server is a running AnyConnect responder. It owns the TUN and the TLS
// listener but, like the other protocols, configures no host networking —
// Gateway and Network report what the caller needs to do that.
type Server struct {
	eng      *engine.Server
	tun      *dataplane.TUN
	pool     *dataplane.AddrPool
	gateway  net.IP
	listener net.Listener
	logger   *log.Logger

	closeOnce sync.Once
}

// NewServer opens the TUN, creates the address pool, and binds the listener. It
// does not accept clients until ListenAndServe.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("anyconnect: server keypair: %w", err)
	}
	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = defaultPool
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("anyconnect: address pool: %w", err)
	}
	port := cfg.ListenPort
	if port == 0 {
		port = defaultPort
	}
	ln, err := tls.Listen("tcp", net.JoinHostPort(cfg.ListenIP, strconv.Itoa(port)), &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("anyconnect: listen: %w", err)
	}
	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("anyconnect: open TUN: %w", err)
	}

	eng := engine.NewServer(tun, engine.ServerConfig{
		Users:   cfg.Users,
		Pool:    pool,
		Gateway: gateway,
		DNS:     cfg.DNS,
		Logger:  logger,
	})
	return &Server{
		eng: eng, tun: tun, pool: pool, gateway: gateway,
		listener: ln, logger: logger,
	}, nil
}

// ListenAndServe accepts clients until Close. It blocks.
func (s *Server) ListenAndServe() error {
	s.eng.Start()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// A closed listener is the ordinary shutdown path, not a failure.
			return nil
		}
		go s.eng.ServeConn(conn)
	}
}

// Close stops the server and releases the TUN and listener.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.listener.Close()
		_ = s.eng.Close()
		s.tun.Close()
	})
	return nil
}

// TUNName is the interface the data path is bound to.
func (s *Server) TUNName() string { return s.tun.Name() }

// Gateway is the server's own tunnel-side address (the pool's first host).
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet, for routing and NAT rules.
func (s *Server) Network() *net.IPNet { return s.pool.Network() }

func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		ListenIP: opts[OptServerListen],
		Pool:     opts[OptServerPool],
		DNS:      parseIPList(opts[OptServerDNS]),
		TUNName:  opts[OptServerTUN],
		Logger:   log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
	if path := opts[OptServerCert]; path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("anyconnect: read cert: %w", err)
		}
		cfg.Cert = pem
	}
	if path := opts[OptServerKey]; path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("anyconnect: read key: %w", err)
		}
		cfg.Key = pem
	}
	if v := opts[OptServerPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("anyconnect: invalid port %q", v)
		}
		cfg.ListenPort = p
	}
	if user := opts[OptServerUser]; user != "" {
		cfg.Users = map[string]string{user: opts[OptServerPassword]}
	}
	return NewServer(cfg)
}
