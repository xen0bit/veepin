package masque

// The server role: a CONNECT-IP proxy.
//
// One QUIC endpoint, many clients, one shared TUN. Each client is a QUIC
// connection carrying one CONNECT-IP request stream; the proxy assigns an
// address from the pool and routes packets from the shared TUN to whichever
// client owns the destination. The facade mirrors every other server here:
// NewServer validates configuration and opens the TUN but binds no socket, so
// the caller configures host networking before ListenAndServe.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	imasque "github.com/xen0bit/veepin/internal/masque"
	"golang.org/x/net/quic"
)

func init() { client.RegisterServer("masque", parseServerOptions) }

const defaultPool = "10.30.0.0/24"

// Server option keys accepted by client.NewServer("masque", opts).
const (
	OptServerListen = "listen" // local IP to bind (default 0.0.0.0)
	OptServerPort   = "port"   // UDP port (default 443)
	OptServerPool   = "pool"   // client address pool CIDR
	OptServerCert   = "cert"   // TLS certificate PEM (required)
	OptServerKey    = "key"    // TLS private key PEM (required)
	OptServerMTU    = "mtu"    // inner MTU
	OptServerTUN    = "tun"    // TUN interface name
)

// ServerConfig configures a MASQUE proxy.
type ServerConfig struct {
	// ListenIP is the local address to bind; empty means all.
	ListenIP string
	// Port is the UDP port; zero means defaultPort.
	Port int
	// Pool is the client address pool in CIDR form; empty means defaultPool.
	Pool string
	// Cert and Key are the PEM-encoded TLS certificate and private key.
	Cert []byte
	Key  []byte
	// MTU is the inner MTU; zero means defaultMTU.
	MTU int
	// TUNName is the interface to open.
	TUNName string
	// Logger receives progress messages.
	Logger *log.Logger
}

// Server is a MASQUE proxy.
type Server struct {
	cfg     ServerConfig
	tlsCfg  *tls.Config
	pool    *dataplane.AddrPool
	gateway net.IP

	mu      sync.Mutex
	engine  *imasque.Server
	tun     *dataplane.TUN
	end     *quic.Endpoint
	started bool
	closed  bool
}

// NewServer validates the configuration, loads the keypair, allocates the pool
// and opens the TUN. It binds no socket and changes no host state.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Cert) == 0 || len(cfg.Key) == 0 {
		return nil, errors.New("masque: a TLS certificate and key are required")
	}
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("masque: server keypair: %w", err)
	}

	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = defaultPool
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("masque: address pool %q: %w", poolCIDR, err)
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("masque: opening TUN: %w", err)
	}

	return &Server{
		cfg: cfg,
		tlsCfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
			MinVersion:   tls.VersionTLS13,
		},
		pool:    pool,
		gateway: gateway,
		tun:     tun,
	}, nil
}

// ListenAndServe binds the QUIC endpoint and serves until Close. It blocks.
func (s *Server) ListenAndServe() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("masque: server already started")
	}
	s.started = true
	s.mu.Unlock()

	port := s.cfg.Port
	if port == 0 {
		port = defaultPort
	}
	listenIP := s.cfg.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	bind := net.JoinHostPort(listenIP, strconv.Itoa(port))

	end, err := quic.Listen("udp", bind, &quic.Config{
		TLSConfig:                s.tlsCfg,
		MaxBidiRemoteStreams:     100,
		MaxUniRemoteStreams:      100,
		RequireAddressValidation: true, // a stateless retry blunts spoofed-source floods
	})
	if err != nil {
		return fmt.Errorf("masque: listening on %s: %w", bind, err)
	}

	logger := s.cfg.Logger
	engine, err := imasque.NewServer(end, s.tun, imasque.ServerConfig{
		Pool:   s.pool,
		MTU:    s.serverMTU(),
		Logger: logger,
	})
	if err != nil {
		_ = end.Close(context.Background())
		return err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return engine.Close()
	}
	s.end = end
	s.engine = engine
	s.mu.Unlock()

	return engine.Run()
}

func (s *Server) serverMTU() int {
	if s.cfg.MTU > 0 {
		return s.cfg.MTU
	}
	return defaultMTU
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	engine, tun := s.engine, s.tun
	s.mu.Unlock()

	if engine == nil {
		// Constructed but never started: this still owns the TUN.
		if tun != nil {
			return tun.Close()
		}
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
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet client addresses come from.
func (s *Server) Network() *net.IPNet { return s.pool.Network() }

// serverDialer adapts ServerConfig to the registry.
func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		ListenIP: opts[OptServerListen],
		Pool:     opts[OptServerPool],
		TUNName:  opts[OptServerTUN],
		Logger:   log.New(logDest(), "", log.LstdFlags|log.Lmicroseconds),
	}
	if v := opts[OptServerPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("masque: invalid port %q", v)
		}
		cfg.Port = p
	}
	if v := opts[OptServerMTU]; v != "" {
		m, err := strconv.Atoi(v)
		if err != nil || m <= 0 {
			return nil, fmt.Errorf("masque: invalid mtu %q", v)
		}
		cfg.MTU = m
	}

	var err error
	if cfg.Cert, err = readFile(opts[OptServerCert]); err != nil {
		return nil, fmt.Errorf("masque: certificate: %w", err)
	}
	if cfg.Key, err = readFile(opts[OptServerKey]); err != nil {
		return nil, fmt.Errorf("masque: key: %w", err)
	}
	return NewServer(cfg)
}
