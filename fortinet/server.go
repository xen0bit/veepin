package fortinet

// The server role: a Fortinet SSL VPN gateway.
//
// It runs an HTTPS server whose handler is internal/fortinet's — login, config,
// and the hijacked PPP tunnel — alongside a read loop over the shared TUN. The
// facade mirrors every other server here: NewServer validates configuration and
// opens the TUN but binds no socket, so the caller configures host networking
// before ListenAndServe.

import (
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	ifortinet "github.com/xen0bit/veepin/internal/fortinet"
	"github.com/xen0bit/veepin/internal/otp"
)

func init() { client.RegisterServer("fortinet", parseServerOptions) }

const defaultPool = "10.40.0.0/24"

// Server option keys accepted by client.NewServer("fortinet", opts).
const (
	OptServerListen = "listen"  // local IP to bind (default 0.0.0.0)
	OptServerPort   = "port"    // HTTPS port (default 443)
	OptServerPool   = "pool"    // client address pool CIDR
	OptServerCert   = "cert"    // TLS certificate PEM (required)
	OptServerKey    = "key"     // TLS private key PEM (required)
	OptServerUser   = "user"    // username to accept (required)
	OptServerPass   = "pass"    // that user's password (required)
	OptServerDNS    = "dns"     // comma-separated DNS servers offered to clients
	OptServerNoDTLS = "no-dtls" // "true" to serve the TLS tunnel only
	OptServerTOTP   = "totp"    // base32 TOTP secret; set it to require a second factor
	OptServerTUN    = "tun"     // TUN interface name
)

// ServerConfig configures a Fortinet SSL VPN server.
type ServerConfig struct {
	ListenIP string
	Port     int
	Pool     string
	Cert     []byte
	Key      []byte
	Users    map[string]string
	DNS      []net.IP
	// NoDTLS serves the TLS tunnel only, leaving the UDP port unbound.
	NoDTLS bool
	// TOTPSecrets maps a username to its base32 TOTP secret. A user listed here
	// must pass a second factor after its password.
	TOTPSecrets map[string]string
	TUNName     string
	Logger      *log.Logger
}

// Server is a Fortinet SSL VPN server.
type Server struct {
	cfg     ServerConfig
	tlsCfg  *tls.Config
	pool    *dataplane.AddrPool
	gateway net.IP
	tun     *dataplane.TUN
	engine  *ifortinet.Server
	dtlsOK  bool // the UDP data channel is configured and will be bound

	mu      sync.Mutex
	httpSrv *http.Server
	udpConn *net.UDPConn
	started bool
	closed  bool
}

// NewServer validates the configuration, loads the keypair, allocates the pool
// and opens the TUN. It binds no socket and changes no host state.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Cert) == 0 || len(cfg.Key) == 0 {
		return nil, errors.New("fortinet: a TLS certificate and key are required")
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("fortinet: at least one user is required")
	}
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("fortinet: server keypair: %w", err)
	}

	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = defaultPool
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("fortinet: address pool %q: %w", poolCIDR, err)
	}
	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("fortinet: opening TUN: %w", err)
	}

	for user, secret := range cfg.TOTPSecrets {
		if _, err := otp.DecodeSecret(secret); err != nil {
			return nil, fmt.Errorf("fortinet: TOTP secret for %q: %w", user, err)
		}
	}
	engineCfg := ifortinet.ServerConfig{
		Users:       cfg.Users,
		Pool:        pool,
		ServerIP:    gateway,
		DNS:         cfg.DNS,
		Logger:      cfg.Logger,
		TOTPSecrets: cfg.TOTPSecrets,
	}
	// The DTLS channel is ECDHE-ECDSA, so an RSA gateway keypair cannot serve it.
	// That is a reason to run TLS-only, not to refuse to start: the TLS tunnel is
	// unaffected and is what every client can already speak.
	if !cfg.NoDTLS {
		if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); ok {
			engineCfg.Certificate = &cert
		} else if cfg.Logger != nil {
			cfg.Logger.Printf("fortinet: server key is not ECDSA; the DTLS data channel is disabled")
		}
	}
	engine, err := ifortinet.NewServer(engineCfg, tun)
	if err != nil {
		_ = tun.Close()
		return nil, err
	}

	return &Server{
		cfg:     cfg,
		dtlsOK:  engineCfg.Certificate != nil,
		tlsCfg:  &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		pool:    pool,
		gateway: gateway,
		tun:     tun,
		engine:  engine,
	}, nil
}

// ListenAndServe binds the HTTPS socket and serves until Close. It blocks.
func (s *Server) ListenAndServe() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("fortinet: server already started")
	}
	s.started = true

	port := s.cfg.Port
	if port == 0 {
		port = defaultPort
	}
	listenIP := s.cfg.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	addr := net.JoinHostPort(listenIP, strconv.Itoa(port))
	ln, err := tls.Listen("tcp", addr, s.tlsCfg)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("fortinet: listen: %w", err)
	}

	// The UDP data channel shares the port number. It is bound and its serve loop
	// started before the HTTPS listener accepts anything, so no client is ever
	// told about a channel that is not yet being read.
	var serveDTLS func()
	if s.dtlsOK {
		udp, uerr := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(listenIP), Port: port})
		if uerr != nil {
			_ = ln.Close()
			s.mu.Unlock()
			return fmt.Errorf("fortinet: listen UDP: %w", uerr)
		}
		serveDTLS, err = s.engine.EnableDTLS(udp)
		if err != nil {
			_ = udp.Close()
			_ = ln.Close()
			s.mu.Unlock()
			return err
		}
		s.udpConn = udp
	}
	s.httpSrv = &http.Server{Handler: s.engine}
	s.mu.Unlock()

	if serveDTLS != nil {
		go serveDTLS()
	}
	go s.engine.RunTUN()

	if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("fortinet: serve: %w", err)
	}
	return nil
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	httpSrv := s.httpSrv
	s.mu.Unlock()

	if httpSrv != nil {
		_ = httpSrv.Close()
	}
	return s.engine.Close()
}

// TUNName is the interface the server is bound to.
func (s *Server) TUNName() string {
	if s.tun == nil {
		return ""
	}
	return s.tun.Name()
}

// Gateway is the server's own address inside the tunnel.
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet client addresses come from.
func (s *Server) Network() *net.IPNet { return s.pool.Network() }

// parseServerOptions turns registry options into a constructed Server.
func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		ListenIP: opts[OptServerListen],
		Pool:     opts[OptServerPool],
		NoDTLS:   opts[OptServerNoDTLS] == "true",
		TUNName:  opts[OptServerTUN],
		Logger:   log.New(logDest(), "", log.LstdFlags|log.Lmicroseconds),
	}
	user, pass := opts[OptServerUser], opts[OptServerPass]
	if user == "" || pass == "" {
		return nil, errors.New("fortinet: user and pass are required")
	}
	if secret := opts[OptServerTOTP]; secret != "" {
		cfg.TOTPSecrets = map[string]string{user: secret}
	}
	cfg.Users = map[string]string{user: pass}

	if v := opts[OptServerPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("fortinet: invalid port %q", v)
		}
		cfg.Port = p
	}
	for _, d := range strings.Split(opts[OptServerDNS], ",") {
		if d = strings.TrimSpace(d); d != "" {
			if ip := net.ParseIP(d); ip != nil {
				cfg.DNS = append(cfg.DNS, ip)
			}
		}
	}

	var err error
	if cfg.Cert, err = readFile(opts[OptServerCert]); err != nil {
		return nil, fmt.Errorf("fortinet: certificate: %w", err)
	}
	if cfg.Key, err = readFile(opts[OptServerKey]); err != nil {
		return nil, fmt.Errorf("fortinet: key: %w", err)
	}
	return NewServer(cfg)
}
