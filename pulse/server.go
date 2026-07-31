package pulse

// The server role: an Ivanti Connect Secure gateway.
//
// The facade mirrors every other server here: NewServer validates
// configuration, loads the keypair, allocates the pool and opens the TUN, but
// binds no socket, so the caller configures host networking before
// ListenAndServe.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	ipulse "github.com/xen0bit/veepin/internal/pulse"
)

func init() {
	client.RegisterServer("pulse", parseServerOptions)
	client.RegisterServerOpts("pulse", []client.OptSpec{
		{Key: OptServerCert, Kind: client.OptFilePath, Required: true, Generate: "tls", Help: "path to the server TLS certificate PEM"},
		{Key: OptServerKey, Kind: client.OptFilePath, Required: true, Secret: true, Generate: "tls", Help: "path to the server TLS private key PEM"},
		{Key: OptServerListen, Kind: client.OptStr, Default: "0.0.0.0", Help: "local IP to bind the HTTPS socket on (default 0.0.0.0)"},
		{Key: OptServerPort, Kind: client.OptInt, Default: "443", Help: "HTTPS port to listen on (default 443)"},
		{Key: OptServerESPPort, Kind: client.OptInt, Default: "4500", Help: "UDP port for the ESP data path (default 4500)"},
		{Key: OptServerPublicIP, Kind: client.OptStr, Help: "address clients reach this gateway on (empty = the bound address)"},
		{Key: OptServerPool, Kind: client.OptCIDR, Default: "10.70.0.0/24", Help: "internal address pool handed to clients (default 10.70.0.0/24)"},
		{Key: OptServerDNS, Kind: client.OptCommaList, Help: "comma-separated DNS servers offered to clients"},
		{Key: OptServerDomain, Kind: client.OptStr, Help: "DNS search domain offered to clients"},
		{Key: OptServerSplitInclude, Kind: client.OptCommaList, Help: "comma-separated CIDRs clients should route into the tunnel (empty = everything)"},
		{Key: OptServerUser, Kind: client.OptStr, Required: true, Help: "username to accept"},
		{Key: OptServerPass, Kind: client.OptStr, Required: true, Secret: true, Help: "the user's password"},
		{Key: OptServerNoESP, Kind: client.OptBool, Help: "serve the IF-T/TLS data path only, leaving the UDP port unbound"},
		{Key: OptServerTUN, Kind: client.OptStr, Help: "TUN interface name (empty = kernel picks)"},
		{Key: OptServerShape, Kind: client.OptInt, Default: "0", Help: "per-flow downstream shaping budget in bytes (0 = off)"},
	})
}

const defaultPool = "10.70.0.0/24"

// Server option keys accepted by client.NewServer("pulse", opts).
const (
	OptServerListen       = "listen"        // local IP to bind (default 0.0.0.0)
	OptServerPort         = "port"          // HTTPS port (default 443)
	OptServerPool         = "pool"          // client address pool CIDR
	OptServerCert         = "cert"          // TLS certificate PEM (required)
	OptServerKey          = "key"           // TLS private key PEM (required)
	OptServerUser         = "user"          // username to accept (required)
	OptServerPass         = "pass"          // that user's password (required)
	OptServerDNS          = "dns"           // comma-separated DNS servers offered to clients
	OptServerDomain       = "domain"        // search domain offered to clients
	OptServerSplitInclude = "split-include" // comma-separated CIDRs clients should route into the tunnel
	OptServerNoESP        = "no-esp"        // "true" to serve the IF-T/TLS data path only
	OptServerESPPort      = "esp-port"      // UDP port for the ESP data path (default 4500)
	OptServerPublicIP     = "public"        // address clients reach this gateway on
	OptServerTUN          = "tun"           // TUN interface name
	OptServerShape        = "shape"         // per-flow downstream shaping budget in bytes (0 = off)
)

// ServerConfig configures an Ivanti Connect Secure gateway.
type ServerConfig struct {
	ListenIP string
	Port     int
	Pool     string
	Cert     []byte
	Key      []byte
	Users    map[string]string
	DNS      []net.IP
	Domain   string
	// SplitInclude are the destinations clients are told to route into the
	// tunnel. Empty tells them nothing, which they read as "send everything".
	SplitInclude []*net.IPNet
	// NoESP serves the IF-T/TLS data path only, leaving the UDP port unbound
	// and handing out no keying material.
	NoESP bool
	// ESPPort is where ESP is served; 0 means the protocol's default of 4500.
	ESPPort int
	// PublicIP is the address clients reach this gateway on.
	PublicIP net.IP
	TUNName  string

	// Shape enables downstream traffic shaping. Clients need no support for it:
	// on the ESP path it is RFC 4303 section 2.7 traffic-flow confidentiality,
	// and on the IF-T/TLS path it is trailing filler after the inner packet,
	// which every IP stack trims by the packet's own header length.
	Shape int

	Logger *log.Logger
}

// Server is an Ivanti Connect Secure gateway.
type Server struct {
	cfg     ServerConfig
	tlsCfg  *tls.Config
	pool    *dataplane.AddrPool
	gateway net.IP
	tun     *dataplane.TUN
	engine  *ipulse.Server

	mu      sync.Mutex
	udpConn *net.UDPConn
	started bool
	closed  bool
}

// NewServer validates the configuration, loads the keypair, allocates the pool
// and opens the TUN. It binds no socket and changes no host state.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Cert) == 0 || len(cfg.Key) == 0 {
		return nil, errors.New("pulse: a TLS certificate and key are required")
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("pulse: at least one user is required")
	}
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("pulse: server keypair: %w", err)
	}

	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = defaultPool
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("pulse: address pool %q: %w", poolCIDR, err)
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("pulse: opening TUN: %w", err)
	}

	routes := make([]ipulse.Route, 0, len(cfg.SplitInclude))
	for _, n := range cfg.SplitInclude {
		routes = append(routes, ipulse.Route{Net: n})
	}

	engine, err := ipulse.NewServer(ipulse.ServerConfig{
		Users:    cfg.Users,
		Pool:     pool,
		ServerIP: gateway,
		PublicIP: cfg.PublicIP,
		DNS:      cfg.DNS,
		Domain:   cfg.Domain,
		Routes:   routes,
		NoESP:    cfg.NoESP,
		ESPPort:  cfg.ESPPort,
		Shape:    cfg.Shape,
		MTU:      client.DefaultTunnelMTU,
		Logger:   cfg.Logger,
	}, tun)
	if err != nil {
		_ = tun.Close()
		return nil, err
	}

	return &Server{
		cfg:     cfg,
		tlsCfg:  &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		pool:    pool,
		gateway: gateway,
		tun:     tun,
		engine:  engine,
	}, nil
}

// ListenAndServe binds the HTTPS socket, and the ESP socket unless disabled,
// and serves until Close. It blocks.
func (s *Server) ListenAndServe() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("pulse: server already started")
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
	ln, err := tls.Listen("tcp", net.JoinHostPort(listenIP, strconv.Itoa(port)), s.tlsCfg)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("pulse: listen: %w", err)
	}

	// The ESP socket is bound and armed before the listener accepts anything,
	// so no client is handed keys for a path that is not yet being read.
	if !s.cfg.NoESP {
		espPort := s.cfg.ESPPort
		if espPort == 0 {
			espPort = ipulse.DefaultESPPort
		}
		udp, uerr := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(listenIP), Port: espPort})
		if uerr != nil {
			_ = ln.Close()
			s.mu.Unlock()
			return fmt.Errorf("pulse: listen UDP: %w", uerr)
		}
		s.udpConn = udp
		s.engine.EnableESP(udp)
	}
	serveESP := s.udpConn != nil
	s.mu.Unlock()

	if serveESP {
		go s.engine.ServeESP()
	}
	go s.engine.RunTUN()

	if err := s.engine.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("pulse: serve: %w", err)
	}
	return nil
}

// Close stops the gateway.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	err := s.engine.Close()
	_ = s.tun.Close()
	return err
}

// TUNName is the interface the gateway is bound to.
func (s *Server) TUNName() string {
	if s.tun == nil {
		return ""
	}
	return s.tun.Name()
}

// Gateway is the gateway's own address inside the tunnel.
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet client addresses come from.
func (s *Server) Network() *net.IPNet { return s.pool.Network() }

// parseServerOptions turns registry options into a constructed Server.
func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		ListenIP: opts[OptServerListen],
		Pool:     opts[OptServerPool],
		Domain:   opts[OptServerDomain],
		NoESP:    opts[OptServerNoESP] == "true",
		TUNName:  opts[OptServerTUN],
		Logger:   log.New(logDest(), "", log.LstdFlags|log.Lmicroseconds),
	}
	user, pass := opts[OptServerUser], opts[OptServerPass]
	if user == "" || pass == "" {
		return nil, errors.New("pulse: user and pass are required")
	}
	cfg.Users = map[string]string{user: pass}

	if v := opts[OptServerPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("pulse: invalid port %q", v)
		}
		cfg.Port = p
	}
	if v := opts[OptServerESPPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("pulse: invalid esp-port %q", v)
		}
		cfg.ESPPort = p
	}
	if v := opts[OptServerPublicIP]; v != "" {
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("pulse: invalid public address %q", v)
		}
		cfg.PublicIP = ip
	}
	if v := opts[OptServerShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("pulse: invalid shape %q", v)
		}
		cfg.Shape = n
	}
	for d := range strings.SplitSeq(opts[OptServerDNS], ",") {
		if d = strings.TrimSpace(d); d != "" {
			if ip := net.ParseIP(d); ip != nil {
				cfg.DNS = append(cfg.DNS, ip)
			}
		}
	}
	for c := range strings.SplitSeq(opts[OptServerSplitInclude], ",") {
		if c = strings.TrimSpace(c); c != "" {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				return nil, fmt.Errorf("pulse: invalid split-include network %q: %w", c, err)
			}
			cfg.SplitInclude = append(cfg.SplitInclude, n)
		}
	}

	var err error
	if cfg.Cert, err = readFile(opts[OptServerCert]); err != nil {
		return nil, fmt.Errorf("pulse: certificate: %w", err)
	}
	if cfg.Key, err = readFile(opts[OptServerKey]); err != nil {
		return nil, fmt.Errorf("pulse: key: %w", err)
	}
	return NewServer(cfg)
}

// logDest is where the CLI-constructed logger writes.
func logDest() io.Writer { return os.Stdout }

// readFile reads a required PEM file, turning an empty path into a clear error.
func readFile(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("no path given")
	}
	return os.ReadFile(path)
}
