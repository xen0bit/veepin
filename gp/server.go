package gp

// The server role: a GlobalProtect gateway.
//
// It hands a TLS listener to internal/gp, which serves the control plane —
// prelogin, login, getconfig, logout — over net/http and splits the packet tunnel
// off in front of it, alongside a read loop over the shared TUN and, unless
// disabled, the UDP socket that carries ESP. The facade mirrors every other
// server here: NewServer validates configuration and opens the TUN but binds no
// socket, so the caller configures host networking before ListenAndServe.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	igp "github.com/xen0bit/veepin/internal/gp"
	"github.com/xen0bit/veepin/internal/pqpolicy"
	"github.com/xen0bit/veepin/internal/userdb"
	"github.com/xen0bit/veepin/internal/vlog"
)

func init() {
	client.RegisterServer("gp", parseServerOptions)
	client.RegisterServerOpts("gp", []client.OptSpec{
		{Key: OptServerCert, Kind: client.OptFilePath, Required: true, Generate: "tls", Help: "path to the server TLS certificate PEM"},
		{Key: OptServerKey, Kind: client.OptFilePath, Required: true, Secret: true, Generate: "tls", Help: "path to the server TLS private key PEM"},
		{Key: OptServerListen, Kind: client.OptStr, Default: "0.0.0.0", Help: "local IP to bind the HTTPS socket on (default 0.0.0.0)"},
		{Key: OptServerPort, Kind: client.OptInt, Default: "443", Help: "HTTPS port to listen on (default 443)"},
		{Key: OptServerESPPort, Kind: client.OptInt, Default: "4501", Help: "UDP port for the ESP data path (default 4501)"},
		{Key: OptServerPublicIP, Kind: client.OptStr, Help: "address clients reach this gateway on, advertised as the ESP endpoint (empty = the address their control connection arrived on)"},
		{Key: OptServerPool, Kind: client.OptCIDR, Default: "10.50.0.0/24", Help: "internal address pool handed to clients (default 10.50.0.0/24)"},
		{Key: OptServerDNS, Kind: client.OptCommaList, Help: "comma-separated DNS servers offered to clients"},
		{Key: OptServerUser, Kind: client.OptStr, Help: "username to accept; the one-user shorthand for users-file, and one of the two is required"},
		{Key: OptServerPass, Kind: client.OptStr, Secret: true, Help: "the password for user"},
		{Key: OptServerUsers, Kind: client.OptFilePath, Secret: true, Help: "path to a file of username:secret lines, for more than one user; the secret may be a bcrypt verifier"},
		{Key: OptServerNoESP, Kind: client.OptBool, Help: "serve the SSL tunnel only, leaving the UDP port unbound"},
		client.TUNOpt(OptServerTUN),
		client.ShapeOpt(OptServerShape, "downstream"),
	})
}

const defaultPool = "10.50.0.0/24"

// Server option keys accepted by client.NewServer("gp", opts).
const (
	OptServerListen   = "listen"     // local IP to bind (default 0.0.0.0)
	OptServerPort     = "port"       // HTTPS port (default 443)
	OptServerPool     = "pool"       // client address pool CIDR
	OptServerCert     = "cert"       // TLS certificate PEM (required)
	OptServerKey      = "key"        // TLS private key PEM (required)
	OptServerUser     = "user"       // username to accept (required)
	OptServerPass     = "pass"       // that user's password (required)
	OptServerUsers    = "users-file" // path to a file of username:secret lines (more than one user)
	OptServerDNS      = "dns"        // comma-separated DNS servers offered to clients
	OptServerNoESP    = "no-esp"     // "true" to serve the SSL tunnel only
	OptServerESPPort  = "esp-port"   // UDP port for the ESP data path (default 4501)
	OptServerPublicIP = "public"     // address clients reach this gateway on
	OptServerTUN      = "tun"        // TUN interface name
	OptServerShape    = "shape"      // per-flow downstream shaping budget in bytes (0 = off)
)

// ServerConfig configures a GlobalProtect gateway.
type ServerConfig struct {
	ListenIP string
	Port     int
	Pool     string
	Cert     []byte
	Key      []byte
	Users    map[string]string
	DNS      []net.IP
	Domain   string
	// NoESP serves the SSL tunnel only, leaving the UDP port unbound and handing
	// out no keying material.
	NoESP bool
	// ESPPort is where ESP is served; 0 means the protocol's default of 4501.
	ESPPort int
	// PublicIP is the address clients reach this gateway on, advertised to them
	// as the ESP endpoint. Empty means "whatever address the client's own control
	// connection arrived on", which is right unless the gateway is behind a DNAT.
	PublicIP net.IP
	TUNName  string

	// Shape enables downstream traffic shaping: how much padded output each inner
	// flow is given before shaping stops for that flow, so it bounds what shaping
	// costs. Zero, the default, disables it.
	//
	// Clients need no support for it. On the ESP path the padding is RFC 4303 §2.7
	// traffic-flow confidentiality; on the SSL tunnel it is trailing bytes after
	// the inner packet, which every IP stack trims by the packet's own header
	// length. Either way a stock GlobalProtect client benefits unmodified.
	// dataplane.DefaultShapeBytes is a reasonable value.
	Shape int

	Logger *slog.Logger

	// PostQuantumOnly requires a post-quantum key exchange and ML-DSA
	// authentication, refusing anything less rather than negotiating down. It is
	// what the pq-gp registry name sets; see internal/pqpolicy for the contract
	// and doc/pq-variants-plan.md for why it is a name rather than a flag.
	PostQuantumOnly bool
}

// Server is a GlobalProtect gateway.
type Server struct {
	cfg     ServerConfig
	tlsCfg  *tls.Config
	pool    *dataplane.AddrPool
	gateway net.IP
	tun     *dataplane.TUN
	engine  *igp.Server

	mu      sync.Mutex
	udpConn *net.UDPConn
	started bool
	closed  bool
}

// NewServer validates the configuration, loads the keypair, allocates the pool
// and opens the TUN. It binds no socket and changes no host state.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Cert) == 0 || len(cfg.Key) == 0 {
		return nil, errors.New("gp: a TLS certificate and key are required")
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("gp: at least one user is required")
	}
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("gp: server keypair: %w", err)
	}

	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = defaultPool
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("gp: address pool %q: %w", poolCIDR, err)
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("gp: opening TUN: %w", err)
	}

	engine, err := igp.NewServer(igp.ServerConfig{
		Users:    cfg.Users,
		Pool:     pool,
		ServerIP: gateway,
		PublicIP: cfg.PublicIP,
		DNS:      cfg.DNS,
		Domain:   cfg.Domain,
		NoESP:    cfg.NoESP,
		ESPPort:  cfg.ESPPort,
		Logger:   vlog.From(cfg.Logger),
		Shape:    cfg.Shape,
		MTU:      client.DefaultTunnelMTU,
	}, tun)
	if err != nil {
		_ = tun.Close()
		return nil, err
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if cfg.PostQuantumOnly {
		// Checked before the TUN is opened and before anything binds: an
		// operator who pointed a pq- name at their existing RSA certificate
		// learns it here, rather than from a listener that comes up and then
		// refuses every client.
		if err := pqpolicy.CheckCredential(cert); err != nil {
			return nil, err
		}
		pqpolicy.HardenTLS(tlsCfg)
	}

	return &Server{
		cfg:     cfg,
		tlsCfg:  tlsCfg,
		pool:    pool,
		gateway: gateway,
		tun:     tun,
		engine:  engine,
	}, nil
}

// ListenAndServe binds the HTTPS socket, and the ESP socket unless disabled, and
// serves until Close. It blocks.
func (s *Server) ListenAndServe() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("gp: server already started")
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
		return fmt.Errorf("gp: listen: %w", err)
	}

	// The ESP socket is bound and armed before the HTTPS listener accepts
	// anything, so no client is ever handed keys for a path that is not yet being
	// read.
	if !s.cfg.NoESP {
		espPort := s.cfg.ESPPort
		if espPort == 0 {
			espPort = igp.DefaultESPPort
		}
		udp, uerr := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(listenIP), Port: espPort})
		if uerr != nil {
			_ = ln.Close()
			s.mu.Unlock()
			return fmt.Errorf("gp: listen UDP: %w", uerr)
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

	// The engine serves the listener itself rather than being handed to an
	// http.Server here: the packet tunnel has to be split off in front of
	// net/http, which will not accept the request that opens it.
	if err := s.engine.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("gp: serve: %w", err)
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

	return s.engine.Close()
}

// Abandon implements client.AbandonableServer. It closes the TUN directly, so
// an abandoned listener's packet pump unparks and its descriptor is released
// even though Close never returned. See client.AbandonableServer for why this
// is not simply Close.
//
// The TUN is set in NewServer and never reassigned, so this reads it without
// the lock Close takes -- deliberately, because a wedged Close may be holding
// that lock, and waiting on it here would reproduce the very stall this is the
// escape from.
func (s *Server) Abandon() { s.tun.Close() }

// Server implements client.AbandonableServer, so the supervisor can take its
// descriptors back when Close overruns. Asserted here because the interface is
// found by type assertion at the one call site: without this, a renamed or
// re-signatured Abandon compiles fine and the assertion silently starts failing,
// which reads as the leak coming back.
var _ client.AbandonableServer = (*Server)(nil)

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
		PostQuantumOnly: pqpolicy.Requested(opts),
		ListenIP:        opts[OptServerListen],
		Pool:            opts[OptServerPool],
		NoESP:           opts[OptServerNoESP] == "true",
		TUNName:         opts[OptServerTUN],
		Logger:          vlog.SlogText(logDest()),
	}
	user, pass := opts[OptServerUser], opts[OptServerPass]
	if user != "" && pass == "" {
		return nil, errors.New("gp: a named user needs a pass")
	}
	users, uerr := userdb.Resolve(userdb.Verifiable, opts[OptServerUsers], user, pass)
	if uerr != nil {
		return nil, fmt.Errorf("gp: %w", uerr)
	}
	if len(users) == 0 {
		return nil, errors.New("gp: user and pass, or users-file, are required")
	}
	cfg.Users = users

	if v := opts[OptServerPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("gp: invalid port %q", v)
		}
		cfg.Port = p
	}
	if v := opts[OptServerESPPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("gp: invalid esp-port %q", v)
		}
		cfg.ESPPort = p
	}
	if v := opts[OptServerPublicIP]; v != "" {
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("gp: invalid public address %q", v)
		}
		cfg.PublicIP = ip
	}
	if v := opts[OptServerShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("gp: invalid shape %q", v)
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

	var err error
	if cfg.Cert, err = readFile(opts[OptServerCert]); err != nil {
		return nil, fmt.Errorf("gp: certificate: %w", err)
	}
	if cfg.Key, err = readFile(opts[OptServerKey]); err != nil {
		return nil, fmt.Errorf("gp: key: %w", err)
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
