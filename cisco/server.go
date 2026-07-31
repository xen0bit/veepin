package cisco

// The server role: a Cisco-style IPsec remote-access gateway.
//
// The facade mirrors every other server here: NewServer validates configuration,
// allocates the address pool and opens the TUN, but binds no socket, so the
// caller configures host networking before ListenAndServe. The two UDP sockets —
// the IKE port and the NAT-T port — are bound there.

import (
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
	icisco "github.com/xen0bit/veepin/internal/cisco"
)

func init() {
	client.RegisterServer("cisco", parseServerOptions)
	client.RegisterServerOpts("cisco", []client.OptSpec{
		{Key: OptServerListen, Kind: client.OptStr, Default: "0.0.0.0", Help: "local IP to bind the IKE sockets on (default 0.0.0.0)"},
		{Key: OptServerPort, Kind: client.OptInt, Default: "500", Help: "IKE port to listen on (default 500; the NAT-T port is always 4500)"},
		{Key: OptServerGroup, Kind: client.OptStr, Required: true, Help: "group name clients must present"},
		{Key: OptServerGroupPSK, Kind: client.OptStr, Required: true, Secret: true, Generate: "psk", Help: "the group's pre-shared key"},
		{Key: OptServerUser, Kind: client.OptStr, Required: true, Help: "XAuth username to accept"},
		{Key: OptServerPass, Kind: client.OptStr, Required: true, Secret: true, Help: "the user's password"},
		{Key: OptServerPool, Kind: client.OptCIDR, Default: "10.60.0.0/24", Help: "internal address pool handed to clients (default 10.60.0.0/24)"},
		{Key: OptServerDNS, Kind: client.OptCommaList, Help: "comma-separated DNS servers offered to clients"},
		{Key: OptServerDomain, Kind: client.OptStr, Help: "default search domain offered to clients"},
		{Key: OptServerBanner, Kind: client.OptStr, Help: "login banner shown to clients"},
		{Key: OptServerSplitInclude, Kind: client.OptCommaList, Help: "comma-separated CIDRs clients should route into the tunnel (empty = everything)"},
		{Key: OptServerPublicIP, Kind: client.OptStr, Help: "address clients reach this gateway on (empty = the bound address)"},
		{Key: OptServerTUN, Kind: client.OptStr, Help: "TUN interface name (empty = kernel picks)"},
		{Key: OptServerShape, Kind: client.OptInt, Default: "0", Help: "per-flow downstream shaping budget in bytes (0 = off)"},
	})
}

const defaultPool = "10.60.0.0/24"

// Server option keys accepted by client.NewServer("cisco", opts).
const (
	OptServerListen       = "listen"        // local IP to bind (default 0.0.0.0)
	OptServerPort         = "port"          // IKE port (default 500)
	OptServerGroup        = "group"         // group name clients present (required)
	OptServerGroupPSK     = "group-psk"     // that group's pre-shared key (required)
	OptServerUser         = "user"          // XAuth username to accept (required)
	OptServerPass         = "pass"          // that user's password (required)
	OptServerPool         = "pool"          // client address pool CIDR
	OptServerDNS          = "dns"           // comma-separated DNS servers offered to clients
	OptServerDomain       = "domain"        // default search domain offered to clients
	OptServerBanner       = "banner"        // login banner shown to clients
	OptServerSplitInclude = "split-include" // comma-separated CIDRs clients should route into the tunnel
	OptServerPublicIP     = "public"        // address clients reach this gateway on
	OptServerTUN          = "tun"           // TUN interface name
	OptServerShape        = "shape"         // per-flow downstream shaping budget in bytes (0 = off)
)

// ServerConfig configures a Cisco IPsec gateway.
type ServerConfig struct {
	ListenIP string
	// Port is the IKE port; 0 means 500. The NAT-T port is fixed at 4500 by
	// RFC 3948 and is not configurable, because a client looking for the float
	// has nowhere to be told otherwise.
	Port int
	// Groups maps a group name to its pre-shared key.
	Groups map[string][]byte
	// Users maps an XAuth username to its password.
	Users map[string]string
	Pool  string
	DNS   []net.IP
	// Domain and Banner are Cisco Unity attributes: a default search domain and
	// a login message, both pushed in the Mode-Config reply.
	Domain string
	Banner string
	// SplitInclude are the destinations clients are told to route into the
	// tunnel. Empty tells them nothing, which they read as "send everything".
	SplitInclude []*net.IPNet
	// PublicIP is the address clients reach this gateway on. It is hashed into
	// the NAT-D payloads, so a gateway on the wildcard must be told.
	PublicIP net.IP
	TUNName  string

	// Shape enables downstream traffic shaping: how much padded output each
	// inner flow is given before shaping stops for that flow. Zero disables it.
	//
	// Clients need no support for it: the padding is RFC 4303 section 2.7
	// traffic-flow confidentiality, which any conforming ESP receiver discards
	// by reading the inner IP header's own length. A stock client benefits
	// unmodified. dataplane.DefaultShapeBytes is a reasonable value.
	Shape int

	Logger *log.Logger
}

// Server is a Cisco IPsec gateway.
type Server struct {
	cfg     ServerConfig
	pool    *dataplane.AddrPool
	gateway net.IP
	tun     *dataplane.TUN

	mu      sync.Mutex
	engine  *icisco.Server
	started bool
	closed  bool
}

// NewServer validates the configuration, allocates the pool and opens the TUN.
// It binds no socket and changes no host state.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Groups) == 0 {
		return nil, errors.New("cisco: a group and its pre-shared key are required")
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("cisco: at least one user is required")
	}
	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = defaultPool
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("cisco: address pool %q: %w", poolCIDR, err)
	}
	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("cisco: opening TUN: %w", err)
	}
	return &Server{cfg: cfg, pool: pool, gateway: gateway, tun: tun}, nil
}

// ListenAndServe binds the IKE and NAT-T sockets and serves until Close. It
// blocks.
func (s *Server) ListenAndServe() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("cisco: server already started")
	}
	s.started = true

	listenIP := s.cfg.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	bind := net.ParseIP(listenIP)
	if bind == nil {
		s.mu.Unlock()
		return fmt.Errorf("cisco: invalid listen address %q", listenIP)
	}
	port := s.cfg.Port
	if port == 0 {
		port = icisco.DefaultIKEPort
	}

	ikeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bind, Port: port})
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("cisco: listen on the IKE port: %w", err)
	}
	nattConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bind, Port: icisco.DefaultNATTPort})
	if err != nil {
		_ = ikeConn.Close()
		s.mu.Unlock()
		return fmt.Errorf("cisco: listen on the NAT-T port: %w", err)
	}

	engine, err := icisco.NewServer(ikeConn, nattConn, s.tun, icisco.ServerConfig{
		Groups:       s.cfg.Groups,
		Users:        s.cfg.Users,
		PublicIP:     s.cfg.PublicIP,
		Pool:         s.pool,
		Gateway:      s.gateway,
		DNS:          s.cfg.DNS,
		Domain:       s.cfg.Domain,
		Banner:       s.cfg.Banner,
		SplitInclude: s.cfg.SplitInclude,
		Shape:        s.cfg.Shape,
		MTU:          client.DefaultTunnelMTU,
		Logger:       s.cfg.Logger,
	})
	if err != nil {
		_ = ikeConn.Close()
		_ = nattConn.Close()
		s.mu.Unlock()
		return err
	}
	s.engine = engine
	s.mu.Unlock()

	return engine.Serve()
}

// Close stops the gateway.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	engine := s.engine
	s.mu.Unlock()

	if engine != nil {
		_ = engine.Close()
	}
	return s.tun.Close()
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
		Banner:   opts[OptServerBanner],
		TUNName:  opts[OptServerTUN],
		Logger:   log.New(logDest(), "", log.LstdFlags|log.Lmicroseconds),
	}
	group, psk := opts[OptServerGroup], opts[OptServerGroupPSK]
	if group == "" || psk == "" {
		return nil, errors.New("cisco: group and group-psk are required")
	}
	cfg.Groups = map[string][]byte{group: []byte(psk)}

	user, pass := opts[OptServerUser], opts[OptServerPass]
	if user == "" || pass == "" {
		return nil, errors.New("cisco: user and pass are required")
	}
	cfg.Users = map[string]string{user: pass}

	if v := opts[OptServerPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("cisco: invalid port %q", v)
		}
		cfg.Port = p
	}
	if v := opts[OptServerPublicIP]; v != "" {
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("cisco: invalid public address %q", v)
		}
		cfg.PublicIP = ip
	}
	if v := opts[OptServerShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("cisco: invalid shape %q", v)
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
				return nil, fmt.Errorf("cisco: invalid split-include network %q: %w", c, err)
			}
			cfg.SplitInclude = append(cfg.SplitInclude, n)
		}
	}
	return NewServer(cfg)
}

// logDest is where the CLI-constructed logger writes.
func logDest() io.Writer { return os.Stdout }
