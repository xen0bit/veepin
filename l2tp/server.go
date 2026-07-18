package l2tp

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	engine "github.com/xen0bit/veepin/internal/l2tp"
)

func init() { client.RegisterServer("l2tp", parseServerOptions) }

// Server option keys for client.NewServer("l2tp", opts).
const (
	OptServerListen   = "listen"
	OptServerPublic   = "public"
	OptServerPort     = "port"
	OptServerPSK      = "psk"
	OptServerUser     = "user"
	OptServerPassword = "password"
	OptServerPool     = "pool"
	OptServerDNS      = "dns"
	OptServerTUN      = "tun"
)

const defaultPool = "10.20.0.0/24"

// ServerConfig configures an L2TP/IPsec responder and its userspace data path.
type ServerConfig struct {
	// ListenIP is the local IP to bind the IKE/ESP sockets on (default 0.0.0.0).
	ListenIP string
	// PublicIP is the server's address as clients reach it, used as the IKE
	// identity and phase-2 traffic selector. It defaults to ListenIP when that is
	// concrete, and must be set when listening on the wildcard.
	PublicIP string
	// Port is the combined IKE/ESP port (default 500).
	Port int
	// PSK authenticates the IPsec SA (required).
	PSK string
	// Users maps a username to its password for MS-CHAPv2 (at least one required).
	Users map[string]string
	// Pool is the internal address pool handed to clients, CIDR (default
	// 10.20.0.0/24). Its first host is the server's tunnel address.
	Pool string
	// DNS servers assigned to clients over IPCP.
	DNS []net.IP
	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string
	Logger  *log.Logger
}

// Server is a running L2TP/IPsec responder. It owns the TUN and the UDP socket
// but, like the other protocols, configures no host networking — Gateway and
// Network report what the caller needs to do that.
type Server struct {
	eng     *engine.Server
	tun     *dataplane.TUN
	pool    *dataplane.AddrPool
	gateway net.IP
}

// NewServer opens the TUN, creates the address pool, and binds the socket. It
// does not start serving until ListenAndServe.
func NewServer(cfg ServerConfig) (*Server, error) {
	switch {
	case cfg.PSK == "":
		return nil, fmt.Errorf("l2tp: PSK is required")
	case len(cfg.Users) == 0:
		return nil, fmt.Errorf("l2tp: at least one user is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = defaultPool
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("l2tp: address pool: %w", err)
	}
	port := cfg.Port
	if port == 0 {
		port = defaultPort
	}
	listenIP := net.ParseIP(cfg.ListenIP)
	if listenIP == nil {
		listenIP = net.IPv4zero
	}
	// Two sockets: Main Mode arrives on the IKE port, and everything after the
	// NAT-T float — IKE behind the non-ESP marker, and UDP-encapsulated ESP —
	// arrives on 4500.
	ikeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: listenIP, Port: port})
	if err != nil {
		return nil, fmt.Errorf("l2tp: bind %s:%d: %w", cfg.ListenIP, port, err)
	}
	nattConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: listenIP, Port: nattPort})
	if err != nil {
		ikeConn.Close()
		return nil, fmt.Errorf("l2tp: bind %s:%d: %w", cfg.ListenIP, nattPort, err)
	}
	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		ikeConn.Close()
		nattConn.Close()
		return nil, fmt.Errorf("l2tp: open TUN: %w", err)
	}

	eng := engine.NewServer(ikeConn, nattConn, tun, engine.ServerConfig{
		PSK:      []byte(cfg.PSK),
		Users:    cfg.Users,
		PublicIP: net.ParseIP(cfg.PublicIP),
		Pool:     pool,
		Gateway:  gateway,
		DNS:      cfg.DNS,
		Logger:   logger,
	})
	return &Server{eng: eng, tun: tun, pool: pool, gateway: gateway}, nil
}

// ListenAndServe serves clients until Close. It blocks.
func (s *Server) ListenAndServe() error { return s.eng.Serve() }

// Close stops the server and releases the TUN and socket.
func (s *Server) Close() error {
	err := s.eng.Close()
	s.tun.Close()
	return err
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
		PublicIP: opts[OptServerPublic],
		PSK:      opts[OptServerPSK],
		Pool:     opts[OptServerPool],
		DNS:      parseIPList(opts[OptServerDNS]),
		TUNName:  opts[OptServerTUN],
		Logger:   log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
	if cfg.ListenIP == "" {
		cfg.ListenIP = "0.0.0.0"
	}
	if v := opts[OptServerPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("l2tp: invalid port %q", v)
		}
		cfg.Port = p
	}
	if user := opts[OptServerUser]; user != "" {
		cfg.Users = map[string]string{user: opts[OptServerPassword]}
	}
	return NewServer(cfg)
}
