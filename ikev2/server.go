package ikev2

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/eap"
	"github.com/xen0bit/veepin/internal/ikev2/ike"
)

// ServerConfig configures an IKEv2 responder and its userspace data path.
type ServerConfig struct {
	// ListenIP is the local IP to bind the IKE sockets on (default 0.0.0.0).
	ListenIP string
	// Port500 / Port4500 are the IKE and NAT-T ports (defaults 500 and 4500).
	// They are overridable mainly for tests.
	Port500  int
	Port4500 int

	// PSK authenticates every peer, and the server to them (required).
	PSK string
	// LocalID is the identity presented to clients — an FQDN or IP literal
	// (required).
	LocalID string
	// PublicIP is the server's address as clients see it, used for NAT
	// detection. If nil, detection still works but may over-report NAT.
	PublicIP net.IP

	// Pool is the internal address pool handed to clients in CIDR form
	// (default 10.10.10.0/24). Its first host is the server's tunnel address.
	Pool string
	// DNS servers pushed to clients via config mode.
	DNS []net.IP

	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string

	// EAPUsers is a path to a username:password file. When set, clients may
	// authenticate with EAP-MSCHAPv2 instead of the PSK; the server still
	// authenticates itself with the PSK.
	EAPUsers string

	// Logger receives progress logs; nil discards them.
	Logger *log.Logger
}

// Server is a running IKEv2 responder: the IKE SAs, a TUN device, an address
// pool and the ESP data path, wired together.
//
// It owns the TUN device but deliberately does not configure the host's
// networking (interface address, forwarding, NAT). Gateway and Network report
// what a caller needs to do that itself.
type Server struct {
	ike  *ike.Server
	pump *dataplane.Pump
	tun  *dataplane.TUN
	pool *dataplane.AddrPool

	gateway net.IP
}

// NewServer builds a server from cfg: it opens the TUN device, creates the
// address pool, and wires the ESP data path to the IKE layer. It does not bind
// the sockets until ListenAndServe.
//
// Opening a TUN device requires CAP_NET_ADMIN.
func NewServer(cfg ServerConfig) (*Server, error) {
	switch {
	case cfg.PSK == "":
		return nil, fmt.Errorf("ikev2: PSK is required")
	case cfg.LocalID == "":
		return nil, fmt.Errorf("ikev2: LocalID is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = "10.10.10.0/24"
	}

	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("ikev2: address pool: %w", err)
	}

	var eapLookup eap.CredentialLookup
	if cfg.EAPUsers != "" {
		store, lerr := eap.LoadFileStore(cfg.EAPUsers)
		if lerr != nil {
			return nil, fmt.Errorf("ikev2: loading EAP users: %w", lerr)
		}
		eapLookup = store.Lookup
		logger.Printf("ikev2: EAP-MSCHAPv2 enabled with %d user(s) from %s", store.Count(), cfg.EAPUsers)
	}

	// GSO: the kernel may hand the pump TCP super-frames to segment and batch
	// (doc/scaling-the-data-path.md); falls back to a plain TUN transparently.
	tun, err := dataplane.OpenTUNGSO(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("ikev2: open TUN: %w", err)
	}

	srv, err := ike.NewServer(ike.Config{
		ListenIP: cfg.ListenIP,
		Port500:  cfg.Port500,
		Port4500: cfg.Port4500,
		PSK:      []byte(cfg.PSK),
		LocalID:  parseIdentity(cfg.LocalID),
		PublicIP: cfg.PublicIP,
		Logger:   logger,
		AssignAddr: func() (net.IP, net.IP, []net.IP, error) {
			ip, aerr := pool.Allocate()
			if aerr != nil {
				return nil, nil, nil, aerr
			}
			return ip, pool.Netmask(), cfg.DNS, nil
		},
		ReleaseAddr:    func(ip net.IP) { pool.Release(ip) },
		EAPCredentials: eapLookup,
		EAPServerName:  cfg.LocalID,
	})
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("ikev2: %w", err)
	}

	// The pump sends through the server's own NAT-T socket, and the server
	// hands it inbound ESP — hence SetDataPath after both exist.
	pump := dataplane.NewPump(tun, srv.SendESP, dataplane.SPIDemux, logger)
	pump.SetBatchSender(srv.SendESPBatch)
	srv.SetDataPath(ike.NewPumpDataPath(pump))

	return &Server{ike: srv, pump: pump, tun: tun, pool: pool, gateway: gateway}, nil
}

// TUNName is the interface the data path is bound to.
func (s *Server) TUNName() string { return s.tun.Name() }

// Gateway is the server's own tunnel-side address (the pool's first host).
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet, for routing and NAT rules.
func (s *Server) Network() *net.IPNet { return s.pool.Network() }

// ListenAndServe starts the data path and serves IKE until Close.
func (s *Server) ListenAndServe() error {
	go s.pump.Run()
	return s.ike.ListenAndServe()
}

// Close stops the data path and releases the TUN device and sockets.
func (s *Server) Close() error {
	s.pump.Close()
	err := s.ike.Close()
	s.tun.Close()
	return err
}

// Server option keys for client.NewServer("ikev2", opts).
const (
	OptServerListen   = "listen"    // local IP to bind IKE sockets on (default 0.0.0.0)
	OptServerPublic   = "public"    // server's public IP as clients see it (NAT detection)
	OptServerPSK      = "psk"       // pre-shared key (required)
	OptServerIdentity = "id"        // server identity presented to clients (required)
	OptServerPool     = "pool"      // internal address pool, CIDR (default 10.10.10.0/24)
	OptServerDNS      = "dns"       // comma-separated DNS servers pushed to clients
	OptServerTUN      = "tun"       // TUN interface name (empty = kernel picks)
	OptServerEAPUsers = "eap-users" // path to a username:password file enabling EAP-MSCHAPv2
)

func init() { client.RegisterServer("ikev2", parseServerOptions) }

// parseServerOptions builds an IKEv2 responder from string options, the
// server-side counterpart of parseOptions. It applies the same defaults the CLI
// documents so the registry is usable standalone.
func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		ListenIP: opts[OptServerListen],
		PSK:      opts[OptServerPSK],
		LocalID:  opts[OptServerIdentity],
		Pool:     opts[OptServerPool],
		TUNName:  opts[OptServerTUN],
		EAPUsers: opts[OptServerEAPUsers],
		Logger:   log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
	if cfg.ListenIP == "" {
		cfg.ListenIP = "0.0.0.0"
	}
	if cfg.Pool == "" {
		cfg.Pool = "10.10.10.0/24"
	}
	// -public defaults to -listen when that is a concrete address.
	if v := opts[OptServerPublic]; v != "" {
		cfg.PublicIP = net.ParseIP(v)
	} else if ip := net.ParseIP(cfg.ListenIP); ip != nil && !ip.IsUnspecified() {
		cfg.PublicIP = ip
	}
	if v := opts[OptServerDNS]; v != "" {
		cfg.DNS = parseIPList(v)
	}
	return NewServer(cfg)
}

// parseIPList parses a comma-separated list of IP addresses, skipping blanks and
// unparseable entries.
func parseIPList(list string) []net.IP {
	var out []net.IP
	for s := range strings.SplitSeq(list, ",") {
		if s = strings.TrimSpace(s); s != "" {
			if ip := net.ParseIP(s); ip != nil {
				out = append(out, ip)
			}
		}
	}
	return out
}
