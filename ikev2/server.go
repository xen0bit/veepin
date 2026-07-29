package ikev2

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
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

	// Pool is the internal IPv4 address pool handed to clients in CIDR form
	// (default 10.10.10.0/24). Its first host is the server's tunnel address.
	Pool string
	// Pool6 is the internal IPv6 address pool (default fd00:10:10::/64). When set,
	// clients are assigned an IPv6 address as well (dual-stack) via config mode.
	Pool6 string
	// DNS servers pushed to clients via config mode.
	DNS []net.IP

	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string

	// EAPUsers is a path to a username:password file. When set, clients may
	// authenticate with EAP-MSCHAPv2 instead of the PSK; the server still
	// authenticates itself with the PSK.
	EAPUsers string

	// CertFile/KeyFile, if set, authenticate the server with an X.509
	// certificate (RFC 7427 digital signature) instead of the PSK. ClientCAFile
	// is a PEM bundle enabling client certificate authentication; a client whose
	// certificate chains to it may authenticate without the PSK.
	CertFile     string
	KeyFile      string
	ClientCAFile string

	// Shape enables downstream traffic shaping: how much padded output each
	// inner flow is given before shaping stops for that flow, so it bounds what
	// shaping costs. A flow gets Shape/MTU padded packets whatever sizes it
	// carries. Zero, the default, disables it.
	//
	// It hides the size pattern of an inner TLS handshake, which otherwise
	// survives encapsulation (see dataplane/shape.go). Clients need no support
	// for it — the padding is inert to any conforming ESP receiver — so a stock
	// Windows, macOS, iOS or Android client benefits unmodified.
	// dataplane.DefaultShapeBytes is a reasonable value.
	Shape int

	// IPTFS permits AGGFRAG (RFC 9347) on Child SAs whose client asks for it.
	// The responder never initiates it -- USE_AGGFRAG is only agreed when both
	// peers send the notify -- so this gates the echo, not the offer.
	IPTFS bool

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
	ike   *ike.Server
	pump  *dataplane.Pump
	tun   *dataplane.TUN
	pool  *dataplane.AddrPool
	pool6 *dataplane.AddrPool6 // nil unless dual-stack

	gateway  net.IP
	gateway6 netip.Addr
}

// NewServer builds a server from cfg: it opens the TUN device, creates the
// address pool, and wires the ESP data path to the IKE layer. It does not bind
// the sockets until ListenAndServe.
//
// Opening a TUN device requires CAP_NET_ADMIN.
func NewServer(cfg ServerConfig) (*Server, error) {
	switch {
	case cfg.PSK == "" && cfg.CertFile == "":
		return nil, fmt.Errorf("ikev2: a PSK or certificate is required")
	case cfg.LocalID == "":
		return nil, fmt.Errorf("ikev2: LocalID is required")
	case cfg.CertFile != "" && cfg.KeyFile == "":
		return nil, fmt.Errorf("ikev2: CertFile requires KeyFile")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	var serverCert *tls.Certificate
	if cfg.CertFile != "" {
		c, err := loadTLSCert(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("ikev2: server certificate: %w", err)
		}
		serverCert = c
	}
	var clientCAs *x509.CertPool
	if cfg.ClientCAFile != "" {
		pool, err := loadCAPool(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("ikev2: client CA bundle: %w", err)
		}
		clientCAs = pool
	}
	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = "10.10.10.0/24"
	}

	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("ikev2: address pool: %w", err)
	}

	pool6CIDR := cfg.Pool6
	if pool6CIDR == "" {
		pool6CIDR = "fd00:10:10::/64"
	}
	pool6, gateway6, err := dataplane.NewAddrPool6(pool6CIDR)
	if err != nil {
		return nil, fmt.Errorf("ikev2: IPv6 address pool: %w", err)
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
		ListenIP:   cfg.ListenIP,
		Port500:    cfg.Port500,
		Port4500:   cfg.Port4500,
		PSK:        []byte(cfg.PSK),
		LocalID:    parseIdentity(cfg.LocalID),
		PublicIP:   cfg.PublicIP,
		ServerCert: serverCert,
		ClientCAs:  clientCAs,
		IPTFS:      cfg.IPTFS,
		Logger:     logger,
		AssignAddr: func() (ike.Assignment, error) {
			ip, aerr := pool.Allocate()
			if aerr != nil {
				return ike.Assignment{}, aerr
			}
			a := ike.Assignment{IP4: ip, Netmask: pool.Netmask(), DNS: cfg.DNS}
			// Dual-stack: hand out an IPv6 address too. A v6 exhaustion is
			// non-fatal — the client still gets a working IPv4-only tunnel.
			if ip6, a6err := pool6.Allocate(); a6err == nil {
				a.IP6 = net.IP(ip6.AsSlice())
				a.Prefix6 = pool6.Bits()
			} else {
				logger.Printf("ikev2: IPv6 assignment skipped: %v", a6err)
			}
			return a, nil
		},
		ReleaseAddr: func(a ike.Assignment) {
			pool.Release(a.IP4)
			if a.IP6 != nil {
				if ip6, ok := netip.AddrFromSlice(a.IP6); ok {
					pool6.Release(ip6)
				}
			}
		},
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
	if cfg.Shape > 0 {
		pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape}))
		logger.Printf("ikev2: downstream shaping on, %d bytes per flow", cfg.Shape)
	}
	srv.SetDataPath(ike.NewPumpDataPath(pump))

	return &Server{
		ike: srv, pump: pump, tun: tun,
		pool: pool, pool6: pool6,
		gateway: gateway, gateway6: gateway6,
	}, nil
}

// TUNName is the interface the data path is bound to.
func (s *Server) TUNName() string { return s.tun.Name() }

// Gateway is the server's own tunnel-side address (the pool's first host).
func (s *Server) Gateway() net.IP { return s.gateway }

// Gateway6 is the server's tunnel-side IPv6 address (the v6 pool's first host).
func (s *Server) Gateway6() netip.Addr { return s.gateway6 }

// Network is the tunnel subnet, for routing and NAT rules.
func (s *Server) Network() *net.IPNet { return s.pool.Network() }

// Network6 is the tunnel's IPv6 subnet, for routing and NAT rules.
func (s *Server) Network6() netip.Prefix { return s.pool6.Prefix() }

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
	OptServerPool6    = "pool6"     // internal IPv6 address pool, CIDR (default fd00:10:10::/64)
	OptServerDNS      = "dns"       // comma-separated DNS servers pushed to clients
	OptServerTUN      = "tun"       // TUN interface name (empty = kernel picks)
	OptServerEAPUsers = "eap-users" // path to a username:password file enabling EAP-MSCHAPv2
	OptServerCert     = "cert"      // server certificate PEM (enables certificate auth)
	OptServerKey      = "key"       // server private-key PEM
	OptServerClientCA = "client-ca" // CA bundle PEM enabling client certificate auth
	OptServerShape    = "shape"     // per-flow downstream shaping budget in bytes (0 = off)
	OptServerIPTFS    = "iptfs"     // permit AGGFRAG (RFC 9347) for clients that request it
)

func init() { client.RegisterServer("ikev2", parseServerOptions) }

// parseServerOptions builds an IKEv2 responder from string options, the
// server-side counterpart of parseOptions. It applies the same defaults the CLI
// documents so the registry is usable standalone.
func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		ListenIP:     opts[OptServerListen],
		PSK:          opts[OptServerPSK],
		LocalID:      opts[OptServerIdentity],
		Pool:         opts[OptServerPool],
		Pool6:        opts[OptServerPool6],
		TUNName:      opts[OptServerTUN],
		EAPUsers:     opts[OptServerEAPUsers],
		CertFile:     opts[OptServerCert],
		KeyFile:      opts[OptServerKey],
		ClientCAFile: opts[OptServerClientCA],
		Logger:       log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
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
	cfg.IPTFS = opts[OptServerIPTFS] == "true"
	if v := opts[OptServerShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("ikev2: invalid %s %q", OptServerShape, v)
		}
		cfg.Shape = n
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
