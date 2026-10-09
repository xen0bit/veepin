package wireguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/vlog"
	iwg "github.com/xen0bit/veepin/internal/wireguard"
)

// ServerConfig configures a WireGuard responder and its userspace data path.
type ServerConfig struct {
	// PrivateKey is the server's static private key, base64 (required).
	PrivateKey string
	// ListenPort is the UDP port to accept handshakes on (required).
	ListenPort int
	// ListenIP is the local address to bind on; empty binds all interfaces.
	ListenIP string
	// Address is the server's own tunnel address in CIDR form, e.g.
	// "10.10.0.1/24" (required). Its host is the gateway; its network is used
	// for routing and NAT.
	Address string
	// Address6 is the same for the IPv6 half, e.g. "fd00:10::1/64". Empty
	// leaves the tunnel IPv4-only.
	//
	// WireGuard assigns nothing: a peer's tunnel address is its AllowedIPs,
	// configured at both ends. So this is only the server's *own* address —
	// which is exactly what was missing, because without it the interface has
	// no v6 address, the kernel installs no connected route for the v6 prefix,
	// and the server cannot answer a ping to an address its peers are
	// configured to reach it at.
	Address6 string
	// MTU is the inner-interface MTU (0 uses the default).
	MTU int

	// Peers are the clients this server accepts, each keyed by its static public
	// key (required: a server with no peers accepts no one).
	Peers []ServerPeer

	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string
	// Logger receives progress logs; nil discards them.
	// Obfuscation, if non-zero enables DPI-resistant wire-format transforms
	// (AmneziaWG-style). Zero values reproduce stock WireGuard on the wire.
	Obfuscation ObfuscationConfig

	// Shape enables downstream traffic shaping: how much padded output each
	// inner flow is given before shaping stops for that flow, so it bounds what
	// shaping costs. A flow gets Shape/MTU padded packets whatever sizes it
	// carries. Zero, the default, disables it.
	//
	// It hides the size pattern of an inner TLS handshake, which otherwise
	// survives encapsulation (see dataplane/shape.go). Peers need no support
	// for it — WireGuard's inner packet delimits itself, so the filler is inert
	// to any conforming receiver, the official clients included.
	// dataplane.DefaultShapeBytes is a reasonable value.
	Shape int

	// CookieThreshold is how many handshake initiations a second the server
	// takes before it is under load, and starts answering initiations that
	// lack a valid mac2 with a cookie reply rather than a Diffie-Hellman (the
	// protocol's own flood defence, paper §5.3). Zero means
	// DefaultCookieThreshold; a negative value keeps the server under load
	// permanently, so that every initiation must first prove it can receive at
	// its source address -- a choice for a server already under attack, and
	// what the interop cell uses to make a stock client go through the
	// exchange.
	CookieThreshold int

	Logger *slog.Logger
}

// ServerPeer is one client the server will accept: its static public key, the
// inner addresses it may use, and an optional preshared key. The JSON tags are
// the on-disk shape of the OptServerPeers option: the management plane appends
// a peer to that array when it provisions a client config, and the parse below
// reads the same shape back.
type ServerPeer struct {
	PublicKey    string   `json:"public-key"`              // the client's static public key, base64 (required)
	PresharedKey string   `json:"preshared-key,omitempty"` // optional symmetric key, base64
	AllowedIPs   []string `json:"allowed-ips"`             // inner destinations routed to and accepted from this peer
}

// Server option keys for client.NewServer("wireguard", opts).
const (
	OptServerConfig           = "config"             // wg-quick server config file (interface + peers)
	OptServerPrivateKey       = "private-key"        // server static private key, base64
	OptServerListenIP         = "listen"             // local IP to bind the UDP socket on
	OptServerListenPort       = "listen-port"        // UDP port to listen on (default 51820)
	OptServerAddress          = "address"            // server tunnel address, CIDR
	OptServerAddress6         = "address6"           // server tunnel IPv6 address, CIDR (dual-stack)
	OptServerMTU              = "mtu"                // inner MTU
	OptServerTUN              = "tun"                // TUN interface name (empty = kernel picks)
	OptServerPeerPublicKey    = "peer-public-key"    // a single peer's static public key, base64
	OptServerPeerPresharedKey = "peer-preshared-key" // that peer's preshared key, base64 (optional)
	OptServerPeerAllowedIPs   = "peer-allowed-ips"   // that peer's allowed IPs, comma-separated CIDRs
	OptServerPeers            = "peers"              // additional peers as a JSON array of ServerPeer
	OptServerShape            = "shape"              // per-flow downstream shaping budget in bytes (0 = off)
	OptServerCookieThreshold  = "cookie-threshold"   // initiations/s before demanding cookies (-1 = always)
)

func init() {
	client.RegisterServer("wireguard", parseServerOptions)
	client.RegisterServerOpts("wireguard", []client.OptSpec{
		// Neither the private key nor the address is Required, despite both being
		// mandatory for a working server: a wg-quick file supplied via
		// OptServerConfig carries them, and parseServerOptions accepts that. A
		// spec marked Required makes the panel refuse a form that a config file
		// would have completed. AmneziaWG, which reuses this Server type and the
		// same parse, marks neither -- the two must agree.
		{Key: OptServerConfig, Kind: client.OptFilePath, Help: "wg-quick server config file (interface + peers)"},
		{Key: OptServerPrivateKey, Kind: client.OptStr, Secret: true, Generate: "wg-keypair", Help: "server static private key, base64 (required unless in -config)"},
		{Key: OptServerListenIP, Kind: client.OptStr, Default: "0.0.0.0", Help: "local IP to bind the UDP socket on (default 0.0.0.0)"},
		{Key: OptServerListenPort, Kind: client.OptInt, Default: "51820", Help: "UDP port to listen on (default 51820)"},
		{Key: OptServerAddress, Kind: client.OptCIDR, Help: "server tunnel address in CIDR form (required unless in -config)"},
		{Key: OptServerAddress6, Kind: client.OptCIDR, Help: "server tunnel IPv6 address in CIDR form, for a dual-stack tunnel"},
		{Key: OptServerMTU, Kind: client.OptInt, Default: "1420", Help: "inner MTU (default 1420)"},
		client.TUNOpt(OptServerTUN),
		{Key: OptServerPeerPublicKey, Kind: client.OptStr, Help: "a single peer's static public key, base64"},
		{Key: OptServerPeerPresharedKey, Kind: client.OptStr, Secret: true, Help: "the -peer-public-key peer's preshared key, base64 (optional)"},
		{Key: OptServerPeerAllowedIPs, Kind: client.OptCommaList, Help: "the -peer-public-key peer's allowed IPs, comma-separated CIDRs"},
		// OptStr, not OptCommaList: the value is a JSON document, and a
		// comma-list editor in the panel would split it on the commas inside it.
		{Key: OptServerPeers, Kind: client.OptStr, Help: "additional peers as a JSON array, e.g. [{\"public-key\":\"...\",\"allowed-ips\":[\"10.0.0.2/32\"]}] (managed by client-config generation)"},
		client.ShapeOpt(OptServerShape, "downstream"),
		{Key: OptServerCookieThreshold, Kind: client.OptInt, Default: "128", Help: "handshake initiations per second before the server is under load and demands a cookie (-1 = always)"},
	})
}

// parseServerOptions builds a WireGuard responder from string options, the
// server-side counterpart of parseOptions. Peers come from a wg-quick -config
// file; a single peer can also be supplied with the peer-* options for a quick
// server without a file.
// ServerConfigFromOptions builds a ServerConfig from the CLI option map. It is
// exported because AmneziaWG is WireGuard with a perturbed wire format and
// needs precisely this surface plus its obfuscation parameters; duplicating the
// parse there is how the two drift apart.
func ServerConfigFromOptions(opts map[string]string) (ServerConfig, error) {
	var sc ServerConfig
	if path := opts[OptServerConfig]; path != "" {
		parsed, err := ParseConfigFile(path)
		if err != nil {
			return sc, err
		}
		if sc, err = ServerConfigFromFile(parsed); err != nil {
			return sc, err
		}
	}
	if v := opts[OptServerPrivateKey]; v != "" {
		sc.PrivateKey = v
	}
	if v := opts[OptServerAddress6]; v != "" {
		sc.Address6 = v
	}
	if v := opts[OptServerAddress]; v != "" {
		sc.Address = v
	}
	if v := opts[OptServerListenPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return sc, fmt.Errorf("wireguard: invalid %s %q", OptServerListenPort, v)
		}
		sc.ListenPort = p
	}
	if sc.ListenPort == 0 {
		sc.ListenPort = 51820
	}
	if v := opts[OptServerMTU]; v != "" {
		m, err := strconv.Atoi(v)
		if err != nil {
			return sc, fmt.Errorf("wireguard: invalid %s %q", OptServerMTU, v)
		}
		sc.MTU = m
	}
	if v := opts[OptServerTUN]; v != "" {
		sc.TUNName = v
	}
	if v := opts[OptServerShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return sc, fmt.Errorf("wireguard: invalid %s %q", OptServerShape, v)
		}
		sc.Shape = n
	}
	if v := opts[OptServerCookieThreshold]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < -1 {
			return sc, fmt.Errorf("wireguard: invalid %s %q (a rate, or -1 for always)", OptServerCookieThreshold, v)
		}
		if n == 0 {
			// Zero in a config struct means "the default", so an explicit 0
			// here -- "demand a cookie past zero initiations a second" -- is
			// the same as always, and is spelled as always.
			n = -1
		}
		sc.CookieThreshold = n
	}
	if v := opts[OptServerPeerPublicKey]; v != "" {
		sc.Peers = append(sc.Peers, ServerPeer{
			PublicKey:    v,
			PresharedKey: opts[OptServerPeerPresharedKey],
			AllowedIPs:   SplitList(opts[OptServerPeerAllowedIPs]),
		})
	}
	// The management plane appends provisioned clients here as a JSON array; a
	// wg-quick -config file's peers (above) and these merge, so a listener can
	// mix a static file with dynamically provisioned clients.
	if v := opts[OptServerPeers]; v != "" {
		var extra []ServerPeer
		if err := json.Unmarshal([]byte(v), &extra); err != nil {
			return sc, fmt.Errorf("wireguard: invalid %s JSON: %w", OptServerPeers, err)
		}
		sc.Peers = append(sc.Peers, extra...)
	}
	sc.ListenIP = opts[OptServerListenIP]
	sc.Logger = vlog.SlogText(os.Stdout)
	return sc, nil
}

func parseServerOptions(opts map[string]string) (client.Server, error) {
	sc, err := ServerConfigFromOptions(opts)
	if err != nil {
		return nil, err
	}
	return NewServer(sc)
}

// ServerConfigFromFile builds a ServerConfig from a parsed wg-quick file: the
// [Interface] is the server, and each [Peer] is a client. It is how the CLI
// turns `-config wg0.conf` into a server.
func ServerConfigFromFile(cfg *Config) (ServerConfig, error) {
	if len(cfg.Address) == 0 {
		return ServerConfig{}, fmt.Errorf("%s is required", OptAddress)
	}
	// wg-quick's Address line is a list, and a dual-stack interface writes both
	// families on it. Taking Address[0] read a v4-then-v6 config as IPv4-only
	// and a v6-then-v4 one as a broken IPv4 server, so the family decides which
	// field it lands in rather than the order.
	v4, v6, err := splitAddressFamilies(cfg.Address)
	if err != nil {
		return ServerConfig{}, err
	}
	sc := ServerConfig{
		PrivateKey: cfg.PrivateKey,
		ListenPort: cfg.ListenPort,
		Address:    v4,
		Address6:   v6,
		MTU:        cfg.MTU,
		TUNName:    cfg.TUNName,
		Logger:     cfg.Logger,
	}
	for _, p := range cfg.Peers {
		sc.Peers = append(sc.Peers, ServerPeer{
			PublicKey:    p.PublicKey,
			PresharedKey: p.PresharedKey,
			AllowedIPs:   p.AllowedIPs,
		})
	}
	return sc, nil
}

// Server is a running WireGuard responder: a UDP socket, a TUN device, the
// transport pump, and the set of peers it accepts. It owns the TUN but does not
// configure host networking — Gateway and Network report what a caller needs to
// do that itself. The engine is internal/wireguard's; this is its public name.
type Server struct{ *iwg.Server }

// Server implements client.AbandonableServer and client.DualStackServer, both
// discovered by type assertion at their one call site, so a method lost in the
// embedding would compile fine and silently stop being found. Asserted here on
// the type the registry hands out, which is the one that matters.
var (
	_ client.AbandonableServer = (*Server)(nil)
	_ client.DualStackServer   = (*Server)(nil)
)

// NewServer builds a server from cfg: it decodes keys, parses the address and
// peers, and opens the TUN device. It does not bind the socket until
// ListenAndServe. Opening a TUN device requires CAP_NET_ADMIN.
func NewServer(cfg ServerConfig) (*Server, error) {
	priv, err := decodeKey(cfg.PrivateKey, OptPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf("wireguard: %s %d out of range", OptListenPort, cfg.ListenPort)
	}
	if cfg.Address == "" {
		return nil, fmt.Errorf("wireguard: %s is required", OptAddress)
	}
	gwAddr, network, err := parseCIDR(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %s: %w", OptAddress, err)
	}
	if gwAddr.To4() == nil {
		return nil, fmt.Errorf("wireguard: %s %q is IPv6; the v6 half goes in %s",
			OptServerAddress, cfg.Address, OptServerAddress6)
	}
	var gw6 netip.Addr
	var net6 netip.Prefix
	if cfg.Address6 != "" {
		gw6, net6, err = parsePrefix6(cfg.Address6)
		if err != nil {
			return nil, fmt.Errorf("wireguard: %s: %w", OptServerAddress6, err)
		}
	}
	if len(cfg.Peers) == 0 {
		return nil, errors.New("wireguard: a server needs at least one peer")
	}
	peers, err := resolvePeers(cfg.Peers)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	srv, err := iwg.NewServer(iwg.ServerConfig{
		PrivateKey:      priv,
		ListenAddr:      &net.UDPAddr{IP: net.ParseIP(cfg.ListenIP), Port: cfg.ListenPort},
		MTU:             mtu,
		Shape:           cfg.Shape,
		Gateway:         gwAddr,
		Network:         network,
		Gateway6:        gw6,
		Network6:        net6,
		Peers:           peers,
		TUNName:         cfg.TUNName,
		Obfuscation:     cfg.Obfuscation,
		CookieThreshold: cfg.CookieThreshold,
		Logger:          vlog.From(cfg.Logger),
	})
	if err != nil {
		return nil, err
	}
	return &Server{srv}, nil
}

// resolvePeers decodes the configured peers, refusing a duplicate key here,
// where the error can name the option that carried it.
func resolvePeers(cfgPeers []ServerPeer) ([]iwg.Peer, error) {
	peers := make([]iwg.Peer, 0, len(cfgPeers))
	seen := make(map[[32]byte]bool, len(cfgPeers))
	for i, p := range cfgPeers {
		pub, err := decodeKey(p.PublicKey, OptPublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %d: %w", i, err)
		}
		if seen[pub] {
			return nil, fmt.Errorf("peer %d: duplicate %s", i, OptPublicKey)
		}
		seen[pub] = true
		sp := iwg.Peer{PublicKey: pub}
		if p.PresharedKey != "" {
			psk, err := decodeKey(p.PresharedKey, OptPresharedKey)
			if err != nil {
				return nil, fmt.Errorf("peer %d: %w", i, err)
			}
			sp.PresharedKey = psk
		}
		if len(p.AllowedIPs) == 0 {
			return nil, fmt.Errorf("peer %d: %s is required", i, OptAllowedIPs)
		}
		sp.AllowedIPs, err = prefixes(p.AllowedIPs)
		if err != nil {
			return nil, fmt.Errorf("peer %d: %s: %w", i, OptAllowedIPs, err)
		}
		peers = append(peers, sp)
	}
	return peers, nil
}

// parseCIDR splits "10.10.0.1/24" into the host address and its network.
func parseCIDR(s string) (net.IP, *net.IPNet, error) {
	ip, network, err := net.ParseCIDR(s)
	if err != nil {
		return nil, nil, err
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip, network, nil
}

// splitAddressFamilies sorts a wg-quick Address list into its first IPv4 and
// first IPv6 entry. A second address of either family is an error rather than a
// silent choice: the server installs exactly one address per family, and
// quietly ignoring the rest is how a config that looks right stops working.
func splitAddressFamilies(addrs []string) (v4, v6 string, err error) {
	for _, a := range addrs {
		ip, _, perr := net.ParseCIDR(a)
		if perr != nil {
			return "", "", fmt.Errorf("%s %q: %w", OptAddress, a, perr)
		}
		slot := &v6
		if ip.To4() != nil {
			slot = &v4
		}
		if *slot != "" {
			return "", "", fmt.Errorf("%s names two addresses of the same family (%q and %q); "+
				"a server installs one per family", OptAddress, *slot, a)
		}
		*slot = a
	}
	if v4 == "" {
		return "", "", fmt.Errorf("%s names no IPv4 address", OptAddress)
	}
	return v4, v6, nil
}

// parsePrefix6 parses a v6 CIDR into the host address and its prefix. It
// rejects a v4 address, which would otherwise produce a v4-mapped netip.Addr
// that hostnet would hand to `ip -6`.
func parsePrefix6(s string) (netip.Addr, netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	if !p.Addr().Is6() || p.Addr().Is4In6() {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("%q is not an IPv6 address", s)
	}
	return p.Addr(), p.Masked(), nil
}
