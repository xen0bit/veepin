// Package pulse is the public entry point to the Ivanti Connect Secure VPN
// (formerly Pulse Connect Secure, formerly Juniper): IF-T/TLS framing over TLS,
// EAP inside it for authentication, and either RFC 4303 ESP over UDP or that
// same connection for data.
//
// It is the last of the big enterprise remote-access protocols veepin speaks,
// and architecturally the odd one out: its authentication is EAP over a stream
// transport, nested four layers deep, and its ESP keys arrive in a fixed-layout
// binary packet with one field — the SPI — in little-endian.
//
// The shape is the one every veepin client follows: Dial authenticates, learns
// the assigned address and routes, and returns a client.Result the caller
// applies — it installs no addresses or routes itself.
package pulse

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/pqpolicy"
	ipulse "github.com/xen0bit/veepin/internal/pulse"
	"github.com/xen0bit/veepin/internal/vlog"
)

func init() { client.Register("pulse", parseOptions) }

// defaultPort is the HTTPS port an Ivanti gateway listens on.
const defaultPort = 443

// Option keys accepted by client.Dial(ctx, "pulse", opts).
const (
	OptServer   = "server"   // gateway host or IP (required)
	OptPort     = "port"     // HTTPS port (default 443)
	OptPath     = "path"     // request path the upgrade is sent to (default "/")
	OptUser     = "user"     // username (required)
	OptPassword = "password" // password (required)
	OptCA       = "ca"       // PEM bundle to verify the gateway
	OptInsecure = "insecure" // "true" to skip certificate verification
	OptNoESP    = "no-esp"   // "true" to stay on the IF-T/TLS data path
	OptTUN      = "tun"      // TUN interface name
	OptShape    = "shape"    // per-flow outbound shaping budget in bytes (0 = off)
)

// Config is the parsed client configuration.
type Config struct {
	Server   string
	Port     int
	Path     string
	Username string
	Password string
	RootCAs  *x509.CertPool
	Insecure bool
	// NoESP keeps the data path on the IF-T/TLS connection even where the
	// gateway hands out ESP keys.
	NoESP bool
	// Hostname names this host in the gateway's logs.
	Hostname string
	TUNName  string
	// Shape enables outbound traffic shaping: how much padded output each inner
	// flow is given before shaping stops for that flow. Zero disables it.
	Shape  int
	Logger *slog.Logger

	// PostQuantumOnly requires a post-quantum key exchange and ML-DSA
	// authentication, refusing anything less rather than negotiating down. It is
	// what the pq-pulse registry name sets; see internal/pqpolicy for the contract
	// and doc/pq-variants-plan.md for why it is a name rather than a flag.
	PostQuantumOnly bool
}

// Session is a running Pulse client.
type Session struct {
	client *ipulse.Client
	logger *vlog.Logger
}

// Dial authenticates, brings a data path up, and returns what the caller must
// apply. It installs no addresses or routes.
func Dial(ctx context.Context, cfg Config) (*Session, client.Result, error) {
	if cfg.Server == "" || cfg.Username == "" {
		return nil, client.Result{}, fmt.Errorf("pulse: server and user are required")
	}
	logger := vlog.From(cfg.Logger)
	port := cfg.Port
	if port == 0 {
		port = defaultPort
	}
	host := net.JoinHostPort(cfg.Server, strconv.Itoa(port))
	hostname := cfg.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	path := cfg.Path
	if path == "" {
		path = "/"
	}

	tlsCfg := &tls.Config{
		ServerName:         cfg.Server,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            cfg.RootCAs,
		InsecureSkipVerify: cfg.Insecure, //nolint:gosec // guarded by the explicit option below
	}
	if cfg.PostQuantumOnly {
		pqpolicy.HardenTLS(tlsCfg)
	}
	if cfg.Insecure {
		logger.Printf("pulse: WARNING: gateway certificate verification disabled (insecure)")
	}

	dialer := &tls.Dialer{Config: tlsCfg}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("pulse: dialing the gateway: %w", err)
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		_ = conn.Close()
		return nil, client.Result{}, fmt.Errorf("pulse: opening TUN: %w", err)
	}

	c, err := ipulse.Connect(conn, host, path, cfg.Username, cfg.Password, hostname,
		tun, logger, !cfg.NoESP, cfg.Shape)
	if err != nil {
		_ = conn.Close()
		_ = tun.Close()
		return nil, client.Result{}, client.WrapAuth(err, ipulse.ErrAuth)
	}

	gwCfg := c.AssignedConfig()
	mtu := gwCfg.MTU
	if mtu <= 0 {
		mtu = client.DefaultTunnelMTU
	}
	// The gateway's split-include networks are reported rather than returned:
	// client.Result has no field for per-destination routes, so a caller that
	// wants split tunnelling installs them itself and the safe default —
	// everything through the tunnel — is what a bare Result produces.
	for _, r := range gwCfg.Routes {
		verb := "routing"
		if r.Exclude {
			verb = "excluding"
		}
		logger.Printf("pulse: gateway suggests %s %s", verb, r.Net)
	}

	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: gwCfg.Address,
		Netmask:    netmaskOf(gwCfg),
		// Gateway is the server's OUTER address, so the caller pins a host route
		// to it and the tunnel's own packets do not recurse into it.
		Gateway: outerIP(conn),
		DNS:     gwCfg.DNS,
		MTU:     mtu,
	}
	carrier := "IF-T/TLS"
	if c.OverESP() {
		carrier = "ESP"
	}
	logger.Printf("pulse: tunnel up over %s, assigned %s", carrier, gwCfg.Address)
	return &Session{client: c, logger: logger}, res, nil
}

// netmaskOf is the assigned address's mask: the gateway's, or a host mask where
// it sent none — which is what this protocol means by an address with no mask.
func netmaskOf(cfg ipulse.Config) net.IP {
	if cfg.Netmask != nil {
		return cfg.Netmask
	}
	return net.IP{255, 255, 255, 255}
}

// outerIP is the gateway's address on the underlying network, read off the
// connection that reached it — which is the address that actually carried the
// traffic, whatever the name resolved to.
func outerIP(conn net.Conn) net.IP {
	if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP
	}
	return nil
}

// Wait blocks until the session ends or ctx is cancelled.
func (s *Session) Wait(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- s.client.Wait() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// Close tears the session down, telling the gateway on the way out so the
// address it assigned comes back at once rather than at the session timeout.
func (s *Session) Close() error { return s.client.Close() }

// Probe implements client.Prober.
func (s *Session) Probe(ctx context.Context) error { return s.client.Probe(ctx) }

// dialer adapts Config to the client registry.
type dialer struct{ cfg Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, d.cfg)
}

// parseOptions turns registry options into a Config.
func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := Config{
		PostQuantumOnly: pqpolicy.Requested(opts),
		Server:          opts[OptServer],
		Path:            opts[OptPath],
		Username:        opts[OptUser],
		Password:        opts[OptPassword],
		Insecure:        opts[OptInsecure] == "true",
		NoESP:           opts[OptNoESP] == "true",
		TUNName:         opts[OptTUN],
		Logger:          slog.New(vlog.NewTextHandler(os.Stdout, slog.LevelInfo)),
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("pulse: server is required")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("pulse: user is required")
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("pulse: invalid port %q", v)
		}
		cfg.Port = p
	}
	if v := opts[OptShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("pulse: invalid shape %q", v)
		}
		cfg.Shape = n
	}
	if path := opts[OptCA]; path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("pulse: reading CA %q: %w", path, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("pulse: CA %q contains no certificates", path)
		}
		cfg.RootCAs = pool
	}
	return dialer{cfg}, nil
}
