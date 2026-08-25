// Package gp is the public entry point to the Palo Alto Networks GlobalProtect
// SSL VPN: an HTTPS login and configuration exchange, then either an ESP data
// path or a framed layer-3 tunnel over TLS.
//
// It is the third enterprise SSL VPN in veepin, next to AnyConnect and Fortinet,
// and the one that reuses the IPsec machinery rather than the PPP machinery: the
// gateway hands out ESP keys and SPIs inside the configuration document, so
// internal/ikev2/esp carries the traffic with no key exchange in front of it.
//
// The shape is the one every veepin client follows: Dial authenticates, learns
// the assigned address and routes, and returns a client.Result the caller
// applies — it installs no addresses or routes itself.
package gp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	igp "github.com/xen0bit/veepin/internal/gp"
	"github.com/xen0bit/veepin/internal/vlog"
)

func init() { client.Register("gp", parseOptions) }

// defaultPort is the GlobalProtect HTTPS port.
const defaultPort = 443

// defaultMaskBits is the netmask assumed when a gateway sends none.
const defaultMaskBits = 24

// Option keys accepted by client.Dial(ctx, "gp", opts).
const (
	OptServer   = "server"   // gateway host or IP (required)
	OptPort     = "port"     // HTTPS port (default 443)
	OptUser     = "user"     // username (required)
	OptPassword = "password" // password (required)
	OptCA       = "ca"       // PEM bundle to verify the gateway
	OptInsecure = "insecure" // "true" to skip certificate verification
	OptNoESP    = "no-esp"   // "true" to stay on the SSL tunnel even where ESP is offered
	OptTUN      = "tun"      // TUN interface name
	OptShape    = "shape"    // per-flow outbound shaping budget in bytes (0 = off)
)

// Config is the parsed client configuration.
type Config struct {
	Server   string
	Port     int
	Username string
	Password string
	RootCAs  *x509.CertPool
	Insecure bool
	// NoESP keeps the data path on the SSL tunnel even where the gateway hands
	// out ESP keys.
	NoESP bool
	// Computer names this host in the gateway's logs.
	Computer string
	TUNName  string
	// Shape enables outbound traffic shaping: how much padded output each inner
	// flow is given before shaping stops for that flow. Zero disables it.
	Shape  int
	Logger *slog.Logger
}

// Session is a running GlobalProtect client.
type Session struct {
	client   *igp.Client
	hc       *http.Client
	base     string
	info     igp.LoginInfo
	computer string
	logger   *vlog.Logger
}

// Dial authenticates, brings a data path up, and returns what the caller must
// apply. It installs no addresses or routes.
func Dial(ctx context.Context, cfg Config) (*Session, client.Result, error) {
	if cfg.Server == "" || cfg.Username == "" {
		return nil, client.Result{}, fmt.Errorf("gp: server and user are required")
	}
	logger := vlog.From(cfg.Logger)
	port := cfg.Port
	if port == 0 {
		port = defaultPort
	}
	host := net.JoinHostPort(cfg.Server, strconv.Itoa(port))
	base := "https://" + host
	computer := cfg.Computer
	if computer == "" {
		computer, _ = os.Hostname()
	}

	tlsConfig := &tls.Config{
		ServerName:         cfg.Server,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            cfg.RootCAs,
		InsecureSkipVerify: cfg.Insecure,
	}
	if cfg.Insecure {
		logger.Printf("gp: WARNING: gateway certificate verification disabled (insecure)")
	}

	// A cookie jar is not what authorises this protocol — the cookie travels in
	// the form and the query string — but a gateway may still set session cookies
	// it expects back, so one is kept.
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	info, gwCfg, err := igp.Login(hc, base, cfg.Username, cfg.Password, computer)
	if err != nil {
		// ErrSAML is deliberately NOT folded into ErrAuth. The credentials were
		// never judged: the gateway wants a browser flow this client does not
		// do, and reporting that as a rejected password makes NetworkManager
		// re-prompt for a password that cannot ever work. It is permanent for a
		// different reason, which is why it is a sentinel of its own.
		return nil, client.Result{}, client.WrapAuth(err, igp.ErrAuth)
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("gp: opening TUN: %w", err)
	}

	mtu := gwCfg.MTU
	if mtu <= 0 {
		mtu = client.DefaultTunnelMTU
	}
	c, err := dialDataPath(host, info, gwCfg, tlsConfig, tun, logger, !cfg.NoESP, cfg.Shape, mtu)
	if err != nil {
		_ = tun.Close()
		return nil, client.Result{}, err
	}

	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: gwCfg.AssignedIP,
		Netmask:    netmaskOf(gwCfg),
		// Gateway is the server's OUTER address, so the caller pins a host route
		// to it and the tunnel's own packets do not recurse into it.
		Gateway: outerIP(cfg.Server),
		DNS:     gwCfg.DNS,
		MTU:     mtu,
	}
	carrier := "TLS"
	if c.OverESP() {
		carrier = "ESP"
	}
	logger.Printf("gp: tunnel up over %s, assigned %s", carrier, gwCfg.AssignedIP)
	return &Session{client: c, hc: hc, base: base, info: info, computer: computer, logger: logger}, res, nil
}

// dialDataPath brings up whichever data path the gateway made available, trying
// ESP first where it offered keys.
//
// The order is forced by the protocol, not chosen here: opening the SSL tunnel
// invalidates the SPIs the same configuration handed out, so a client that tried
// the tunnel first would have nothing left to fall back to. Trying ESP first
// costs a few seconds when UDP is blocked and nothing at all when it is not.
func dialDataPath(host string, info igp.LoginInfo, gwCfg igp.Config, tlsConfig *tls.Config,
	tun io.ReadWriteCloser, logger *vlog.Logger, wantESP bool, shape, mtu int,
) (*igp.Client, error) {
	if wantESP && gwCfg.ESP != nil {
		c, err := igp.RunESP(gwCfg, tun, logger, shape, mtu)
		if err == nil {
			return c, nil
		}
		logger.Printf("gp: ESP unavailable (%v), falling back to the SSL tunnel", err)
	}
	return dialSSL(host, info, gwCfg, tlsConfig, tun, logger)
}

// dialSSL opens the framed layer-3 tunnel over a fresh TLS connection.
func dialSSL(host string, info igp.LoginInfo, gwCfg igp.Config, tlsConfig *tls.Config,
	tun io.ReadWriteCloser, logger *vlog.Logger,
) (*igp.Client, error) {
	conn, err := tls.Dial("tcp", host, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("gp: dialing the tunnel: %w", err)
	}
	if _, err := conn.Write(igp.TunnelRequest(host, info)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("gp: sending the tunnel request: %w", err)
	}
	if err := igp.ReadTunnelStart(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	c, err := igp.RunSSL(conn, gwCfg, tun, logger)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

// netmaskOf is the assigned address's mask: the gateway's, or a /24 where it sent
// none. A /24 puts the gateway on-link, which is the shape every other protocol
// here hands back.
func netmaskOf(cfg igp.Config) net.IP {
	if cfg.Netmask != nil {
		return net.IP(cfg.Netmask)
	}
	return net.IP(net.CIDRMask(defaultMaskBits, 32))
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

// Close tears the session down and tells the gateway, so the address it assigned
// comes back at once rather than at the session timeout.
func (s *Session) Close() error {
	err := s.client.Close()
	if lerr := igp.Logout(s.hc, s.base, s.info, s.computer); lerr != nil {
		s.logger.Printf("gp: logout: %v", lerr)
	}
	return err
}

// Probe implements client.Prober, so a gateway that has gone away tears the
// tunnel down instead of blackholing it.
func (s *Session) Probe(ctx context.Context) error { return s.client.Probe(ctx) }

// dialer adapts Config to the client registry.
type dialer struct{ cfg Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, d.cfg)
}

// parseOptions turns registry options into a Config.
func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := Config{
		Server:   opts[OptServer],
		Username: opts[OptUser],
		Password: opts[OptPassword],
		Insecure: opts[OptInsecure] == "true",
		NoESP:    opts[OptNoESP] == "true",
		TUNName:  opts[OptTUN],
		Logger:   slog.New(vlog.NewTextHandler(os.Stdout, slog.LevelInfo)),
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("gp: server is required")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("gp: user is required")
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("gp: invalid port %q", v)
		}
		cfg.Port = p
	}
	if v := opts[OptShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("gp: invalid shape %q", v)
		}
		cfg.Shape = n
	}
	if path := opts[OptCA]; path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("gp: reading CA %q: %w", path, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("gp: CA %q contains no certificates", path)
		}
		cfg.RootCAs = pool
	}
	return dialer{cfg}, nil
}

// outerIP resolves the gateway host to an IP for the host route. A resolution
// failure yields nil, which means "install no host route" — acceptable, since the
// name will resolve the same way for the route as for the dial.
func outerIP(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	if addrs, err := net.LookupIP(host); err == nil {
		for _, a := range addrs {
			if v4 := a.To4(); v4 != nil {
				return v4
			}
		}
	}
	return nil
}
