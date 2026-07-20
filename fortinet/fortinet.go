// Package fortinet is the public entry point to the Fortinet FortiOS SSL VPN:
// an HTTPS login and config exchange, then a PPP-over-TLS data tunnel. It is the
// second enterprise SSL VPN in veepin next to AnyConnect, and reuses the most —
// internal/ppp for the link and the ordinary TLS stack for the carrier.
//
// The shape is the one every veepin client follows: Dial authenticates, learns
// the assigned address and routes, and returns a client.Result the caller
// applies — it installs no addresses or routes itself.
package fortinet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	ifortinet "github.com/xen0bit/veepin/internal/fortinet"
)

func init() { client.Register("fortinet", parseOptions) }

// defaultPort is the FortiOS SSL VPN HTTPS port.
const defaultPort = 443

// defaultMaskBits is the netmask the client assumes for its assigned address.
// FortiOS carries no netmask in the config, and the assigned address sits in the
// same subnet the server's pool draws from, so a /24 puts the gateway on-link —
// the shape every other protocol here hands back. -no-route or a full-tunnel
// default route override it when a caller wants different routing.
const defaultMaskBits = 24

// Option keys accepted by client.Dial(ctx, "fortinet", opts).
const (
	OptServer   = "server"   // proxy host or IP (required)
	OptPort     = "port"     // HTTPS port (default 443)
	OptUser     = "user"     // username (required)
	OptPassword = "password" // password (required)
	OptRealm    = "realm"    // FortiOS realm (optional)
	OptCA       = "ca"       // PEM bundle to verify the server
	OptInsecure = "insecure" // "true" to skip certificate verification
	OptTUN      = "tun"      // TUN interface name
)

// Config is the parsed client configuration.
type Config struct {
	Server   string
	Port     int
	Username string
	Password string
	Realm    string
	RootCAs  *x509.CertPool
	Insecure bool
	TUNName  string
	Logger   *log.Logger
}

// Session is a running Fortinet client.
type Session struct {
	client *ifortinet.Client
}

// Dial authenticates, opens the tunnel, and starts the data path.
func Dial(ctx context.Context, cfg Config) (*Session, client.Result, error) {
	if cfg.Server == "" || cfg.Username == "" {
		return nil, client.Result{}, fmt.Errorf("fortinet: server and user are required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	port := cfg.Port
	if port == 0 {
		port = defaultPort
	}
	host := net.JoinHostPort(cfg.Server, strconv.Itoa(port))
	base := "https://" + host

	tlsConfig := &tls.Config{
		ServerName:         cfg.Server,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            cfg.RootCAs,
		InsecureSkipVerify: cfg.Insecure,
	}
	if cfg.Insecure {
		logger.Printf("fortinet: WARNING: server certificate verification disabled (insecure)")
	}

	// Control plane: a cookie-jar client so the SVPNCOOKIE flows to the config
	// fetch.
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	fcfg, cookie, err := ifortinet.Login(hc, base, cfg.Username, cfg.Password, cfg.Realm)
	if err != nil {
		return nil, client.Result{}, err
	}
	if fcfg.AssignedIP == nil {
		return nil, client.Result{}, fmt.Errorf("fortinet: server assigned no address")
	}

	// Data plane: a fresh TLS connection carrying the tunnel GET.
	conn, err := tls.Dial("tcp", host, tlsConfig)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("fortinet: dialing tunnel: %w", err)
	}
	if _, err := conn.Write(ifortinet.TunnelRequest(host, cookie)); err != nil {
		_ = conn.Close()
		return nil, client.Result{}, fmt.Errorf("fortinet: sending tunnel request: %w", err)
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		_ = conn.Close()
		return nil, client.Result{}, fmt.Errorf("fortinet: opening TUN: %w", err)
	}

	c, err := ifortinet.RunClient(conn, fcfg, tun, logger)
	if err != nil {
		_ = tun.Close()
		return nil, client.Result{}, err
	}

	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: fcfg.AssignedIP,
		Netmask:    net.IP(net.CIDRMask(defaultMaskBits, 32)),
		// Gateway is the server's OUTER address, so the caller pins a host route to
		// it and the tunnel's own TLS packets do not recurse into it.
		Gateway: outerIP(cfg.Server),
		DNS:     fcfg.DNS,
		MTU:     client.DefaultTunnelMTU,
	}
	logger.Printf("fortinet: tunnel up, assigned %s", fcfg.AssignedIP)
	return &Session{client: c}, res, nil
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

// Close tears the session down.
func (s *Session) Close() error { return s.client.Close() }

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
		Realm:    opts[OptRealm],
		Insecure: opts[OptInsecure] == "true",
		TUNName:  opts[OptTUN],
		Logger:   log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("fortinet: server is required")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("fortinet: user is required")
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("fortinet: invalid port %q", v)
		}
		cfg.Port = p
	}
	if path := opts[OptCA]; path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("fortinet: reading CA %q: %w", path, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("fortinet: CA %q contains no certificates", path)
		}
		cfg.RootCAs = pool
	}
	return dialer{cfg}, nil
}

// outerIP resolves the server host to an IP for the host route. A resolution
// failure yields nil, which means "install no host route" — acceptable, since
// the name will resolve the same way for the route as for the dial.
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
