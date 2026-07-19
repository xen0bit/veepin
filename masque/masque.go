// Package masque is the public entry point to MASQUE CONNECT-IP (RFC 9484):
// IP-over-HTTP/3, the first modern tunnel in veepin and the only one that needs
// a golang.org/x module beyond x/crypto — golang.org/x/net for QUIC.
//
// # Capsule-mode transport, and what it costs
//
// MASQUE carries inner packets as HTTP Datagrams, which normally ride on QUIC
// DATAGRAM frames for an unreliable, head-of-line-free data path. x/net/quic
// does not implement QUIC DATAGRAM frames, so veepin runs in *capsule mode*: the
// packets are DATAGRAM capsules on the CONNECT request stream, which is reliable
// and ordered. That is spec-compliant (RFC 9297) and interoperates with any
// proxy that supports the fallback, but it reintroduces head-of-line blocking on
// a lossy path. It is the honest boundary of this implementation, documented in
// the README alongside the others; when x/net/quic grows datagram support the
// data path can switch transports with nothing above it changing.
//
// # Structure
//
// The shape is the one every veepin client follows: Dial completes the handshake
// and returns a client.Result the caller applies, installing no addresses or
// routes itself. The internal engine lives in internal/masque, with the HTTP/3
// substrate under internal/masque/http3.
package masque

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	imasque "github.com/xen0bit/veepin/internal/masque"
	"golang.org/x/net/quic"
)

func init() { client.Register("masque", parseOptions) }

// defaultPort is the UDP port a CONNECT-IP proxy listens on. HTTP/3 is HTTPS, so
// this is 443 — the same port, over UDP.
const defaultPort = 443

// defaultMTU is the inner MTU a MASQUE client uses. Unlike the UDP protocols it
// cannot be derived exactly: the carrier is QUIC, whose per-packet overhead
// varies with the header form and the AEAD, and on top of that sit the HTTP/3
// DATA frame, the capsule header and the datagram context ID. 1350 sits under
// the worst case on a 1500-octet path with margin to spare, which is the
// conventional figure MASQUE deployments use.
const defaultMTU = 1350

// Option keys accepted by client.Dial(ctx, "masque", opts).
const (
	OptServer    = "server"    // proxy host or IP (required)
	OptPort      = "port"      // proxy UDP port (default 443)
	OptAuthority = "authority" // :authority to present (default: server host)
	OptServerCA  = "ca"        // PEM bundle to verify the proxy against
	OptInsecure  = "insecure"  // "true" to skip proxy certificate verification
	OptTUN       = "tun"       // TUN interface name
)

// Config is the parsed form of the options above.
type Config struct {
	// Server is the proxy host or IP.
	Server string
	// Port is the proxy's UDP port; zero means defaultPort.
	Port int
	// Authority is the :authority the request presents; empty uses Server.
	Authority string
	// RootCAs verifies the proxy certificate; nil uses the system roots.
	RootCAs *x509.CertPool
	// Insecure skips proxy certificate verification. It is for testing against a
	// self-signed proxy and says so, loudly, in the logs.
	Insecure bool
	// TUNName is the interface to open; empty picks the next free one.
	TUNName string
	// Logger receives progress messages; nil discards them.
	Logger *log.Logger
}

// Session is a running MASQUE client.
type Session struct {
	client *imasque.Client
}

// Dial completes the CONNECT-IP handshake and starts the data path. Like every
// protocol here it installs no addresses, routes or DNS; it returns the
// client.Result and the caller applies it.
func Dial(ctx context.Context, cfg Config) (*Session, client.Result, error) {
	if cfg.Server == "" {
		return nil, client.Result{}, fmt.Errorf("masque: server is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	port := cfg.Port
	if port == 0 {
		port = defaultPort
	}
	serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.Server, strconv.Itoa(port)))
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("masque: resolving %s: %w", cfg.Server, err)
	}

	serverName := cfg.Authority
	if serverName == "" {
		serverName = cfg.Server
	}
	if cfg.Insecure {
		logger.Printf("masque: WARNING: proxy certificate verification disabled (insecure)")
	}
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
		RootCAs:            cfg.RootCAs,
		InsecureSkipVerify: cfg.Insecure,
	}

	end, err := quic.Listen("udp", ":0", &quic.Config{TLSConfig: tlsConfig})
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("masque: opening QUIC endpoint: %w", err)
	}
	qc, err := end.Dial(ctx, "udp", serverAddr.String(), &quic.Config{TLSConfig: tlsConfig})
	if err != nil {
		_ = end.Close(context.Background())
		return nil, client.Result{}, fmt.Errorf("masque: dialing proxy: %w", err)
	}

	authority := cfg.Authority
	if authority == "" {
		authority = cfg.Server
	}
	h3conn, rs, assigned, routes, err := imasque.Connect(ctx, qc, imasque.ClientConfig{
		Authority: authority,
		Logger:    logger,
	})
	if err != nil {
		_ = end.Close(context.Background())
		return nil, client.Result{}, err
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		_ = end.Close(context.Background())
		return nil, client.Result{}, fmt.Errorf("masque: opening TUN: %w", err)
	}

	c := imasque.StartClient(h3conn, rs, tun, assigned, routes, logger)

	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: net.IP(assigned.Addr().AsSlice()),
		Netmask:    net.IP(net.CIDRMask(assigned.Bits(), assigned.Addr().BitLen())),
		// Gateway is the proxy's OUTER address, so the caller pins a host route
		// to it and encapsulated QUIC packets do not recurse into the tunnel.
		Gateway: serverAddr.IP,
		MTU:     defaultMTU,
	}
	logger.Printf("masque: tunnel up, assigned %s", assigned)
	return &Session{client: c}, res, nil
}

// Wait blocks until the session ends or ctx is cancelled.
func (s *Session) Wait(ctx context.Context) error { return s.client.Wait(ctx) }

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
		Server:    opts[OptServer],
		Authority: opts[OptAuthority],
		TUNName:   opts[OptTUN],
		Insecure:  opts[OptInsecure] == "true",
		Logger:    log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("masque: server is required")
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("masque: invalid port %q", v)
		}
		cfg.Port = p
	}
	if path := opts[OptServerCA]; path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("masque: reading CA %q: %w", path, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("masque: CA %q contains no certificates", path)
		}
		cfg.RootCAs = pool
	}
	return dialer{cfg}, nil
}
