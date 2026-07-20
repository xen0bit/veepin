package masque

// The public CONNECT-UDP forwarder.
//
// Unlike Dial/NewServer, this does not join the client registry and returns no
// client.Result: CONNECT-UDP is a per-flow UDP proxy, not a full-IP VPN, so it
// has a shape of its own. UDPProxy binds a local UDP socket and forwards its
// datagrams to one target through a MASQUE proxy over HTTP/3.
//
// The server side is the same veepin MASQUE proxy that serves CONNECT-IP: it
// dispatches on the request's :protocol, so `veepin serve masque` already
// accepts these flows and no separate server exists here.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"

	imasque "github.com/xen0bit/veepin/internal/masque"
	"golang.org/x/net/quic"
)

// UDPProxyConfig configures a CONNECT-UDP forwarder.
type UDPProxyConfig struct {
	// Server is the MASQUE proxy host or IP.
	Server string
	// Port is the proxy's UDP port; zero means defaultPort (443).
	Port int
	// Authority is the :authority the request presents; empty uses Server.
	Authority string
	// RootCAs verifies the proxy certificate; nil uses the system roots.
	RootCAs *x509.CertPool
	// Insecure skips proxy certificate verification (testing only).
	Insecure bool

	// Listen is the local UDP address to bind, e.g. "127.0.0.1:5353".
	Listen string
	// TargetHost and TargetPort are what the proxy is asked to reach.
	TargetHost string
	TargetPort int

	// Logger receives progress messages; nil discards them.
	Logger *log.Logger
}

// UDPProxy is a running CONNECT-UDP forwarder.
type UDPProxy struct {
	forwarder *imasque.UDPForwarder
	local     *net.UDPConn
}

// NewUDPProxy dials the MASQUE proxy, binds the local socket, and prepares to
// forward. It does not block; ListenAndServe does.
func NewUDPProxy(ctx context.Context, cfg UDPProxyConfig) (*UDPProxy, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("masque: proxy server is required")
	}
	if cfg.Listen == "" {
		return nil, fmt.Errorf("masque: a local listen address is required")
	}
	if cfg.TargetHost == "" || cfg.TargetPort <= 0 {
		return nil, fmt.Errorf("masque: a target host and port are required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	port := cfg.Port
	if port == 0 {
		port = defaultPort
	}
	proxyAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.Server, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("masque: resolving proxy %s: %w", cfg.Server, err)
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
		return nil, fmt.Errorf("masque: opening QUIC endpoint: %w", err)
	}
	qc, err := end.Dial(ctx, "udp", proxyAddr.String(), &quic.Config{TLSConfig: tlsConfig})
	if err != nil {
		_ = end.Close(context.Background())
		return nil, fmt.Errorf("masque: dialing proxy: %w", err)
	}

	local, err := net.ListenUDP("udp", udpAddr(cfg.Listen))
	if err != nil {
		_ = end.Close(context.Background())
		return nil, fmt.Errorf("masque: binding %s: %w", cfg.Listen, err)
	}

	authority := cfg.Authority
	if authority == "" {
		authority = cfg.Server
	}
	fwd, err := imasque.NewUDPForwarderOverQUIC(ctx, qc, local, cfg.TargetHost, cfg.TargetPort, authority, logger)
	if err != nil {
		_ = local.Close()
		_ = end.Close(context.Background())
		return nil, fmt.Errorf("masque: http/3 setup: %w", err)
	}
	logger.Printf("masque: forwarding %s -> %s:%d via %s:%d", local.LocalAddr(), cfg.TargetHost, cfg.TargetPort, cfg.Server, port)
	return &UDPProxy{forwarder: fwd, local: local}, nil
}

// LocalAddr is the bound local socket address, useful when Listen used port 0.
func (p *UDPProxy) LocalAddr() net.Addr { return p.local.LocalAddr() }

// ListenAndServe forwards datagrams until Close. It blocks.
func (p *UDPProxy) ListenAndServe() error { return p.forwarder.Run() }

// Close stops forwarding and tears down every flow and the proxy connection.
func (p *UDPProxy) Close() error { return p.forwarder.Close() }

// udpAddr resolves a listen string to a *net.UDPAddr, falling back to a wildcard
// address the ListenUDP call will report on.
func udpAddr(listen string) *net.UDPAddr {
	if a, err := net.ResolveUDPAddr("udp", listen); err == nil {
		return a
	}
	return &net.UDPAddr{}
}
