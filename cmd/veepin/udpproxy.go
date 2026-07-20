package main

// The `udp-proxy` subcommand: forward a local UDP socket to a remote host:port
// through a MASQUE proxy, using CONNECT-UDP (RFC 9298).
//
// Unlike `connect`, this is not a VPN and touches no routing or interfaces: it
// binds one local UDP address and relays its datagrams. It is the client half of
// what `veepin serve masque` already accepts alongside CONNECT-IP -- useful for
// tunnelling DNS, QUIC, or any single UDP service through the proxy.

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/xen0bit/veepin/masque"
)

func runUDPProxy(args []string) error {
	fs := flag.NewFlagSet("udp-proxy", flag.ContinueOnError)
	var (
		server    = fs.String("server", "", "MASQUE proxy host or IP (required)")
		port      = fs.Int("port", 0, "proxy UDP port (default 443)")
		authority = fs.String("authority", "", "HTTP :authority to present (default: server host)")
		ca        = fs.String("ca", "", "PEM bundle to verify the proxy against")
		insecure  = fs.Bool("insecure", false, "skip proxy certificate verification (self-signed proxies)")
		listen    = fs.String("listen", "", "local UDP address to bind, e.g. 127.0.0.1:5353 (required)")
		target    = fs.String("target", "", "remote UDP target host:port to proxy to (required)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *listen == "" || *target == "" {
		return fmt.Errorf("udp-proxy: -server, -listen and -target are all required")
	}

	host, portStr, err := net.SplitHostPort(*target)
	if err != nil {
		return fmt.Errorf("udp-proxy: -target %q: %w", *target, err)
	}
	targetPort, err := strconv.Atoi(portStr)
	if err != nil || targetPort < 1 || targetPort > 65535 {
		return fmt.Errorf("udp-proxy: -target port %q is not valid", portStr)
	}

	cfg := masque.UDPProxyConfig{
		Server:     *server,
		Port:       *port,
		Authority:  *authority,
		Insecure:   *insecure,
		Listen:     *listen,
		TargetHost: host,
		TargetPort: targetPort,
		Logger:     log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			return fmt.Errorf("udp-proxy: reading CA %q: %w", *ca, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("udp-proxy: CA %q contains no certificates", *ca)
		}
		cfg.RootCAs = pool
	}

	proxy, err := masque.NewUDPProxy(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer proxy.Close()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		_ = proxy.Close()
	}()

	fmt.Printf("forwarding %s -> %s via MASQUE proxy %s\n", *listen, *target, *server)
	if err := proxy.ListenAndServe(); err != nil {
		return fmt.Errorf("udp-proxy: %w", err)
	}
	return nil
}
