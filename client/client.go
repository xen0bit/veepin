// Package client is an embeddable ikennkt VPN client. It performs the IKEv2
// handshake (PSK or EAP-MSCHAPv2) and runs the userspace ESP-in-UDP data path
// over a TUN device — but it deliberately does NOT install addresses, routes or
// DNS. The caller is responsible for applying the returned Result to the system
// (the ikev2 command uses internal/dataplane's router; the NetworkManager
// plugin hands the Result to NM, which applies it).
//
// This package is CGO-free and depends only on the standard library and this
// module's own packages, so it is safe to embed in the core binaries and to
// import from the separate nm/ plugin module.
package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xen0bit/ikennkt/internal/dataplane"
	"github.com/xen0bit/ikennkt/internal/ike"
)

// ErrAuth wraps a handshake failure caused by rejected credentials (a wrong PSK
// or EAP password). Dial's returned error satisfies errors.Is(err, ErrAuth),
// letting callers distinguish a bad password from a transport failure.
var ErrAuth = errors.New("authentication failed")

// defaultTunnelMTU is a conservative MTU for the inner interface. ESP-in-UDP
// over a 1500-byte path leaves room for the outer IP+UDP+ESP overhead; 1400 is
// the customary safe value and avoids inner-path fragmentation.
const defaultTunnelMTU = 1400

// Config describes how to reach and authenticate to an IKEv2 server.
type Config struct {
	// Server is the VPN server host or IP (required).
	Server string
	// Port is the server IKE port (default 500).
	Port int

	// PSK authenticates the server, and the client too unless EAP is used
	// (required).
	PSK string
	// LocalID is the identity presented to the server, e.g. "client.example.com"
	// or an IP literal (required).
	LocalID string
	// ServerID, if set, is verified against the server's presented identity.
	ServerID string

	// EAPUser/EAPPassword, if set, switch client authentication to
	// EAP-MSCHAPv2. The server still authenticates itself with the PSK.
	EAPUser     string
	EAPPassword string

	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string

	// Logger receives progress logs; nil discards them.
	Logger *log.Logger
}

// Result is the negotiated configuration a caller must apply to the system for
// the tunnel to carry traffic: the interface, its assigned address, the server
// gateway (for a host route so ESP does not recurse into the tunnel), and DNS.
type Result struct {
	// TUNName is the interface the data path is bound to (e.g. "tun0").
	TUNName string
	// AssignedIP is the internal address the server assigned via config mode.
	AssignedIP net.IP
	// Netmask is the internal address's netmask.
	Netmask net.IP
	// Gateway is the server's outer (public) IP.
	Gateway net.IP
	// DNS holds the internal DNS servers, if the server offered any.
	DNS []net.IP
	// MTU is the recommended inner-interface MTU.
	MTU int
}

// Session is a running tunnel: the IKE SA, the TUN device, and the ESP pump.
// Close tears everything down; Wait blocks until that happens.
type Session struct {
	ike     *ike.Client
	tun     *dataplane.TUN
	pump    *dataplane.Pump
	espConn *net.UDPConn
	logger  *log.Logger

	closeOnce sync.Once
	closeErr  error
	done      chan struct{} // closed when the inbound loop exits (i.e. on Close)
	stopKA    chan struct{} // stops the NAT-keepalive goroutine
}

// Dial performs the handshake, opens the TUN, and starts the ESP data path,
// returning a running Session and the Result the caller must apply. It installs
// no routes or addresses. On error nothing is left running.
//
// The context bounds the setup; once Dial returns, use Session.Wait/Close for
// the tunnel lifetime.
func Dial(ctx context.Context, cfg Config) (*Session, Result, error) {
	if cfg.Server == "" || cfg.PSK == "" || cfg.LocalID == "" {
		return nil, Result{}, fmt.Errorf("client: Server, PSK and LocalID are required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(discard{}, "", 0)
	}

	ikeCfg := ike.ClientConfig{
		ServerHost:  cfg.Server,
		ServerPort:  cfg.Port,
		PSK:         []byte(cfg.PSK),
		LocalID:     parseIdentity(cfg.LocalID),
		EAPUsername: cfg.EAPUser,
		EAPPassword: cfg.EAPPassword,
		Logger:      logger,
	}
	if cfg.ServerID != "" {
		id := parseIdentity(cfg.ServerID)
		ikeCfg.RemoteID = &id
	}

	// 1. Handshake, honoring ctx cancellation. Connect has its own read
	// deadlines, but a caller (e.g. an NM Disconnect mid-handshake) must be able
	// to abort promptly rather than wait them out.
	c := ike.NewClient(ikeCfg)
	res, err := connect(ctx, c)
	if err != nil {
		if errors.Is(err, ike.ErrAuthFailed) {
			return nil, Result{}, fmt.Errorf("client: %w: %v", ErrAuth, err)
		}
		return nil, Result{}, fmt.Errorf("client: connect: %w", err)
	}
	// From here on, any failure must close the IKE client.
	fail := func(err error) (*Session, Result, error) {
		c.Close()
		return nil, Result{}, err
	}

	// 2. TUN.
	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return fail(fmt.Errorf("client: open TUN: %w", err))
	}

	// 3. Data-path tunnel.
	tunnel, err := res.BuildTunnel()
	if err != nil {
		tun.Close()
		return fail(fmt.Errorf("client: build tunnel: %w", err))
	}

	// 4. ESP socket (NAT-T port 4500).
	espConn, err := net.DialUDP("udp", nil, res.ServerAddr)
	if err != nil {
		tun.Close()
		return fail(fmt.Errorf("client: ESP socket: %w", err))
	}

	s := &Session{
		ike:     c,
		tun:     tun,
		pump:    nil,
		espConn: espConn,
		logger:  logger,
		done:    make(chan struct{}),
		stopKA:  make(chan struct{}),
	}

	send := func(esp []byte, _ *net.UDPAddr, _ bool) {
		if _, werr := espConn.Write(esp); werr != nil {
			logger.Printf("client: ESP send error: %v", werr)
		}
	}
	pump := dataplane.NewPump(tun, send, logger)
	pump.AddTunnel(tunnel)
	pump.SetDefaultRoute(tunnel)
	s.pump = pump
	go pump.Run()

	// Inbound ESP read loop. Exits when espConn is closed (on Close).
	go func() {
		defer close(s.done)
		buf := make([]byte, 65535)
		for {
			n, rerr := espConn.Read(buf)
			if rerr != nil {
				return
			}
			pkt := buf[:n]
			// Non-ESP marker (keepalive / non-ESP): 4 leading zero octets.
			if len(pkt) >= 4 && pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 {
				continue
			}
			pump.HandleESP(append([]byte(nil), pkt...))
		}
	}()

	// NAT keepalive: a single 0xFF byte every 20s holds the NAT binding (RFC 3948).
	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.stopKA:
				return
			case <-t.C:
				_, _ = espConn.Write([]byte{0xff})
			}
		}
	}()

	out := Result{
		TUNName:    tun.Name(),
		AssignedIP: res.AssignedIP,
		Netmask:    res.Netmask,
		Gateway:    serverGateway(res, cfg.Server),
		DNS:        res.DNS,
		MTU:        defaultTunnelMTU,
	}
	logger.Printf("client: tunnel up on %s, internal IP %s, DNS %v",
		out.TUNName, out.AssignedIP, out.DNS)
	return s, out, nil
}

// Wait blocks until the session is closed or ctx is cancelled. It returns
// ctx.Err() if the context ended first, else nil.
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the pump, ESP socket, TUN and IKE SA. It is idempotent and
// safe to call from any goroutine.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopKA)
		if s.pump != nil {
			s.pump.Close()
		}
		if s.espConn != nil {
			s.closeErr = s.espConn.Close() // unblocks the read loop
		}
		if s.tun != nil {
			s.tun.Close()
		}
		if s.ike != nil {
			s.ike.Close()
		}
	})
	return s.closeErr
}

// connect runs the IKE handshake but returns early if ctx is cancelled,
// interrupting the in-flight Connect by closing the client's socket so the
// caller does not have to wait out Connect's read deadlines.
func connect(ctx context.Context, c *ike.Client) (*ike.ClientResult, error) {
	type outcome struct {
		res *ike.ClientResult
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		res, err := c.Connect()
		ch <- outcome{res, err}
	}()
	select {
	case <-ctx.Done():
		c.Close() // unblocks Connect's socket read
		<-ch      // let the goroutine finish so nothing leaks
		return nil, ctx.Err()
	case o := <-ch:
		return o.res, o.err
	}
}

// serverGateway resolves the server's outer IPv4 address for the host route.
// res.ServerAddr already carries the resolved server IP; fall back to parsing or
// resolving the configured host if needed.
func serverGateway(res *ike.ClientResult, host string) net.IP {
	if res.ServerAddr != nil && res.ServerAddr.IP != nil {
		return res.ServerAddr.IP
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	if ips, err := net.LookupIP(host); err == nil {
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				return v4
			}
		}
	}
	return nil
}

// parseIdentity interprets an identity string as an IP literal or an FQDN.
func parseIdentity(s string) ike.Identity {
	if ip := net.ParseIP(s); ip != nil {
		return ike.IPIdentity(ip)
	}
	return ike.FQDNIdentity(s)
}

// discard is an io.Writer that drops everything, for a no-op logger.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
