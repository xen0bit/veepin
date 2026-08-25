// Package cisco is the public entry point to Cisco-style IPsec remote access:
// IKEv1 Aggressive Mode with a group pre-shared key, XAuth for the per-user
// credentials, Mode-Config for the address assignment, and a tunnel-mode ESP SA
// carrying bare IP over UDP.
//
// This is the "Cisco IPSec" every desktop and phone ships a built-in client for,
// and what vpnc and strongSwan's XAuth plugins speak. It is veepin's second
// IKEv1 protocol: internal/ikev1 already carried L2TP/IPsec, and this promotes
// the same ISAKMP machinery to a first-class remote-access profile.
//
// The shape is the one every veepin client follows: Dial authenticates, learns
// the assigned address and routes, and returns a client.Result the caller
// applies — it installs no addresses or routes itself.
package cisco

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	icisco "github.com/xen0bit/veepin/internal/cisco"
	"github.com/xen0bit/veepin/internal/vlog"
)

func init() { client.Register("cisco", parseOptions) }

// Option keys accepted by client.Dial(ctx, "cisco", opts).
const (
	OptServer   = "server"    // gateway host or IP (required)
	OptPort     = "port"      // gateway IKE port (default 500)
	OptGroup    = "group"     // the group name presented as the phase-1 identity (required)
	OptGroupPSK = "group-psk" // that group's pre-shared key (required)
	OptUser     = "user"      // XAuth username (required)
	OptPassword = "password"  // XAuth password (required)
	OptTUN      = "tun"       // TUN interface name
	OptShape    = "shape"     // per-flow outbound shaping budget in bytes (0 = off)
)

// Config is the parsed client configuration.
type Config struct {
	Server string
	// Port is the gateway's IKE port; 0 means the protocol's 500. The NAT-T port
	// is fixed at 4500 by RFC 3948 and is not configurable, because a peer
	// looking for the float has nowhere to be told otherwise.
	Port     int
	Group    string
	GroupPSK []byte
	Username string
	Password string
	TUNName  string
	// Shape enables outbound traffic shaping: how much padded output each inner
	// flow is given before shaping stops for that flow. Zero disables it.
	Shape  int
	Logger *slog.Logger
}

// Session is a running Cisco IPsec client.
type Session struct {
	client *icisco.Client
	tun    *dataplane.TUN
}

// Dial authenticates, brings the ESP SA up, and returns what the caller must
// apply. It installs no addresses or routes.
func Dial(ctx context.Context, cfg Config) (*Session, client.Result, error) {
	if cfg.Server == "" || cfg.Group == "" || len(cfg.GroupPSK) == 0 || cfg.Username == "" {
		return nil, client.Result{}, fmt.Errorf("cisco: server, group, group-psk and user are required")
	}
	logger := vlog.From(cfg.Logger)
	port := cfg.Port
	if port == 0 {
		port = icisco.DefaultIKEPort
	}

	serverIP, err := resolve(cfg.Server)
	if err != nil {
		return nil, client.Result{}, err
	}

	// One unconnected socket serves both gateway ports: phase 1 starts on the
	// IKE port and floats to the NAT-T port, where IKE and ESP then share it.
	// Keeping one local port across the float is also what keeps a NAT binding
	// the pre-float packets created.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("cisco: binding a local socket: %w", err)
	}
	localIP := localAddrFor(serverIP)

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		_ = conn.Close()
		return nil, client.Result{}, fmt.Errorf("cisco: opening TUN: %w", err)
	}

	c := icisco.NewClient(conn, tun, icisco.ClientConfig{
		ServerIP: serverIP,
		IKEPort:  port,
		LocalIP:  localIP,
		Group:    cfg.Group,
		GroupPSK: cfg.GroupPSK,
		Username: cfg.Username,
		Password: cfg.Password,
		Shape:    cfg.Shape,
		MTU:      client.DefaultTunnelMTU,
		Logger:   logger,
	})
	nc, err := c.Handshake(ctx)
	if err != nil {
		_ = c.Close()
		_ = tun.Close()
		// A rejected group key or XAuth password must reach the caller as
		// client.ErrAuth: retrying either is how an account locks out.
		return nil, client.Result{}, client.WrapAuth(err, icisco.ErrAuth)
	}
	if nc.Banner != "" {
		logger.Printf("cisco: gateway banner: %s", nc.Banner)
	}
	// The split-tunnel networks are reported rather than returned: client.Result
	// has no field for per-destination routes, so a caller that wants split
	// tunnelling installs them itself. The default a bare Result produces is the
	// safe one — everything through the tunnel — and the log says what the
	// gateway would have preferred.
	for _, r := range nc.Routes {
		logger.Printf("cisco: gateway suggests routing %s into the tunnel", r)
	}

	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: nc.AssignedIP,
		Netmask:    nc.Netmask,
		// Gateway is the server's OUTER address, so the caller pins a host route
		// to it and the tunnel's own packets do not recurse into it.
		Gateway: serverIP,
		DNS:     nc.DNS,
		MTU:     client.DefaultTunnelMTU,
	}
	logger.Printf("cisco: tunnel up, assigned %s", nc.AssignedIP)
	return &Session{client: c, tun: tun}, res, nil
}

// resolve turns the gateway name into an IPv4 address. IKEv1's identities and
// traffic selectors are IPv4 throughout, so an IPv6-only gateway has no
// representation in this protocol and is refused with the reason.
func resolve(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("cisco: %s is IPv6; this protocol addresses gateways by IPv4 only", host)
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("cisco: resolving %q: %w", host, err)
	}
	for _, a := range addrs {
		if v4 := a.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("cisco: %q has no IPv4 address", host)
}

// localAddrFor is the source address a datagram to the gateway would leave
// from. It is hashed into the NAT-D payloads, so it must be what the wire
// actually carries — and a failure to determine it is not fatal: NAT detection
// then simply reports a NAT that is not there, which is the conclusion veepin
// forces anyway.
func localAddrFor(server net.IP) net.IP {
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: server, Port: icisco.DefaultIKEPort})
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }()
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return la.IP.To4()
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

// Close tears the session down.
func (s *Session) Close() error {
	err := s.client.Close()
	_ = s.tun.Close()
	return err
}

// Probe implements client.Prober with the protocol's own dead-peer detection
// (RFC 3706), so a gateway that has gone away tears the tunnel down instead of
// blackholing it.
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
		Group:    opts[OptGroup],
		GroupPSK: []byte(opts[OptGroupPSK]),
		Username: opts[OptUser],
		Password: opts[OptPassword],
		TUNName:  opts[OptTUN],
		Logger:   slog.New(vlog.NewTextHandler(os.Stdout, slog.LevelInfo)),
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("cisco: server is required")
	}
	if cfg.Group == "" || len(cfg.GroupPSK) == 0 {
		return nil, fmt.Errorf("cisco: group and group-psk are required")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("cisco: user is required")
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("cisco: invalid port %q", v)
		}
		cfg.Port = p
	}
	if v := opts[OptShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("cisco: invalid shape %q", v)
		}
		cfg.Shape = n
	}
	return dialer{cfg}, nil
}
