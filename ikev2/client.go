// Package ikev2 is the public entry point to this module's IKEv2
// implementation: a client that performs the handshake (PSK or EAP-MSCHAPv2)
// and runs a userspace ESP-in-UDP data path over a TUN device.
//
// Like every protocol here, Dial installs no addresses, routes or DNS. It
// returns the negotiated client.Result and the caller applies it — the veepin
// command hands it to dataplane's router, and the NetworkManager plugin hands it
// to NM.
//
// Importing this package also registers "ikev2" with the client registry, so a
// caller that dials by name only needs the blank import:
//
//	import _ "github.com/xen0bit/veepin/ikev2"
//
//	sess, res, err := client.Dial(ctx, "ikev2", opts)
//
// The protocol internals (the state machine, wire codec, ESP and EAP) stay in
// internal/ikev2; this package is the supported surface.
package ikev2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/ike"
)

func init() { client.Register("ikev2", parseOptions) }

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

// Option keys accepted by client.Dial(ctx, "ikev2", opts). They match the
// NetworkManager plugin's connection settings, which is why the parsed names are
// hyphenated rather than Go-cased.
const (
	OptGateway  = "gateway"   // server host or IP (required)
	OptPort     = "port"      // server IKE port (default 500)
	OptPSK      = "psk"       // pre-shared key (required)
	OptLocalID  = "local-id"  // identity presented to the server (required)
	OptServerID = "server-id" // expected server identity (optional)
	OptUser     = "user"      // EAP-MSCHAPv2 username (optional)
	OptPassword = "password"  // EAP-MSCHAPv2 password (optional)
	OptTUNName  = "tun"       // desired TUN interface name (optional)
)

// parseOptions turns string-keyed options into a Dialer. It is what the registry
// calls for client.Dial(ctx, "ikev2", opts).
func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := Config{
		Server:      opts[OptGateway],
		PSK:         opts[OptPSK],
		LocalID:     opts[OptLocalID],
		ServerID:    opts[OptServerID],
		EAPUser:     opts[OptUser],
		EAPPassword: opts[OptPassword],
		TUNName:     opts[OptTUNName],
	}
	if p := opts[OptPort]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("bad %s %q: %w", OptPort, p, err)
		}
		cfg.Port = n
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return dialer{cfg}, nil
}

func (cfg Config) validate() error {
	switch {
	case cfg.Server == "":
		return fmt.Errorf("%s is required", OptGateway)
	case cfg.PSK == "":
		return fmt.Errorf("%s is required", OptPSK)
	case cfg.LocalID == "":
		return fmt.Errorf("%s is required", OptLocalID)
	}
	return nil
}

// dialer adapts a Config to client.Dialer.
type dialer struct{ cfg Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, d.cfg)
}

// Dial performs the handshake, opens the TUN, and starts the ESP data path,
// returning a running session and the Result the caller must apply. It installs
// no routes or addresses. On error nothing is left running.
//
// The context bounds the setup; once Dial returns, use the session's Wait/Close
// for the tunnel lifetime.
func Dial(ctx context.Context, cfg Config) (client.Session, client.Result, error) {
	if err := cfg.validate(); err != nil {
		return nil, client.Result{}, fmt.Errorf("ikev2: %w", err)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
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
			return nil, client.Result{}, fmt.Errorf("ikev2: %w: %v", client.ErrAuth, err)
		}
		return nil, client.Result{}, fmt.Errorf("ikev2: connect: %w", err)
	}
	// From here on, any failure must close the IKE client.
	fail := func(err error) (client.Session, client.Result, error) {
		c.Close()
		return nil, client.Result{}, err
	}

	// 2. TUN.
	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return fail(fmt.Errorf("ikev2: open TUN: %w", err))
	}

	// 3. Data-path tunnel.
	tunnel, err := res.BuildTunnel()
	if err != nil {
		tun.Close()
		return fail(fmt.Errorf("ikev2: build tunnel: %w", err))
	}

	// 4. ESP shares the IKE socket (already floated to NAT-T port 4500), so ESP
	// and IKE leave from one source port — the standards-compliant NAT-T layout a
	// responder relies on to route return ESP back to us.
	dataConn := c.DataConn()

	s := &session{
		ike:      c,
		tun:      tun,
		dataConn: dataConn,
		logger:   logger,
		done:     make(chan struct{}),
		stopKA:   make(chan struct{}),
	}

	// The socket is connected to the server, so the destination is implicit.
	send := func(esp []byte, _ *net.UDPAddr) {
		if _, werr := dataConn.Write(esp); werr != nil {
			logger.Printf("ikev2: ESP send error: %v", werr)
		}
	}
	// The tunnel reports 0.0.0.0/0 as its route, so everything leaving the TUN is
	// routed to the server; no separate default-route call is needed.
	pump := dataplane.NewPump(tun, send, dataplane.SPIDemux, logger)
	pump.AddTunnel(tunnel)
	s.pump = pump
	go pump.Run()

	// Inbound read loop on the shared socket. Exits when the socket is closed
	// (on Close, via ike.Close()). A 4-zero-octet prefix marks a non-ESP datagram
	// (NAT keepalive, or any late IKE) — skip it; everything else is ESP. Reads
	// are batched (dataplane.BatchConn over the connected socket): one recvmmsg
	// drains up to readBatch datagrams under load and blocks like a plain read
	// when idle.
	go func() {
		defer close(s.done)
		const readBatch = 16
		bc := dataplane.NewBatchConn(dataConn)
		bufs := make([][]byte, readBatch)
		for i := range bufs {
			bufs[i] = make([]byte, 65535)
		}
		sizes := make([]int, readBatch)
		for {
			n, rerr := bc.ReadBatch(bufs, sizes)
			for i := range n {
				pkt := bufs[i][:sizes[i]]
				if len(pkt) >= 4 && pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 {
					continue
				}
				// No copy: the pump decrypts in place and writes the TUN before
				// returning; bufs[i] is not touched again until the next
				// ReadBatch. Connected socket: the source is implicitly the
				// server, so no return-address update is needed (pass nil).
				pump.HandleInbound(pkt, nil)
			}
			if rerr != nil {
				return
			}
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
				_, _ = dataConn.Write([]byte{0xff})
			}
		}
	}()

	out := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: res.AssignedIP,
		Netmask:    res.Netmask,
		Gateway:    serverGateway(res, cfg.Server),
		DNS:        res.DNS,
		MTU:        client.DefaultTunnelMTU,
	}
	logger.Printf("ikev2: tunnel up on %s, internal IP %s, DNS %v",
		out.TUNName, out.AssignedIP, out.DNS)
	return s, out, nil
}

// session is a running IKEv2 tunnel: the IKE SA, the TUN device, and the ESP
// pump. It implements client.Session.
type session struct {
	ike  *ike.Client
	tun  *dataplane.TUN
	pump *dataplane.Pump
	// dataConn is the IKE socket (floated to 4500), shared for the ESP data
	// path so ESP and IKE share one source port as RFC 3948 NAT-T requires. It
	// is owned by ike; Close closes it via ike.Close().
	dataConn *net.UDPConn
	logger   *log.Logger

	closeOnce sync.Once
	closeErr  error
	done      chan struct{} // closed when the inbound loop exits (i.e. on Close)
	stopKA    chan struct{} // stops the NAT-keepalive goroutine
}

// Wait blocks until the session is closed or ctx is cancelled. It returns
// ctx.Err() if the context ended first, else nil.
func (s *session) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the pump, ESP socket, TUN and IKE SA. It is idempotent and
// safe to call from any goroutine.
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopKA)
		if s.pump != nil {
			s.pump.Close()
		}
		if s.tun != nil {
			s.tun.Close()
		}
		// Closing the IKE client closes the shared socket, which unblocks the
		// inbound read loop.
		if s.ike != nil {
			s.closeErr = s.ike.Close()
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
