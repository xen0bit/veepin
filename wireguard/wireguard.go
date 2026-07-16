// Package wireguard is the public entry point to this module's WireGuard
// implementation: an initiator that performs the Noise_IKpsk2 handshake and runs
// a userspace transport data path over a TUN device.
//
// Like every protocol here, Dial installs no addresses, routes or DNS. It
// returns the negotiated client.Result and the caller applies it — the veepin
// command hands it to dataplane's router, and the NetworkManager plugin hands it
// to NM.
//
// Importing this package registers "wireguard" with the client registry, so a
// caller that dials by name only needs the blank import:
//
//	import _ "github.com/xen0bit/veepin/wireguard"
//
//	sess, res, err := client.Dial(ctx, "wireguard", opts)
//
// The protocol internals (the message codec, the handshake, and the transport
// crypto) live in internal/wireguard; this package is the supported surface.
//
// # Scope
//
// This is the initiator, single-peer data path. It performs one handshake and
// carries traffic under that keypair; it does not yet rekey, so a session is
// good for the handshake's lifetime (RejectAfterTime, ~180s of continuous use)
// before it must be re-dialed. It answers no cookie replies, so a peer under
// load will refuse it. Both are deliberate Milestone-1 boundaries, not silent
// gaps: the first surfaces as the tunnel going quiet, the second as a refused
// handshake.
package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/wireguard/noise"
	"github.com/xen0bit/veepin/internal/wireguard/transport"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

func init() { client.Register("wireguard", parseOptions) }

// Default inner MTU. WireGuard's own default is 1420: a 1500-octet outer path
// less the 80 octets of the largest (IPv6) outer header, UDP header and
// transport framing. Config.MTU overrides it.
const defaultMTU = 1420

// Handshake retransmission, from the protocol paper §6.1. An initiation is
// resent every rekeyTimeout until a response arrives or the overall attempt
// budget is spent.
const (
	rekeyTimeout = 5 * time.Second
	maxAttempts  = 5
)

// Option keys accepted by client.Dial(ctx, "wireguard", opts). OptConfig points
// at a wg-quick file; the rest override individual fields, so the CLI can take a
// file, a set of flags, or both.
const (
	OptConfig       = "config"               // path to a wg-quick config file
	OptPrivateKey   = "private-key"          // our static private key, base64
	OptAddress      = "address"              // our tunnel address(es), CIDR
	OptDNS          = "dns"                  // DNS servers
	OptMTU          = "mtu"                  // inner MTU
	OptPublicKey    = "public-key"           // peer static public key, base64
	OptPresharedKey = "preshared-key"        // optional preshared key, base64
	OptEndpoint     = "endpoint"             // peer host:port
	OptAllowedIPs   = "allowed-ips"          // inner destinations for the peer
	OptKeepalive    = "persistent-keepalive" // keepalive seconds
	OptTUNName      = "tun"                  // desired TUN interface name
)

// parseOptions turns string-keyed options into a Dialer: it loads the -config
// file if given, then layers the individual options over it. It is what the
// registry calls for client.Dial(ctx, "wireguard", opts).
func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := &Config{}
	if path := opts[OptConfig]; path != "" {
		loaded, err := ParseConfigFile(path)
		if err != nil {
			return nil, err
		}
		cfg = loaded
	}
	if err := cfg.applyOverrides(opts); err != nil {
		return nil, err
	}
	if _, err := cfg.resolve(); err != nil {
		return nil, err
	}
	return dialer{cfg}, nil
}

// dialer adapts a Config to client.Dialer.
type dialer struct{ cfg *Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, *d.cfg)
}

// resolved is a Config decoded and validated into the concrete types Dial needs:
// keys as bytes, addresses as prefixes, the endpoint as a UDP address. Doing it
// once, up front, means a malformed key is a config error rather than a
// mid-handshake surprise.
type resolved struct {
	noiseCfg   noise.Config
	endpoint   *net.UDPAddr
	address    netip.Prefix   // our first tunnel address
	allowedIPs []netip.Prefix // routed to the peer
	dns        []net.IP
	mtu        int
	tunName    string
	keepalive  time.Duration
}

// resolve decodes and validates cfg. It is called both by parseOptions (to
// reject bad input early) and by Dial.
func (c *Config) resolve() (*resolved, error) {
	priv, err := decodeKey(c.PrivateKey, OptPrivateKey)
	if err != nil {
		return nil, err
	}
	pub, err := decodeKey(c.PublicKey, OptPublicKey)
	if err != nil {
		return nil, err
	}
	if c.Endpoint == "" {
		return nil, fmt.Errorf("%s is required", OptEndpoint)
	}
	if len(c.Address) == 0 {
		return nil, fmt.Errorf("%s is required", OptAddress)
	}
	if len(c.AllowedIPs) == 0 {
		return nil, fmt.Errorf("%s is required", OptAllowedIPs)
	}

	r := &resolved{
		noiseCfg: noise.Config{LocalStatic: priv, RemoteStatic: pub},
		mtu:      c.MTU,
		tunName:  c.TUNName,
	}
	if c.PresharedKey != "" {
		psk, err := decodeKey(c.PresharedKey, OptPresharedKey)
		if err != nil {
			return nil, err
		}
		r.noiseCfg.PresharedKey = psk
	}
	if r.mtu == 0 {
		r.mtu = defaultMTU
	}
	if c.Keepalive > 0 {
		r.keepalive = time.Duration(c.Keepalive) * time.Second
	}

	addrs, err := prefixes(c.Address)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", OptAddress, err)
	}
	r.address = addrs[0]

	r.allowedIPs, err = prefixes(c.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", OptAllowedIPs, err)
	}

	r.endpoint, err = net.ResolveUDPAddr("udp", c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%s %q: %w", OptEndpoint, c.Endpoint, err)
	}

	for _, s := range c.DNS {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("%s: bad address %q", OptDNS, s)
		}
		r.dns = append(r.dns, ip)
	}
	return r, nil
}

// Dial performs the handshake, opens the TUN, and starts the transport data
// path, returning a running session and the Result the caller must apply. It
// installs no routes or addresses. On error nothing is left running.
//
// The context bounds the handshake; once Dial returns, use the session's
// Wait/Close for the tunnel lifetime.
func Dial(ctx context.Context, cfg Config) (client.Session, client.Result, error) {
	r, err := cfg.resolve()
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("wireguard: %w", err)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	// A connected socket: the kernel filters to the endpoint, and every send
	// implicitly addresses it, so the road-warrior return-address handling the
	// server side needs does not arise here.
	conn, err := net.DialUDP("udp", nil, r.endpoint)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("wireguard: dial %s: %w", r.endpoint, err)
	}

	kp, err := handshake(ctx, conn, r.noiseCfg, logger)
	if err != nil {
		conn.Close()
		if errors.Is(err, noise.ErrDecrypt) {
			return nil, client.Result{}, fmt.Errorf("wireguard: %w: %v", client.ErrAuth, err)
		}
		return nil, client.Result{}, fmt.Errorf("wireguard: handshake: %w", err)
	}

	sess, err := transport.NewSession(kp.Send, kp.Recv, kp.Local, kp.Remote)
	if err != nil {
		conn.Close()
		return nil, client.Result{}, fmt.Errorf("wireguard: transport keys: %w", err)
	}

	tun, err := dataplane.OpenTUN(r.tunName)
	if err != nil {
		conn.Close()
		return nil, client.Result{}, fmt.Errorf("wireguard: open TUN: %w", err)
	}

	tunnel := &wgTunnel{sess: sess, routes: r.allowedIPs, peer: r.endpoint}

	s := &session{
		conn:   conn,
		tun:    tun,
		logger: logger,
		done:   make(chan struct{}),
		stopKA: make(chan struct{}),
	}

	// The socket is connected, so the destination is implicit and the pump's
	// PeerAddr is ignored.
	send := func(pkt []byte, _ *net.UDPAddr) {
		if _, werr := conn.Write(pkt); werr != nil {
			logger.Printf("wireguard: send error: %v", werr)
		}
	}
	// Outbound TUN traffic is routed to the peer by longest-prefix match over its
	// AllowedIPs; inbound transport packets demux on our receiver index.
	pump := dataplane.NewPump(tun, send, wire.Demux, logger)
	pump.AddTunnel(tunnel)
	s.pump = pump
	go pump.Run()

	go s.readLoop(pump)
	s.startKeepalive(tunnel, r.keepalive)

	out := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: net.IP(r.address.Addr().AsSlice()),
		Netmask:    prefixNetmask(r.address),
		Gateway:    r.endpoint.IP,
		DNS:        r.dns,
		MTU:        r.mtu,
	}
	logger.Printf("wireguard: tunnel up on %s, internal IP %s, peer %s",
		out.TUNName, out.AssignedIP, r.endpoint)
	return s, out, nil
}

// handshake sends the initiation and waits for the response, retransmitting a
// fresh initiation every rekeyTimeout until one is answered, the attempt budget
// is spent, or ctx is cancelled. Each attempt uses a new Initiator, since an
// initiation — and its ephemeral key — is single-use.
func handshake(ctx context.Context, conn *net.UDPConn, cfg noise.Config, logger *log.Logger) (*noise.Keypair, error) {
	buf := make([]byte, wire.SizeHandshakeResponse)
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		init, err := noise.NewInitiator(cfg)
		if err != nil {
			return nil, err
		}
		msg, err := init.Initiation()
		if err != nil {
			return nil, err
		}
		if _, err := conn.Write(msg); err != nil {
			return nil, fmt.Errorf("send initiation: %w", err)
		}

		deadline := time.Now().Add(rekeyTimeout)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if attempt >= maxAttempts {
					return nil, fmt.Errorf("no response after %d attempts", maxAttempts)
				}
				logger.Printf("wireguard: handshake attempt %d timed out, retrying", attempt)
				continue
			}
			return nil, err
		}

		kp, err := init.Consume(buf[:n])
		if err != nil {
			// A cookie reply (message type 3) lands here as a parse failure: the
			// responder is under load and demands a cookie this build does not
			// send. Retrying will not help until that is implemented.
			if errors.Is(err, noise.ErrDecrypt) {
				return nil, err
			}
			logger.Printf("wireguard: discarding unexpected handshake reply: %v", err)
			if attempt >= maxAttempts {
				return nil, fmt.Errorf("no valid response after %d attempts", maxAttempts)
			}
			continue
		}
		_ = conn.SetReadDeadline(time.Time{}) // clear for the steady-state loop
		return kp, nil
	}
}

// session is a running WireGuard tunnel: the UDP socket, the TUN device, and the
// transport pump. It implements client.Session.
type session struct {
	conn   *net.UDPConn
	tun    *dataplane.TUN
	pump   *dataplane.Pump
	logger *log.Logger

	closeOnce sync.Once
	closeErr  error
	done      chan struct{} // closed when the inbound loop exits
	stopKA    chan struct{} // stops the keepalive goroutine
}

// readLoop reads datagrams off the socket and hands them to the pump, which
// demuxes transport-data packets to the tunnel and drops everything else
// (stray handshake or cookie messages). It exits when the socket is closed.
func (s *session) readLoop(pump *dataplane.Pump) {
	defer close(s.done)
	buf := make([]byte, 65535)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			return
		}
		// Copy: the pump decrypts in place and outlives this iteration's buffer.
		pump.HandleInbound(append([]byte(nil), buf[:n]...), nil)
	}
}

// startKeepalive primes the peer's return path and, if a persistent-keepalive
// interval is configured, holds it open. WireGuard's responder will not send
// transport data on a fresh session until it has received some, so an initial
// keepalive makes the tunnel usable in both directions immediately rather than
// only after our first outbound packet.
func (s *session) startKeepalive(t *wgTunnel, interval time.Duration) {
	s.sendKeepalive(t)
	if interval <= 0 {
		return
	}
	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-s.stopKA:
				return
			case <-tick.C:
				s.sendKeepalive(t)
			}
		}
	}()
}

func (s *session) sendKeepalive(t *wgTunnel) {
	pkt, err := t.Encapsulate(nil)
	if err != nil {
		s.logger.Printf("wireguard: keepalive: %v", err)
		return
	}
	if _, err := s.conn.Write(pkt); err != nil {
		s.logger.Printf("wireguard: keepalive send: %v", err)
	}
}

// Wait blocks until the session is closed or ctx is cancelled.
func (s *session) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the pump, socket and TUN. It is idempotent and safe to call
// from any goroutine.
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopKA)
		if s.pump != nil {
			s.pump.Close()
		}
		if s.tun != nil {
			s.tun.Close()
		}
		// Closing the socket unblocks the inbound read loop.
		if s.conn != nil {
			s.closeErr = s.conn.Close()
		}
	})
	return s.closeErr
}

// wgTunnel is the data-path view of the established session: it encrypts and
// decrypts transport packets and reports the peer's AllowedIPs as its routes. It
// implements dataplane.Tunnel.
type wgTunnel struct {
	sess   *transport.Session
	routes []netip.Prefix
	peer   *net.UDPAddr
}

func (t *wgTunnel) InboundKey() uint32                   { return t.sess.LocalIndex() }
func (t *wgTunnel) Routes() []netip.Prefix               { return t.routes }
func (t *wgTunnel) PeerAddr() *net.UDPAddr               { return t.peer }
func (t *wgTunnel) Encapsulate(p []byte) ([]byte, error) { return t.sess.Seal(p) }
func (t *wgTunnel) Decapsulate(p []byte) ([]byte, error) { return t.sess.Open(p) }

// decodeKey decodes a 32-octet base64 WireGuard key, naming the option so a bad
// value points at the field that carried it.
func decodeKey(s, name string) ([32]byte, error) {
	var k [32]byte
	if s == "" {
		return k, fmt.Errorf("%s is required", name)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("%s: not base64: %w", name, err)
	}
	if len(raw) != len(k) {
		return k, fmt.Errorf("%s: %d octets, want 32", name, len(raw))
	}
	copy(k[:], raw)
	return k, nil
}

// prefixNetmask returns the IPv4 netmask of a prefix as a net.IP, for the
// Result the client router applies.
func prefixNetmask(p netip.Prefix) net.IP {
	return net.IP(net.CIDRMask(p.Bits(), p.Addr().BitLen()))
}
