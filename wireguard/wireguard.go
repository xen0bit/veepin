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
// This package provides both roles: Dial is the initiator (below), and Server
// (see server.go) is the multi-peer responder that `veepin serve wireguard`
// runs.
//
// # Scope
//
// A client rekeys: it re-runs the handshake every rekeyAfterTime and rotates the
// fresh keypair in, so a tunnel stays up indefinitely rather than going quiet at
// the key's rejection age (~180s). Rekey is client-initiated only — the server
// answers new initiations but does not start its own — and neither role answers
// cookie replies, so a peer under load will refuse the handshake. Both are
// deliberate boundaries, not silent gaps: an idle peer that never rekeys and a
// peer under load both surface as a refused or absent handshake.
package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/binary"
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

// Default inner MTU, derived rather than asserted. WireGuard's conventional
// 1420 is exactly a 1500-octet path less the *IPv6* outer header, the UDP
// header, and WireGuard's own transport framing — the larger of the two IP
// families, so one MTU is safe over either. That is why every WireGuard
// implementation ships the same slightly-conservative number, and computing it
// here says so rather than leaving 1420 to look arbitrary.
//
// Config.MTU overrides it.
const defaultMTU = dataplane.DefaultPathMTU - dataplane.OuterUDP6 - wire.Overhead

// Handshake retransmission, from the protocol paper §6.1. An initiation is
// resent every rekeyTimeout until a response arrives or the overall attempt
// budget is spent. The initial handshake uses maxAttempts as its budget; a
// rekey, which runs against a live tunnel, retries for rekeyAttemptTime instead
// (§6.1's REKEY_ATTEMPT_TIME) so it keeps trying for nearly the whole rejection
// window before giving the tunnel up.
const (
	rekeyTimeout     = 5 * time.Second
	maxAttempts      = 5
	rekeyAttemptTime = 90 * time.Second
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
	OptListenPort   = "listen-port"          // UDP port to listen on (server)
	OptRekeySeconds = "rekey-seconds"        // client rekey interval (0 = default)
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
	rekey      time.Duration // how often to re-run the handshake
}

// resolve decodes and validates cfg as a client config: exactly one peer, with
// an endpoint to dial. It is called both by parseOptions (to reject bad input
// early) and by Dial.
func (c *Config) resolve() (*resolved, error) {
	priv, err := decodeKey(c.PrivateKey, OptPrivateKey)
	if err != nil {
		return nil, err
	}
	switch len(c.Peers) {
	case 1:
		// ok
	case 0:
		return nil, fmt.Errorf("%s is required", OptPublicKey)
	default:
		return nil, fmt.Errorf("a client takes one peer, got %d", len(c.Peers))
	}
	peer := c.Peers[0]

	pub, err := decodeKey(peer.PublicKey, OptPublicKey)
	if err != nil {
		return nil, err
	}
	if peer.Endpoint == "" {
		return nil, fmt.Errorf("%s is required", OptEndpoint)
	}
	if len(c.Address) == 0 {
		return nil, fmt.Errorf("%s is required", OptAddress)
	}
	if len(peer.AllowedIPs) == 0 {
		return nil, fmt.Errorf("%s is required", OptAllowedIPs)
	}

	r := &resolved{
		noiseCfg: noise.Config{LocalStatic: priv, RemoteStatic: pub},
		mtu:      c.MTU,
		tunName:  c.TUNName,
	}
	if peer.PresharedKey != "" {
		psk, err := decodeKey(peer.PresharedKey, OptPresharedKey)
		if err != nil {
			return nil, err
		}
		r.noiseCfg.PresharedKey = psk
	}
	if r.mtu == 0 {
		r.mtu = defaultMTU
	}
	if peer.Keepalive > 0 {
		r.keepalive = time.Duration(peer.Keepalive) * time.Second
	}
	r.rekey = rekeyAfterTime
	if c.RekeySeconds > 0 {
		r.rekey = time.Duration(c.RekeySeconds) * time.Second
	}

	addrs, err := prefixes(c.Address)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", OptAddress, err)
	}
	r.address = addrs[0]

	r.allowedIPs, err = prefixes(peer.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", OptAllowedIPs, err)
	}

	r.endpoint, err = net.ResolveUDPAddr("udp", peer.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%s %q: %w", OptEndpoint, peer.Endpoint, err)
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

	tunnel := newTunnel(sess, r.allowedIPs, r.endpoint, false)

	s := &session{
		conn:          conn,
		tun:           tun,
		tunnel:        tunnel,
		logger:        logger,
		noiseCfg:      r.noiseCfg,
		rekeyInterval: r.rekey,
		done:          make(chan struct{}),
		stop:          make(chan struct{}),
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
	pump.SetInnerMTU(r.mtu)
	pump.AddTunnel(tunnel)
	s.pump = pump
	go pump.Run()

	go s.readLoop()
	s.startKeepalive(r.keepalive)
	go s.rekeyLoop()

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

// session is a running WireGuard tunnel: the UDP socket, the TUN device, the
// transport pump, and the single peer tunnel whose keys it rotates. It
// implements client.Session.
type session struct {
	conn   *net.UDPConn
	tun    *dataplane.TUN
	pump   *dataplane.Pump
	tunnel *wgTunnel
	logger *log.Logger

	// noiseCfg is kept so the rekey loop can start fresh handshakes, and
	// rekeyInterval is how often it does.
	noiseCfg      noise.Config
	rekeyInterval time.Duration

	// hsMu guards pending, the in-flight rekey handshake awaiting its response.
	// The initial handshake does not use it: it runs before readLoop starts, so
	// there is no dispatch to arbitrate.
	hsMu    sync.Mutex
	pending *pendingHandshake

	closeOnce sync.Once
	closeErr  error
	done      chan struct{} // closed when the inbound loop exits
	stop      chan struct{} // stops the keepalive and rekey goroutines
}

// pendingHandshake links an in-flight rekey initiation to the goroutine awaiting
// its response. readLoop matches an inbound response's receiver index against
// localIdx and hands the packet over on ch.
type pendingHandshake struct {
	localIdx uint32
	ch       chan []byte
}

// readLoop reads datagrams off the socket and dispatches by message type:
// transport-data packets go to the pump for the tunnel, and handshake responses
// go to a waiting rekey (there is no other reason to receive one on an
// established client tunnel). Everything else — stray initiations, cookie
// replies — is dropped. It exits when the socket is closed.
func (s *session) readLoop() {
	defer close(s.done)
	// Reads are batched (dataplane.BatchConn over the connected socket): one
	// recvmmsg drains up to readBatch datagrams under load and blocks like a
	// plain read when idle.
	const readBatch = 16
	bc := dataplane.NewBatchConn(s.conn)
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	for {
		n, err := bc.ReadBatch(bufs, sizes)
		for i := range n {
			pkt := bufs[i][:sizes[i]]
			t, ok := wire.Type(pkt)
			if !ok {
				continue
			}
			switch t {
			case wire.TypeTransportData:
				// No copy: the pump decrypts in place and writes the TUN before
				// returning; bufs[i] is not touched again until the next
				// ReadBatch.
				s.pump.HandleInbound(pkt, nil)
			case wire.TypeHandshakeResponse:
				// Copied: a delivered response is handed to the rekey goroutine
				// and outlives this batch's buffers.
				s.deliverResponse(append([]byte(nil), pkt...))
			default:
				// A stray initiation or a cookie reply: nothing an established
				// client tunnel acts on.
			}
		}
		if err != nil {
			return
		}
	}
}

// deliverResponse hands a handshake response to the rekey goroutine waiting for
// it, matched on the receiver index the response is addressed to. A response for
// no pending handshake — a duplicate, or one that arrived after the waiter gave
// up — is dropped.
func (s *session) deliverResponse(pkt []byte) {
	if len(pkt) != wire.SizeHandshakeResponse {
		return
	}
	receiver := binary.LittleEndian.Uint32(pkt[8:12])
	s.hsMu.Lock()
	p := s.pending
	s.hsMu.Unlock()
	if p == nil || p.localIdx != receiver {
		return
	}
	// Buffered channel of one; a second response for the same index is dropped.
	select {
	case p.ch <- pkt:
	default:
	}
}

func (s *session) setPending(p *pendingHandshake) {
	s.hsMu.Lock()
	s.pending = p
	s.hsMu.Unlock()
}

func (s *session) clearPending() {
	s.hsMu.Lock()
	s.pending = nil
	s.hsMu.Unlock()
}

// rekeyLoop re-runs the handshake every rekeyInterval, rotating a fresh keypair
// into the tunnel so traffic never reaches the key's rejection age. It is the
// initiator half of the protocol's rekey timing (§6.1); the server responds to
// each new initiation as it would a first one.
func (s *session) rekeyLoop() {
	if s.rekeyInterval <= 0 {
		return
	}
	tick := time.NewTicker(s.rekeyInterval)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			s.rekey()
		}
	}
}

// rekey runs one handshake and installs its keypair as the tunnel's current one,
// registering the new receiver index with the pump and retiring the keypair that
// fell out. A failure leaves the existing keys in place: the next tick tries
// again, and Encapsulate refuses only once the current key passes rejectAfterTime.
func (s *session) rekey() {
	ctx, cancel := context.WithTimeout(context.Background(), rekeyAttemptTime)
	defer cancel()
	// Abandon the attempt promptly if the session is closing.
	go func() {
		select {
		case <-s.stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	kp, err := s.doHandshake(ctx)
	if err != nil {
		s.logger.Printf("wireguard: rekey failed: %v", err)
		return
	}
	sess, err := transport.NewSession(kp.Send, kp.Recv, kp.Local, kp.Remote)
	if err != nil {
		s.logger.Printf("wireguard: rekey transport keys: %v", err)
		return
	}
	evicted := s.tunnel.install(sess)
	s.pump.AddInboundKey(sess.LocalIndex(), s.tunnel)
	if evicted != nil {
		s.pump.RemoveInboundKey(evicted.LocalIndex())
	}
	// Prime the new key's return path: the responder holds off sending under a
	// fresh keypair until it has received something under it.
	s.sendKeepalive(s.tunnel)
	s.logger.Printf("wireguard: rekeyed, session index %#x", sess.LocalIndex())
}

// doHandshake runs a rekey handshake dispatched through readLoop: it sends an
// initiation, waits for readLoop to deliver the matching response, and
// retransmits a fresh initiation every rekeyTimeout until one is answered or ctx
// (bounded by rekeyAttemptTime) is spent. Each attempt is a new Initiator, since
// an initiation and its ephemeral key are single-use.
//
// It is separate from the initial handshake, which reads the socket directly
// because readLoop is not running yet; here readLoop owns the socket, so the
// response must be handed over rather than read.
func (s *session) doHandshake(ctx context.Context) (*noise.Keypair, error) {
	defer s.clearPending()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		init, err := noise.NewInitiator(s.noiseCfg)
		if err != nil {
			return nil, err
		}
		msg, err := init.Initiation()
		if err != nil {
			return nil, err
		}
		ch := make(chan []byte, 1)
		s.setPending(&pendingHandshake{localIdx: init.LocalIndex(), ch: ch})
		if _, err := s.conn.Write(msg); err != nil {
			return nil, fmt.Errorf("send initiation: %w", err)
		}

		timer := time.NewTimer(rekeyTimeout)
		select {
		case resp := <-ch:
			timer.Stop()
			kp, err := init.Consume(resp)
			if err != nil {
				if errors.Is(err, noise.ErrDecrypt) {
					return nil, err
				}
				s.logger.Printf("wireguard: rekey: discarding unexpected reply: %v", err)
				continue
			}
			return kp, nil
		case <-timer.C:
			s.logger.Printf("wireguard: rekey attempt timed out, retrying")
			continue
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}
}

// startKeepalive primes the peer's return path and, if a persistent-keepalive
// interval is configured, holds it open. WireGuard's responder will not send
// transport data on a fresh session until it has received some, so an initial
// keepalive makes the tunnel usable in both directions immediately rather than
// only after our first outbound packet.
func (s *session) startKeepalive(interval time.Duration) {
	s.sendKeepalive(s.tunnel)
	if interval <= 0 {
		return
	}
	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-tick.C:
				s.sendKeepalive(s.tunnel)
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
		close(s.stop)
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
