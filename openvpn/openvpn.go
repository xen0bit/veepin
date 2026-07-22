// Package openvpn is the public entry point to this module's OpenVPN
// implementation: a UDP client that speaks OpenVPN's TLS control channel and
// AES-256-GCM data channel, over a userspace TUN.
//
// Like every protocol here, Dial installs no addresses, routes or DNS. It
// returns the negotiated client.Result and the caller applies it — the veepin
// command hands it to dataplane's router, and the NetworkManager plugin to NM.
//
// Importing this package registers "openvpn" with the client registry:
//
//	import _ "github.com/xen0bit/veepin/openvpn"
//
//	sess, res, err := client.Dial(ctx, "openvpn", opts)
//
// The protocol internals — the packet codec, reliability layer, TLS control
// channel, key exchange, and data-channel crypto — live in internal/openvpn;
// this package orchestrates them into a dial.
//
// # Scope
//
// This is a client (initiator) over UDP transport with TLS certificate
// authentication and P_DATA_V2 (a server-assigned peer-id). It negotiates the
// AES-256-GCM data cipher by default and also speaks the older AES-256-CBC data
// channel (encrypt-then-MAC with an --auth HMAC). The control channel can be
// plain, --tls-auth (an HMAC over every control packet), or --tls-crypt
// (authenticated encryption of every control packet); the static key is read
// from the config or a flag. It does not implement compression or the older
// net30 topology's assumptions, and a profile it cannot speak fails at dial
// rather than silently misbehaving.
package openvpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/openvpn/control"
	"github.com/xen0bit/veepin/internal/openvpn/data"
	"github.com/xen0bit/veepin/internal/openvpn/keys"
	"github.com/xen0bit/veepin/internal/openvpn/tlswrap"
	"github.com/xen0bit/veepin/internal/openvpn/wire"
)

func init() { client.Register("openvpn", parseOptions) }

const (
	// handshakeTimeout bounds the whole negotiation: TLS handshake, key exchange
	// and config pull.
	handshakeTimeout = 30 * time.Second
	// controlTimeout is the control-channel retransmit interval (--tls-timeout).
	controlTimeout = 2 * time.Second
	// keepaliveInterval is how often the client sends a data-channel ping to hold
	// the tunnel and NAT binding open.
	keepaliveInterval = 10 * time.Second
	// dataTunnelKey is the pump demux key for the client's single data tunnel;
	// the value is arbitrary since there is only one.
	dataTunnelKey = 1
	// defaultMTU is the inner TUN MTU when the server pushes none.
	//
	// It is not derived, and should not be: OpenVPN's own `tun-mtu` default is
	// 1500, and this value is only ever a fallback for a server that declined to
	// push one. Substituting a smaller derived figure would silently disagree
	// with what every other OpenVPN client uses against that same server. The
	// negotiated path is the pushed value, which parseInstruction applies.
	defaultMTU = 1500
)

// parseOptions turns string-keyed options into a Dialer: it loads the .ovpn file
// if given, layers the individual options over it, and validates. It is what the
// registry calls for client.Dial(ctx, "openvpn", opts).
func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := &Config{KeyDirection: -1}
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
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return dialer{cfg}, nil
}

// dialer adapts a Config to client.Dialer.
type dialer struct{ cfg *Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, *d.cfg)
}

// Dial connects to the OpenVPN server, runs the handshake, key exchange and
// config pull, opens the TUN, and starts the data path. It returns a running
// session and the Result the caller must apply. On error nothing is left
// running.
func Dial(ctx context.Context, cfg Config) (client.Session, client.Result, error) {
	if err := cfg.validate(); err != nil {
		return nil, client.Result{}, fmt.Errorf("openvpn: %w", err)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	tlsCfg, err := clientTLSConfig(&cfg)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("openvpn: %w", err)
	}

	endpoint, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.Remote, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("openvpn: resolve %s: %w", cfg.Remote, err)
	}
	conn, err := net.DialUDP("udp", nil, endpoint)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("openvpn: dial %s: %w", endpoint, err)
	}

	wrap, err := buildWrapper(&cfg)
	if err != nil {
		conn.Close()
		return nil, client.Result{}, fmt.Errorf("openvpn: %w", err)
	}

	m := &muxer{conn: conn, logger: logger, closed: make(chan struct{})}
	ch, err := control.New(func(b []byte) error { _, werr := conn.Write(b); return werr }, 0, controlTimeout, wrap)
	if err != nil {
		conn.Close()
		return nil, client.Result{}, fmt.Errorf("openvpn: control channel: %w", err)
	}
	m.control = ch
	go m.readLoop()

	// Bound the whole negotiation; on failure tear the socket down, which unblocks
	// the control channel and the read loop.
	deadline := time.Now().Add(handshakeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = ch.SetDeadline(deadline)

	result, tunnel, err := negotiate(ctx, &cfg, ch, tlsCfg, endpoint, logger)
	if err != nil {
		m.Close()
		if errors.Is(err, io.EOF) || isTLSAuthError(err) {
			return nil, client.Result{}, fmt.Errorf("openvpn: %w: %v", client.ErrAuth, err)
		}
		return nil, client.Result{}, fmt.Errorf("openvpn: %w", err)
	}
	_ = ch.SetDeadline(time.Time{})

	// GSO: the kernel may hand the pump TCP super-frames to segment and batch
	// (doc/scaling-the-data-path.md); falls back to a plain TUN transparently.
	tun, err := dataplane.OpenTUNGSO(cfg.TUNName)
	if err != nil {
		m.Close()
		return nil, client.Result{}, fmt.Errorf("openvpn: open TUN: %w", err)
	}
	result.TUNName = tun.Name()

	send := func(pkt []byte, _ *net.UDPAddr) {
		if _, werr := conn.Write(pkt); werr != nil {
			logger.Printf("openvpn: send: %v", werr)
		}
	}
	pump := dataplane.NewPump(tun, send, dataDemux, logger)
	// GSO bursts flush with one sendmmsg on the connected socket. This
	// BatchConn is the pump goroutine's own; the muxer read loop has another.
	sendBC := dataplane.NewBatchConn(conn)
	pump.SetBatchSender(func(pkts [][]byte, _ *net.UDPAddr) {
		if _, werr := sendBC.WriteBatch(pkts, nil); werr != nil {
			logger.Printf("openvpn: batch send: %v", werr)
		}
	})
	pump.SetInnerMTU(result.MTU)
	pump.AddTunnel(tunnel)
	m.setPump(pump)
	go pump.Run()

	s := &session{muxer: m, tun: tun, pump: pump, tunnel: tunnel, conn: conn, logger: logger, done: make(chan struct{})}
	go s.keepalive()

	logger.Printf("openvpn: tunnel up on %s, internal IP %s, peer %s", result.TUNName, result.AssignedIP, endpoint)
	return s, result, nil
}

// clientTLSConfig builds the mutual-TLS config: this client's certificate, and
// verification of the server certificate's chain to the CA. OpenVPN does not
// check the server's hostname by default, so neither does this — the CA is the
// trust anchor.
func clientTLSConfig(cfg *Config) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.CA) {
		return nil, errors.New("ca: no certificates parsed")
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		MinVersion:            tls.VersionTLS12,
		InsecureSkipVerify:    true, // hostname is not verified; the chain check below is
		VerifyPeerCertificate: verifyChainToCA(pool),
	}, nil
}

// verifyChainToCA verifies the server certificate chains to the CA, ignoring the
// hostname (which OpenVPN does not bind to the transport address).
func verifyChainToCA(pool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("server sent no certificate")
		}
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, raw := range rawCerts {
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			certs[i] = c
		}
		opts := x509.VerifyOptions{Roots: pool, Intermediates: x509.NewCertPool()}
		for _, c := range certs[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, err := certs[0].Verify(opts)
		return err
	}
}

// negotiate runs the post-connect handshake over the control channel: TLS, the
// key_method_2 exchange, key derivation, and the config pull. It returns the
// Result (minus the TUN name) and the built data tunnel.
func negotiate(ctx context.Context, cfg *Config, ch *control.Channel, tlsCfg *tls.Config, endpoint *net.UDPAddr, logger *log.Logger) (client.Result, *tunnel, error) {
	tlsConn := tls.Client(ch, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return client.Result{}, nil, fmt.Errorf("tls handshake: %w", err)
	}
	logger.Printf("openvpn: TLS established, negotiating keys")

	// Send our key material, then read the server's and derive data keys.
	clientKS, err := keys.NewClientKeySource()
	if err != nil {
		return client.Result{}, nil, err
	}
	if _, err := tlsConn.Write(clientKS.MarshalClient(occOptions(cfg), cfg.Username, cfg.Password, peerInfo(cfg))); err != nil {
		return client.Result{}, nil, fmt.Errorf("send key material: %w", err)
	}
	serverKS, _, err := readServerKeys(tlsConn)
	if err != nil {
		return client.Result{}, nil, fmt.Errorf("read server key material: %w", err)
	}

	clientSID := keys.SessionID(ch.LocalSessionID())
	remoteSID, _ := ch.RemoteSessionID()
	serverSID := keys.SessionID(remoteSID)
	ks2 := &keys.KeySource2{Client: *clientKS, Server: *serverKS}

	// Pull the pushed configuration.
	if _, err := tlsConn.Write([]byte("PUSH_REQUEST\x00")); err != nil {
		return client.Result{}, nil, fmt.Errorf("push request: %w", err)
	}
	reply, err := readPushReply(tlsConn)
	if err != nil {
		return client.Result{}, nil, fmt.Errorf("read push reply: %w", err)
	}
	logger.Printf("openvpn: server pushed %q", reply)

	pushed, err := parsePush(reply)
	if err != nil {
		return client.Result{}, nil, err
	}

	// The server's pushed cipher is authoritative under NCP; if it pushes none,
	// fall back to the configured cipher (an old server using its compiled --cipher).
	effectiveCipher := cfg.Cipher
	if pushed.cipher != "" {
		effectiveCipher = pushed.cipher
	}
	dc, err := buildDataCipher(effectiveCipher, cfg, ks2, clientSID, serverSID, pushed.peerID)
	if err != nil {
		return client.Result{}, nil, err
	}
	logger.Printf("openvpn: data channel cipher %s", effectiveCipher)
	tun := &tunnel{
		cipher: dc,
		routes: []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
	}
	tun.peer.Store(endpoint)

	res := client.Result{
		AssignedIP: pushed.localIP,
		Netmask:    pushed.netmask,
		// Gateway is the server's real transport IP: the client router pins a host
		// route to it via the physical gateway so the encapsulated packets do not
		// loop back into the tunnel. The pushed route-gateway is the tunnel's
		// internal address and must not be used here — it would collide with
		// in-tunnel destinations.
		Gateway: endpoint.IP,
		MTU:     pushed.mtu,
	}
	return res, tun, nil
}

// readServerKeys reads TLS bytes until a complete server key_method_2 message is
// present, then parses it.
func readServerKeys(tlsConn *tls.Conn) (*keys.KeySource, string, error) {
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(tmp)
		if err != nil {
			return nil, "", err
		}
		buf = append(buf, tmp[:n]...)
		ks, opts, perr := keys.ParseServer(buf)
		if perr == nil {
			return ks, opts, nil
		}
		if !errors.Is(perr, keys.ErrShortMessage) {
			return nil, "", perr
		}
		if len(buf) > 8192 {
			return nil, "", errors.New("server key message too long")
		}
	}
}

// readPushReply reads TLS bytes until a NUL-terminated control string arrives.
func readPushReply(tlsConn *tls.Conn) (string, error) {
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(tmp)
		if err != nil {
			return "", err
		}
		buf = append(buf, tmp[:n]...)
		if before, _, found := bytes.Cut(buf, []byte{0}); found {
			return string(before), nil
		}
		if len(buf) > 16384 {
			return "", errors.New("push reply too long")
		}
	}
}

// buildDataCipher constructs the data-channel crypto for the negotiated cipher,
// deriving the matching key material. The GCM path is the AEAD default; the CBC
// path derives an HMAC key of the --auth digest's size.
func buildDataCipher(name string, cfg *Config, ks2 *keys.KeySource2, clientSID, serverSID keys.SessionID, peerID uint32) (dataCipher, error) {
	switch {
	case strings.EqualFold(name, cipherGCM):
		dk := ks2.Derive(clientSID, serverSID, false)
		return data.New(dk, peerID, 0)
	case strings.EqualFold(name, cipherCBC):
		digest, err := tlswrap.ParseDigest(cfg.Auth)
		if err != nil {
			return nil, fmt.Errorf("cbc data channel: %w", err)
		}
		ck := ks2.DeriveCBC(clientSID, serverSID, false)
		return data.NewCBC(ck, digest.New, digest.Size, peerID, 0)
	default:
		return nil, fmt.Errorf("server negotiated unsupported cipher %q", name)
	}
}

// occOptions is the OCC options string. Without --opt-verify on the server it is
// advisory, so a plausible value suffices; the cipher and auth fields track the
// configured data channel.
func occOptions(cfg *Config) string {
	authName := "[null-digest]" // GCM authenticates within the AEAD
	if strings.EqualFold(cfg.Cipher, cipherCBC) {
		authName = strings.ToUpper(digestName(cfg.Auth))
	}
	return fmt.Sprintf("V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher %s,auth %s,keysize 256,key-method 2,tls-client",
		strings.ToUpper(cfg.Cipher), authName)
}

// peerInfo advertises this client's capabilities: P_DATA_V2 support (IV_PROTO
// bit 1) so the server assigns a peer-id, NCP, and the configured data cipher, so
// the server negotiates it.
func peerInfo(cfg *Config) string {
	return fmt.Sprintf("IV_VER=2.6.0\nIV_PROTO=2\nIV_NCP=2\nIV_CIPHERS=%s\n", strings.ToUpper(cfg.Cipher))
}

// digestName returns the --auth digest name, defaulting to SHA1 (OpenVPN's
// default) when unset.
func digestName(auth string) string {
	if auth == "" {
		return "SHA1"
	}
	return auth
}

// isTLSAuthError reports whether an error is a TLS certificate verification
// failure, so dial can map it to client.ErrAuth.
func isTLSAuthError(err error) bool {
	var ce *tls.CertificateVerificationError
	return errors.As(err, &ce)
}

// buildWrapper builds the control-channel protection from the config: --tls-crypt
// (encrypt + authenticate) takes precedence over --tls-auth (authenticate only),
// and neither yields a nil wrapper — the plain control channel.
func buildWrapper(cfg *Config) (control.Wrapper, error) {
	switch {
	case len(cfg.TLSCrypt) > 0:
		key, err := tlswrap.ParseStaticKey(cfg.TLSCrypt)
		if err != nil {
			return nil, fmt.Errorf("tls-crypt key: %w", err)
		}
		// tls-crypt's client direction is fixed: it sends with the second key slot
		// and receives with the first.
		return tlswrap.NewCrypt(key, tlswrap.Inverse)
	case len(cfg.TLSAuth) > 0:
		key, err := tlswrap.ParseStaticKey(cfg.TLSAuth)
		if err != nil {
			return nil, fmt.Errorf("tls-auth key: %w", err)
		}
		digest, err := tlswrap.ParseDigest(cfg.Auth)
		if err != nil {
			return nil, fmt.Errorf("tls-auth: %w", err)
		}
		return tlswrap.NewAuth(key, authDirection(cfg.KeyDirection), digest), nil
	default:
		return nil, nil
	}
}

// authDirection maps a --key-direction (0, 1, or -1 for unset) to the tlswrap
// direction the client sends and receives with.
func authDirection(keyDirection int) tlswrap.Direction {
	switch keyDirection {
	case 0:
		return tlswrap.Normal
	case 1:
		return tlswrap.Inverse
	default:
		return tlswrap.Bidirectional
	}
}

// dataDemux routes any data-channel packet to the client's single tunnel.
func dataDemux(pkt []byte) (uint32, bool) {
	op, _, ok := wire.Opcode(pkt)
	if !ok || !data.IsDataOpcode(op) {
		return 0, false
	}
	return dataTunnelKey, true
}
