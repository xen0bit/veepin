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
// The implementation lives in internal/wireguard: the client session and the
// server engine there, and the message codec, the handshake and the transport
// crypto beneath them. This package is the supported surface -- options,
// wg-quick files, validation -- and turns them into the engine's decoded
// configuration.
//
// This package provides both roles: Dial is the initiator (below), and Server
// (see server.go) is the multi-peer responder that `veepin serve wireguard`
// runs.
//
// # Scope
//
// A client rekeys: it re-runs the handshake every two minutes and rotates the
// fresh keypair in, so a tunnel stays up indefinitely rather than going quiet at
// the key's rejection age (~180s). Rekey is client-initiated only — the server
// answers new initiations but does not start its own — which is a deliberate
// boundary rather than a silent gap: an idle peer that never rekeys surfaces as
// an absent handshake. Both roles take part in the cookie exchange a loaded
// server uses to make a flood cost it nothing (internal/wireguard/cookie.go).
package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/vlog"
	iwg "github.com/xen0bit/veepin/internal/wireguard"
	"github.com/xen0bit/veepin/internal/wireguard/noise"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

func init() { client.Register("wireguard", parseOptions) }

// ObfuscationConfig is AmneziaWG's wire transform, the engine's own type under
// its public name: both roles' configs carry it, and amneziawg fills it.
type ObfuscationConfig = iwg.ObfuscationConfig

// DefaultCookieThreshold is the handshake rate a server takes before it is
// under load and demands cookies; see ServerConfig.CookieThreshold.
const DefaultCookieThreshold = iwg.DefaultCookieThreshold

// Default inner MTU, derived rather than asserted. WireGuard's conventional
// 1420 is exactly a 1500-octet path less the *IPv6* outer header, the UDP
// header, and WireGuard's own transport framing — the larger of the two IP
// families, so one MTU is safe over either. That is why every WireGuard
// implementation ships the same slightly-conservative number, and computing it
// here says so rather than leaving 1420 to look arbitrary.
//
// Config.MTU overrides it.
const defaultMTU = dataplane.DefaultPathMTU - dataplane.OuterUDP6 - wire.Overhead

// Option keys accepted by client.Dial(ctx, "wireguard", opts). OptConfig points
// at a wg-quick file; the rest override individual fields, so the CLI can take a
// file, a set of flags, or both.
const (
	OptConfig       = "config"               // path to a wg-quick config file
	OptPrivateKey   = "private-key"          // our static private key, base64
	OptAddress      = "address"              // our tunnel address(es), CIDR
	OptDNS          = "dns"                  // DNS servers
	OptMTU          = "mtu"                  // inner MTU
	OptListenPort   = "listen-port"          // local UDP port to bind (0 = ephemeral)
	OptRekeySeconds = "rekey-seconds"        // client rekey interval (0 = default)
	OptPublicKey    = "public-key"           // peer static public key, base64
	OptPresharedKey = "preshared-key"        // optional preshared key, base64
	OptEndpoint     = "endpoint"             // peer host:port
	OptAllowedIPs   = "allowed-ips"          // inner destinations for the peer
	OptKeepalive    = "persistent-keepalive" // keepalive seconds
	OptTUNName      = "tun"                  // desired TUN interface name
	OptShape        = "shape"                // per-flow shaping budget in bytes (0 = off)
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

// Validate reports whether a Config has everything a dial needs, running the
// same checks parseOptions runs and discarding what they build.
//
// It is exported for amneziawg, which fills this exact struct from its own
// option map and had no way to reach resolve(). The result was that its four
// Required flags claimed something nothing enforced: an entirely empty
// amneziawg profile saved and listed cleanly and failed only at dial.
func (c *Config) Validate() error {
	_, err := c.resolve()
	return err
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
	address    netip.Prefix   // our tunnel address
	address6   netip.Prefix   // our tunnel IPv6 address; zero when there is none
	allowedIPs []netip.Prefix // routed to the peer
	dns        []net.IP
	mtu        int
	tunName    string
	keepalive  time.Duration
	rekey      time.Duration // how often to re-run the handshake
	listenPort int           // local UDP port to bind; 0 lets the kernel pick
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

	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return nil, fmt.Errorf("%s %d out of range", OptListenPort, c.ListenPort)
	}
	r := &resolved{
		noiseCfg:   noise.Config{LocalStatic: priv, RemoteStatic: pub},
		mtu:        c.MTU,
		tunName:    c.TUNName,
		listenPort: c.ListenPort,
	}
	if peer.PresharedKey != "" {
		psk, err := decodeKey(peer.PresharedKey, OptPresharedKey)
		if err != nil {
			return nil, err
		}
		r.noiseCfg.PresharedKey = psk
	}
	// mac1 is computed over the message type, so the noise layer needs H1/H2
	// rather than having them stamped on afterwards by the obfuscation layer.
	r.noiseCfg.TypeInitiation = c.Obfuscation.TypeInitiation
	r.noiseCfg.TypeResponse = c.Obfuscation.TypeResponse
	if r.mtu == 0 {
		r.mtu = defaultMTU
	}
	if peer.Keepalive > 0 {
		r.keepalive = time.Duration(peer.Keepalive) * time.Second
	}
	r.rekey = iwg.RekeyAfterTime
	if c.RekeySeconds > 0 {
		r.rekey = time.Duration(c.RekeySeconds) * time.Second
	}

	// wg-quick's Address line is a list, and a dual-stack interface writes both
	// families on it. Taking addrs[0] and dropping the rest meant a config
	// naming `10.0.0.2/24, fd00::2/64` came up IPv4-only with nothing said —
	// the v6 address was parsed, validated, and thrown away.
	addrs, err := prefixes(c.Address)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", OptAddress, err)
	}
	if r.address, r.address6, err = splitPrefixFamilies(addrs); err != nil {
		return nil, fmt.Errorf("%s: %w", OptAddress, err)
	}

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
	logger := vlog.From(cfg.Logger)

	s, err := iwg.Dial(ctx, iwg.ClientConfig{
		Noise:       r.noiseCfg,
		Endpoint:    r.endpoint,
		ListenPort:  r.listenPort,
		AllowedIPs:  r.allowedIPs,
		MTU:         r.mtu,
		TUNName:     r.tunName,
		Keepalive:   r.keepalive,
		Rekey:       r.rekey,
		Obfuscation: cfg.Obfuscation,
		Shape:       cfg.Shape,
		Logger:      logger,
	})
	if err != nil {
		if errors.Is(err, noise.ErrDecrypt) {
			return nil, client.Result{}, fmt.Errorf("wireguard: %w: %w", client.ErrAuth, err)
		}
		return nil, client.Result{}, err
	}

	out := client.Result{
		TUNName: s.TUNName(),
		Gateway: r.endpoint.IP,
		DNS:     r.dns,
		MTU:     r.mtu,
	}
	if r.address.IsValid() {
		out.AssignedIP = net.IP(r.address.Addr().AsSlice())
		out.Netmask = prefixNetmask(r.address)
	}
	if r.address6.IsValid() {
		out.AssignedIP6 = net.IP(r.address6.Addr().AsSlice())
		out.Prefix6 = r.address6.Bits()
	}
	logger.Printf("wireguard: tunnel up on %s, internal IP %s%s, peer %s",
		out.TUNName, addrOrNone(out.AssignedIP), also(out.AssignedIP6), r.endpoint)
	return s, out, nil
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

// splitPrefixFamilies sorts a wg-quick Address list into its IPv4 and IPv6
// entry. Either may be absent — a v6-only tunnel is legitimate — but a second
// address of the same family is an error rather than a silent choice, because
// the caller installs exactly one per family and quietly ignoring the rest is
// how a config that looks right stops working.
func splitPrefixFamilies(addrs []netip.Prefix) (v4, v6 netip.Prefix, err error) {
	for _, a := range addrs {
		slot := &v6
		family := "IPv6"
		if a.Addr().Is4() {
			slot, family = &v4, "IPv4"
		}
		if slot.IsValid() {
			return netip.Prefix{}, netip.Prefix{},
				fmt.Errorf("two %s addresses (%s and %s); an interface takes one per family", family, *slot, a)
		}
		*slot = a
	}
	if !v4.IsValid() && !v6.IsValid() {
		return netip.Prefix{}, netip.Prefix{}, errors.New("no address")
	}
	return v4, v6, nil
}

// addrOrNone and also render the two families for one log line without
// printing "<nil>" for the half a single-stack tunnel does not have.
func addrOrNone(ip net.IP) string {
	if ip == nil {
		return "none"
	}
	return ip.String()
}

func also(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return " + " + ip.String()
}

// prefixNetmask returns the IPv4 netmask of a prefix as a net.IP, for the
// Result the client router applies.
func prefixNetmask(p netip.Prefix) net.IP {
	return net.IP(net.CIDRMask(p.Bits(), p.Addr().BitLen()))
}
