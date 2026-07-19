// Package nebula is the public entry point to this module's Nebula
// implementation: a mesh overlay in which every host is a peer, authenticated
// by a certificate its CA issued, and reachable either directly or through a
// lighthouse.
//
// Like every protocol here, Dial installs no addresses, routes or DNS. It
// returns the negotiated client.Result and the caller applies it — the veepin
// command hands it to dataplane's router, and the NetworkManager plugin hands it
// to NM.
//
// Importing this package registers "nebula" with the client registry, so a
// caller that dials by name only needs the blank import:
//
//	import _ "github.com/xen0bit/veepin/nebula"
//
//	sess, res, err := client.Dial(ctx, "nebula", opts)
//
// The protocol internals (the certificate format, the Noise handshake, the data
// path and the lighthouse protocol) live in internal/nebula; this package is the
// supported surface.
//
// # A different shape from the other protocols
//
// Nebula is the first mesh protocol in this tree, and it does not divide into a
// client and a server. Dial and NewServer both run the same engine; they differ
// only in whether the host answers lighthouse queries and whether it is expected
// to stay up. A host's address is not assigned by a peer — it is written into
// its certificate, so Result.AssignedIP is read from the certificate rather than
// negotiated.
//
// # Scope
//
// Version 1 certificates (protobuf, IPv4 overlay) and Curve25519 only. Current
// nebula still issues and accepts version 1; version 2 adds ASN.1 encoding and
// IPv6, and is a self-contained follow-up.
//
// Not implemented, deliberately rather than partially: the firewall/ACL engine
// (this build permits any traffic a certificate's addresses allow), relays
// (forwarding through a third host when hole punching fails), and
// multi-lighthouse consensus. Each surfaces as an absent feature, not as a
// silent misbehaviour: without the firewall a mesh is more permissive than
// nebula's default, which is stated here so it is not mistaken for parity.
package nebula

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	inebula "github.com/xen0bit/veepin/internal/nebula"
)

func init() { client.Register("nebula", parseOptions) }

// derivedMTU is what a 1500-octet ethernet path actually leaves for an inner
// packet: the path, less the outer IPv4 and UDP headers, less nebula's own
// header and AEAD tag. It works out to 1456.
const derivedMTU = dataplane.DefaultPathMTU - dataplane.OuterUDP4 - inebula.Overhead

// defaultMTU is nebula's own default, and it is deliberately well under
// derivedMTU. Upstream nebula ships 1300 so a tunnel survives paths that carry
// less than ethernet — PPPoE, or another tunnel underneath — without needing
// path MTU discovery to converge first. Since an MTU is only useful if the peer
// agrees with it, the conventional value wins here over the derived one.
//
// A previous comment on this constant claimed it was the derived figure. It
// never was; the arithmetic above is what that claim would have produced.
const defaultMTU = 1300

// Raising defaultMTU past what the wire format leaves room for would produce a
// tunnel that black-holes on an ordinary ethernet path. Declaring the slack as
// an unsigned constant makes that a compile error rather than a field report.
const _ uint = derivedMTU - defaultMTU

// defaultPort is the UDP port nebula listens on by default.
const defaultPort = 4242

// Option keys accepted by client.Dial(ctx, "nebula", opts).
const (
	OptCA           = "ca"            // path to the CA certificate bundle (PEM)
	OptCert         = "cert"          // path to this host's certificate (PEM)
	OptKey          = "key"           // path to this host's X25519 private key (PEM)
	OptListen       = "listen"        // local UDP address to bind, e.g. "0.0.0.0:4242"
	OptStaticHosts  = "static-hosts"  // "overlay=underlay[,underlay...];..." pairs
	OptLighthouses  = "lighthouses"   // comma-separated overlay addresses
	OptAmLighthouse = "am-lighthouse" // "true" to answer lighthouse queries
	OptCipher       = "cipher"        // "aes" (default) or "chachapoly"
	OptTUN          = "tun"           // TUN interface name
	OptMTU          = "mtu"           // inner MTU
)

// Config is the parsed form of the options above.
type Config struct {
	// CAPath is the PEM bundle of trusted certificate authorities.
	CAPath string
	// CertPath and KeyPath are this host's identity.
	CertPath string
	KeyPath  string

	// Listen is the local UDP address. Empty binds all addresses on the
	// default port.
	Listen string

	// StaticHosts maps an overlay address to underlay addresses. A mesh with no
	// lighthouse needs one entry per peer; with a lighthouse, only the
	// lighthouse itself needs one.
	StaticHosts map[netip.Addr][]netip.AddrPort

	// Lighthouses are the overlay addresses to query and report to.
	Lighthouses []netip.Addr

	// AmLighthouse makes this host answer queries about where others are.
	AmLighthouse bool

	// Cipher is "aes" (default) or "chachapoly". It must match the mesh.
	Cipher string

	// TUNName is the interface to open. Empty picks the next free one.
	TUNName string

	// MTU is the inner interface MTU. Zero uses defaultMTU.
	MTU int

	// Logger receives operational messages. Nil discards them.
	Logger *log.Logger
}

// Session is a running nebula host.
type Session struct {
	host *inebula.Host
	tun  *dataplane.TUN

	closeOnce sync.Once
	done      chan struct{}
}

// Dial starts a nebula host and returns it as a client session.
//
// Unlike the other protocols here there is no server to connect to: the host
// starts, and tunnels form as traffic and discovery require. Dial returns as
// soon as the host is running, because in a mesh there is no single peer whose
// reachability would make a useful readiness signal.
func Dial(ctx context.Context, cfg Config) (*Session, client.Result, error) {
	identity, pool, err := loadIdentity(cfg)
	if err != nil {
		return nil, client.Result{}, err
	}

	addr, ok := identity.Cert.Address()
	if !ok {
		return nil, client.Result{}, errors.New("nebula: certificate carries no overlay address")
	}
	network := identity.Cert.Networks[0]

	listen := cfg.Listen
	if listen == "" {
		listen = ":" + strconv.Itoa(defaultPort)
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("nebula: resolving listen address %q: %w", listen, err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("nebula: listening on %s: %w", listen, err)
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		_ = conn.Close()
		return nil, client.Result{}, fmt.Errorf("nebula: opening TUN: %w", err)
	}

	host, err := inebula.NewHost(&inebula.Config{
		Identity:     identity,
		CAs:          pool,
		Cipher:       cfg.Cipher,
		StaticHosts:  cfg.StaticHosts,
		Lighthouses:  cfg.Lighthouses,
		AmLighthouse: cfg.AmLighthouse,
		Logger:       loggerOrDiscard(cfg.Logger),
	}, dataplane.NewPacketConn(conn), tun)
	if err != nil {
		_ = conn.Close()
		_ = tun.Close()
		return nil, client.Result{}, err
	}

	host.Run()

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	sess := &Session{host: host, tun: tun, done: make(chan struct{})}
	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: net.IP(addr.AsSlice()),
		Netmask:    net.IP(net.CIDRMask(network.Bits(), 32)),
		// Gateway is deliberately nil. In the other protocols here it is the
		// server's outer address, and the caller pins a host route to it so the
		// encapsulated packets are not themselves routed into the tunnel. A
		// mesh has no such address: peers are reached directly, each at its own
		// underlay address, and there is no single one to pin. Reporting this
		// host's own overlay address instead would have the router install a
		// route sending our own address out the physical interface.
		//
		// What the caller does need -- the overlay prefix on the TUN -- comes
		// from AssignedIP and Netmask.
		MTU: mtu,
	}
	return sess, res, nil
}

// Wait blocks until the session is closed or the context is cancelled.
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return nil
	}
}

// Close stops the host and releases the socket and TUN.
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.host.Close()
		close(s.done)
	})
	return err
}

// Addr returns this host's overlay address.
func (s *Session) Addr() netip.Addr { return s.host.Addr() }

// loadIdentity reads the certificate, key and CA bundle from disk.
func loadIdentity(cfg Config) (*inebula.Identity, *inebula.CAPool, error) {
	if cfg.CAPath == "" || cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, nil, errors.New("nebula: ca, cert and key are all required")
	}

	caPEM, err := os.ReadFile(cfg.CAPath)
	if err != nil {
		return nil, nil, fmt.Errorf("nebula: reading CA bundle: %w", err)
	}
	pool, err := inebula.NewCAPoolFromPEM(caPEM)
	if err != nil {
		return nil, nil, err
	}

	certPEM, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("nebula: reading certificate: %w", err)
	}
	cert, _, err := inebula.UnmarshalCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("nebula: reading private key: %w", err)
	}
	raw, err := inebula.UnmarshalX25519PrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("nebula: private key is not a valid X25519 key: %w", err)
	}

	identity, err := inebula.NewIdentity(cert, key)
	if err != nil {
		return nil, nil, err
	}
	return identity, pool, nil
}

func loggerOrDiscard(l *log.Logger) inebula.Logger {
	if l == nil {
		return log.New(io.Discard, "", 0)
	}
	return l
}

// dialer adapts Config to the client registry.
type dialer struct{ cfg Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	sess, res, err := Dial(ctx, d.cfg)
	if err != nil {
		return nil, client.Result{}, err
	}
	return sess, res, nil
}

// parseOptions turns registry options into a Config.
func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := Config{
		CAPath:       opts[OptCA],
		CertPath:     opts[OptCert],
		KeyPath:      opts[OptKey],
		Listen:       opts[OptListen],
		Cipher:       opts[OptCipher],
		TUNName:      opts[OptTUN],
		AmLighthouse: opts[OptAmLighthouse] == "true",
		// A mesh host reports tunnels coming up, peers being rejected and
		// packets being dropped. None of that is visible any other way -- there
		// is no connect/disconnect moment to infer it from -- so a host dialed
		// through the registry logs to stdout, as the other protocols here do.
		Logger: log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}

	if v := opts[OptMTU]; v != "" {
		mtu, err := strconv.Atoi(v)
		if err != nil || mtu <= 0 {
			return nil, fmt.Errorf("nebula: invalid mtu %q", v)
		}
		cfg.MTU = mtu
	}

	if v := opts[OptLighthouses]; v != "" {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("nebula: invalid lighthouse address %q: %w", s, err)
			}
			cfg.Lighthouses = append(cfg.Lighthouses, addr)
		}
	}

	if v := opts[OptStaticHosts]; v != "" {
		hosts, err := ParseStaticHosts(v)
		if err != nil {
			return nil, err
		}
		cfg.StaticHosts = hosts
	}

	if cfg.Cipher != "" && cfg.Cipher != "aes" && cfg.Cipher != "chachapoly" {
		return nil, fmt.Errorf("nebula: unknown cipher %q (want aes or chachapoly)", cfg.Cipher)
	}

	return dialer{cfg}, nil
}

// resolveUnderlay turns one underlay entry into addresses. A literal address is
// used as given; a name is resolved, and every A record it yields becomes a
// candidate, which the handshake then probes in turn.
//
// Resolution happens once, at parse time. Nebula re-resolves periodically so a
// peer that moves behind a changing name is followed; veepin does not, so a
// static host named by DNS is pinned to wherever it was when the host started.
// That is a real limitation rather than an oversight -- it is stated here
// because the failure it produces (a peer that silently stops being reachable
// after a DNS change) is otherwise hard to attribute.
func resolveUnderlay(s string) ([]netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return []netip.AddrPort{ap}, nil
	}

	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("nebula: invalid underlay address %q: %w", s, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("nebula: invalid underlay port in %q: %w", s, err)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("nebula: resolving underlay address %q: %w", s, err)
	}

	var out []netip.AddrPort
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			// The overlay and the socket are both IPv4 here, so an AAAA record
			// is not usable; skipping is better than failing, since a name may
			// legitimately have both.
			continue
		}
		addr, ok := netip.AddrFromSlice(v4)
		if !ok {
			continue
		}
		out = append(out, netip.AddrPortFrom(addr, uint16(port)))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("nebula: %q resolved to no IPv4 addresses", s)
	}
	return out, nil
}

// ParseStaticHosts parses the static host map, in the form
//
//	10.42.0.1=192.0.2.10:4242,192.0.2.11:4242;10.42.0.2=198.51.100.4:4242
//
// Several underlay addresses may be given for one host: a handshake probes all
// of them, which is how a peer with both a public address and a LAN address is
// reached by whichever works.
func ParseStaticHosts(s string) (map[netip.Addr][]netip.AddrPort, error) {
	out := map[netip.Addr][]netip.AddrPort{}
	for _, entry := range strings.Split(s, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		overlay, underlay, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("nebula: static host %q is not overlay=underlay", entry)
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(overlay))
		if err != nil {
			return nil, fmt.Errorf("nebula: invalid overlay address %q: %w", overlay, err)
		}
		for _, u := range strings.Split(underlay, ",") {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			aps, err := resolveUnderlay(u)
			if err != nil {
				return nil, err
			}
			out[addr] = append(out[addr], aps...)
		}
		if len(out[addr]) == 0 {
			return nil, fmt.Errorf("nebula: static host %q names no underlay address", entry)
		}
	}
	return out, nil
}
