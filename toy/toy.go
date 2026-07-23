// Package toy is the public entry point to TOY, a deliberately insecure
// teaching protocol.
//
// # TOY provides no security
//
// This is not a caveat, it is the defining property. TOY "encrypts" with a
// 32-octet repeating XOR pad and "authenticates" with FNV-1a, a hash-table hash.
// Traffic it carries can be read and forged by anyone who can see it, with
// arithmetic rather than cryptanalysis. There is no key exchange, so recovering
// the shared secret later decrypts every session ever recorded.
//
// internal/toy/SPEC.md enumerates the failures individually. Do not use this to
// carry anything.
//
// # Why it exists
//
// veepin implements eight real protocols, each large enough that the *shape* of
// a protocol is buried under the details of the real thing. TOY is that shape
// with nothing else attached:
//
//   - Dial runs a handshake and returns a client.Result the caller applies;
//   - the data path is dataplane.Pump, driven by a Tunnel implementation that
//     is about forty lines;
//   - both roles register with the client registry, so `veepin connect toy` and
//     `veepin serve toy` work like every other protocol;
//   - the wire format is documented well enough that the interop harness talks
//     to an independent Python implementation of the spec.
//
// If you are adding a real protocol, read internal/toy in this order: SPEC.md,
// session.go (the Tunnel), client.go, server.go. Copy the structure. Replace
// every primitive.
//
// # Refusing to be deployed quietly
//
// Both roles log an unmissable warning on startup, every time, with no flag to
// silence it. That is deliberate: the failure mode this package could otherwise
// cause is someone finding it in a protocol list, seeing that it works, and
// shipping it.
package toy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	itoy "github.com/xen0bit/veepin/internal/toy"
)

func init() { client.Register("toy", parseOptions) }

// defaultMTU is derived rather than chosen: an ordinary ethernet path, less the
// outer IPv4 and UDP headers, less TOY's own header and tag. It comes to 1452.
//
// TOY is the protocol in this tree with no interoperability convention to
// honour — nothing else implements it — so unlike nebula and WireGuard there is
// no reason to ship anything but the exact figure. The comment here used to
// describe this arithmetic while the constant next to it said 1400, which is
// the kind of drift the derivation exists to prevent.
const defaultMTU = dataplane.DefaultPathMTU - dataplane.OuterUDP4 - itoy.Overhead

// Option keys accepted by client.Dial(ctx, "toy", opts).
const (
	OptServer = "server" // server host or IP (required)
	OptPort   = "port"   // server UDP port (default 5555)
	OptUser   = "user"   // identity presented in HELLO (required)
	OptSecret = "secret" // shared secret (required); protects nothing
	OptTUN    = "tun"    // TUN interface name
)

// Config is the parsed form of the options above.
type Config struct {
	// Server is the server host or IP.
	Server string
	// Port is the server's UDP port; zero means DefaultPort.
	Port int
	// User is the identity presented in HELLO.
	User string
	// Secret is the shared secret.
	//
	// Naming it "secret" rather than "key" or "password" is intentional: it is
	// not a key in any meaningful sense, and calling it one would overstate what
	// it does. See the package documentation.
	Secret string
	// TUNName is the interface to open; empty picks the next free one.
	TUNName string
	// Logger receives progress messages; nil discards them.
	Logger *log.Logger
}

// warning is printed by both roles on every startup.
//
// It is unconditional and there is no flag to suppress it. A quiet insecure
// protocol is a trap for whoever finds it next; a loud one is a teaching aid.
const warning = `
!!! ------------------------------------------------------------------- !!!
!!! TOY PROVIDES NO SECURITY WHATSOEVER.                                !!!
!!!                                                                     !!!
!!! It is an example protocol. Its "encryption" is a repeating XOR pad   !!!
!!! and its "authentication" is a hash-table hash. Anyone who can see    !!!
!!! this traffic can read and forge it. There is no key exchange, so a   !!!
!!! recorded session can be decrypted later from the shared secret.      !!!
!!!                                                                     !!!
!!! Use it to learn how a veepin protocol is put together. Never to      !!!
!!! carry traffic. See internal/toy/SPEC.md.                            !!!
!!! ------------------------------------------------------------------- !!!
`

// Warn prints the insecurity warning. Both roles call it before doing anything.
func Warn(logger *log.Logger) {
	if logger == nil {
		logger = log.New(os.Stderr, "", 0)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(warning), "\n") {
		logger.Print(line)
	}
}

// Session is a running TOY client.
type Session struct {
	client *itoy.Client
}

// Dial runs the TOY handshake and starts the data path.
//
// Like every protocol here it installs no addresses, routes or DNS: it returns
// the client.Result and the caller applies it.
func Dial(ctx context.Context, cfg Config) (*Session, client.Result, error) {
	logger := cfg.Logger
	Warn(logger)

	if cfg.Server == "" {
		return nil, client.Result{}, errors.New("toy: server is required")
	}
	if cfg.User == "" {
		return nil, client.Result{}, errors.New("toy: user is required")
	}
	if cfg.Secret == "" {
		return nil, client.Result{}, errors.New("toy: secret is required")
	}

	port := cfg.Port
	if port == 0 {
		port = itoy.DefaultPort
	}
	server, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(cfg.Server, strconv.Itoa(port)))
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("toy: resolving %s: %w", cfg.Server, err)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("toy: opening socket: %w", err)
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		_ = conn.Close()
		return nil, client.Result{}, fmt.Errorf("toy: opening TUN: %w", err)
	}

	c, err := itoy.StartClient(ctx, conn, tun, itoy.ClientConfig{
		Server: server,
		User:   cfg.User,
		Secret: cfg.Secret,
		Logger: logger,
	})
	if err != nil {
		_ = conn.Close()
		_ = tun.Close()
		return nil, client.Result{}, err
	}

	w := c.Welcome
	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: itoy.AddrToNetIP(w.AssignedIP),
		Netmask:    itoy.AddrToNetIP(w.Netmask),
		// Result.Gateway is the server's *outer* address, not the inner gateway
		// WELCOME carries. The caller pins a host route to it through the
		// physical interface so that encapsulated packets are not themselves
		// routed into the tunnel.
		//
		// Getting this wrong is silent and total: filling in the inner gateway
		// (10.9.0.1) installs a route sending the very address the tunnel exists
		// to reach out over ethernet, and every ping leaves by the wrong door.
		// The inner gateway needs no route of its own — AssignedIP and Netmask
		// already put it on the connected subnet.
		Gateway: server.IP,
		MTU:     int(w.MTU),
	}
	for _, d := range w.DNS {
		res.DNS = append(res.DNS, itoy.AddrToNetIP(d))
	}
	return &Session{client: c}, res, nil
}

// Wait blocks until the session ends or the context is cancelled.
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.client.Done():
		return nil
	}
}

// Close tears the session down.
func (s *Session) Close() error { return s.client.Close() }

// Probe implements client.Prober. TOY's peer sends a KEEPALIVE every
// KeepaliveInterval, so a stretch of authenticated silence far longer than that
// means the peer is gone. This is the passive, pump-level liveness signal
// (dataplane.Pump.IdleFor) rather than an active round-trip — appropriate for a
// protocol whose peer keeps the path warm on its own.
func (s *Session) Probe(_ context.Context) error {
	if idle := s.client.IdleFor(); idle > toyLivenessDeadline {
		return fmt.Errorf("toy: no authenticated packet for %v", idle.Round(time.Second))
	}
	return nil
}

// LivenessConfig implements client.LivenessTuner: probe on the keepalive cadence
// and declare death only after several silent intervals (toyLivenessDeadline).
func (s *Session) LivenessConfig() client.LivenessConfig {
	return client.LivenessConfig{Interval: itoy.KeepaliveInterval, MaxFailures: 2}
}

// toyLivenessDeadline is how much authenticated silence means the peer is gone:
// several KEEPALIVE intervals, tolerant of a couple of dropped keepalives.
var toyLivenessDeadline = 4 * itoy.KeepaliveInterval

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
		Server:  opts[OptServer],
		User:    opts[OptUser],
		Secret:  opts[OptSecret],
		TUNName: opts[OptTUN],
		Logger:  log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("toy: invalid port %q", v)
		}
		cfg.Port = p
	}
	if cfg.Server == "" {
		return nil, errors.New("toy: server is required")
	}
	if cfg.User == "" {
		return nil, errors.New("toy: user is required")
	}
	if cfg.Secret == "" {
		return nil, errors.New("toy: secret is required")
	}
	return dialer{cfg}, nil
}
