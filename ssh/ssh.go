// Package ssh is the public entry point for using SSH as a VPN: it forwards IP
// over OpenSSH's layer-3 tunnel channel ("tun@openssh.com", what `ssh -w` opens
// under a server's PermitTunnel), over a userspace TUN.
//
// Like every protocol here, Dial installs no addresses, routes or DNS. SSH tunnel
// forwarding carries no address configuration in-band, so the client's tunnel
// address is static (from Config, as the reference sshvpn script sets it by hand)
// and returned in the Result for the caller to apply.
//
// Importing this package registers "ssh" with the client registry:
//
//	import _ "github.com/xen0bit/veepin/ssh"
//	sess, res, err := client.Dial(ctx, "ssh", opts)
//
// It uses golang.org/x/crypto/ssh — already this module's only dependency — so it
// interoperates with a stock sshd (PermitTunnel yes) as a client, and with a
// stock `ssh -w` client as a server (see server.go).
package ssh

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/sshtun"
)

func init() { client.Register("ssh", parseOptions) }

// Option names for client.Dial.
const (
	OptServer     = "server"
	OptPort       = "port"
	OptUser       = "user"
	OptIdentity   = "identity" // path to a private key
	OptPassword   = "password"
	OptKnownHosts = "known-hosts"
	OptInsecure   = "insecure"  // skip host-key verification
	OptAddress    = "address"   // client tunnel address in CIDR form, e.g. 10.200.0.2/30
	OptPeer       = "peer"      // server tunnel address (point-to-point peer)
	OptPeerUnit   = "peer-unit" // remote tun unit to request (default: any)
	OptDNS        = "dns"
	OptTUNName    = "tun"
)

const dialTimeout = 30 * time.Second

// Config holds the parameters for a single SSH VPN tunnel.
type Config struct {
	Server   string
	Port     int
	User     string
	Identity string // path to a private key (optional if Password set)
	Password string // password auth (optional)

	KnownHosts string // path to a known_hosts file (optional)
	Insecure   bool   // skip host-key verification

	// Address is the client's own tunnel address in CIDR form (e.g.
	// "10.200.0.2/30"), assigned statically since SSH negotiates none.
	Address string
	// Peer is the server's tunnel address (the point-to-point gateway).
	Peer string
	// PeerUnit is the remote tun unit to request (matching `ssh -w local:PeerUnit`).
	// A negative value requests SSH_TUNID_ANY, letting the server choose — right
	// for the veepin server (which ignores it) but a stock sshd needs a specific
	// unit so it binds the pre-created device.
	PeerUnit int
	DNS      []net.IP

	TUNName string
	Logger  *log.Logger
}

func (c *Config) validate() error {
	switch {
	case c.Server == "":
		return fmt.Errorf("ssh: server is required")
	case c.User == "":
		return fmt.Errorf("ssh: user is required")
	case c.Address == "":
		return fmt.Errorf("ssh: address is required (SSH assigns none)")
	case c.Identity == "" && c.Password == "":
		return fmt.Errorf("ssh: an identity or password is required")
	}
	return nil
}

func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := &Config{
		Server:     opts[OptServer],
		User:       opts[OptUser],
		Identity:   opts[OptIdentity],
		Password:   opts[OptPassword],
		KnownHosts: opts[OptKnownHosts],
		Insecure:   opts[OptInsecure] == "true",
		Address:    opts[OptAddress],
		Peer:       opts[OptPeer],
		PeerUnit:   -1,
		TUNName:    opts[OptTUNName],
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("ssh: invalid port %q", v)
		}
		cfg.Port = p
	}
	if v := opts[OptPeerUnit]; v != "" {
		u, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("ssh: invalid peer-unit %q", v)
		}
		cfg.PeerUnit = u
	}
	cfg.DNS = parseIPList(opts[OptDNS])
	return dialer{cfg}, cfg.validate()
}

type dialer struct{ cfg *Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, *d.cfg)
}

// Dial connects to the SSH server, opens the tunnel-forwarding channel, brings up
// a TUN, and starts forwarding IP. It returns a running session and the Result
// (built from the static Config) the caller must apply.
func Dial(ctx context.Context, cfg Config) (client.Session, client.Result, error) {
	if err := cfg.validate(); err != nil {
		return nil, client.Result{}, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	assignedIP, netmask, err := parseCIDR(cfg.Address)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("ssh: address: %w", err)
	}

	clientCfg, err := clientConfig(&cfg)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("ssh: %w", err)
	}

	port := cfg.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(cfg.Server, strconv.Itoa(port))

	conn, err := dialContext(ctx, addr, clientCfg)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("ssh: dial %s: %w", addr, err)
	}

	unit := uint32(sshtun.TunIDAny)
	if cfg.PeerUnit >= 0 {
		unit = uint32(cfg.PeerUnit)
	}
	ch, reqs, err := conn.OpenChannel(sshtun.ChannelType,
		sshtun.OpenData(sshtun.ModePointToPoint, unit))
	if err != nil {
		conn.Close()
		return nil, client.Result{}, fmt.Errorf("ssh: open tunnel channel (is PermitTunnel enabled?): %w", err)
	}
	go cryptossh.DiscardRequests(reqs)

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		ch.Close()
		conn.Close()
		return nil, client.Result{}, fmt.Errorf("ssh: open TUN: %w", err)
	}

	s := &session{conn: conn, ch: ch, tun: tun, logger: logger, done: make(chan struct{})}
	go s.tunToChannel()
	go s.channelToTUN()

	serverIP := transportIP(conn)
	logger.Printf("ssh: tunnel up on %s, address %s, peer %s", tun.Name(), assignedIP, cfg.Peer)

	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: assignedIP,
		Netmask:    netmask,
		// Gateway is the SSH server's transport IP: the router pins a host route to
		// it so the TCP carrier does not recurse into the tunnel.
		Gateway: serverIP,
		DNS:     cfg.DNS,
		MTU:     client.DefaultTunnelMTU,
	}
	return s, res, nil
}

// dialContext dials the SSH server, honoring ctx for the connection setup.
func dialContext(ctx context.Context, addr string, cfg *cryptossh.ClientConfig) (*cryptossh.Client, error) {
	d := net.Dialer{Timeout: dialTimeout}
	netConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	sshConn, chans, reqs, err := cryptossh.NewClientConn(netConn, addr, cfg)
	if err != nil {
		netConn.Close()
		return nil, err
	}
	return cryptossh.NewClient(sshConn, chans, reqs), nil
}

// clientConfig builds the x/crypto/ssh client config: the auth methods and the
// host-key policy.
func clientConfig(cfg *Config) (*cryptossh.ClientConfig, error) {
	var auth []cryptossh.AuthMethod
	if cfg.Identity != "" {
		key, err := os.ReadFile(cfg.Identity)
		if err != nil {
			return nil, fmt.Errorf("identity: %w", err)
		}
		signer, err := cryptossh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("identity: %w", err)
		}
		auth = append(auth, cryptossh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		auth = append(auth, cryptossh.Password(cfg.Password))
	}

	hostKey, err := hostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}
	return &cryptossh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: hostKey,
		Timeout:         dialTimeout,
	}, nil
}

// transportIP returns the SSH server's IP from the established connection, used
// as the off-tunnel host-route target.
func transportIP(conn *cryptossh.Client) net.IP {
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return tcp.IP
	}
	return nil
}

// session is a running SSH VPN tunnel. It implements client.Session.
type session struct {
	conn   *cryptossh.Client
	ch     cryptossh.Channel
	tun    *dataplane.TUN
	logger *log.Logger

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}
}

// tunToChannel forwards packets from the TUN to the SSH tunnel channel.
func (s *session) tunToChannel() {
	buf := make([]byte, 65535)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			s.fail(fmt.Errorf("ssh: TUN read: %w", err))
			return
		}
		frame := sshtun.Encode(buf[:n])
		if frame == nil {
			continue // not IPv4/IPv6
		}
		if _, err := s.ch.Write(frame); err != nil {
			s.fail(fmt.Errorf("ssh: channel write: %w", err))
			return
		}
	}
}

// channelToTUN forwards packets from the SSH tunnel channel to the TUN.
func (s *session) channelToTUN() {
	for {
		pkt, err := sshtun.ReadPacket(s.ch)
		if err != nil {
			s.fail(fmt.Errorf("ssh: channel read: %w", err))
			return
		}
		if _, err := s.tun.Write(pkt); err != nil {
			s.logger.Printf("ssh: TUN write: %v", err)
		}
	}
}

func (s *session) fail(err error) {
	s.closeOnce.Do(func() {
		s.closeErr = err
		close(s.done)
		s.ch.Close()
		s.tun.Close()
		s.conn.Close()
	})
}

func (s *session) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *session) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.ch.Close()
		s.tun.Close()
		s.conn.Close()
	})
	return s.closeErr
}

func parseIPList(list string) []net.IP {
	var out []net.IP
	for _, s := range splitComma(list) {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
