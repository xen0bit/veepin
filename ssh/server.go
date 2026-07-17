package ssh

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/sshtun"
)

// ServerConfig configures an SSH VPN responder — an SSH server that accepts
// tun@openssh.com forwarding channels, the equivalent of a stock sshd with
// PermitTunnel yes but scoped to just the tunnel.
type ServerConfig struct {
	// HostKey is the server's private host key, PEM (required).
	HostKey []byte

	// ListenIP is the local address to bind on; empty binds all interfaces.
	ListenIP string
	// ListenPort is the TCP port to accept clients on (default 22).
	ListenPort int

	// Pool is the tunnel subnet in CIDR form (default 10.200.0.0/24); its first
	// host is the server's tunnel address, and clients use addresses within it.
	Pool string
	// DNS is informational (SSH assigns none in-band); reported on Network setup.
	DNS []net.IP

	// Users maps a username to a password for password authentication.
	Users map[string]string
	// AuthorizedKeys holds authorized public keys (authorized_keys lines) for
	// public-key authentication.
	AuthorizedKeys []string

	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string
	// Logger receives progress logs; nil discards them.
	Logger *log.Logger
}

func (c *ServerConfig) validate() error {
	if len(c.HostKey) == 0 {
		return errors.New("ssh: server host key is required")
	}
	if len(c.Users) == 0 && len(c.AuthorizedKeys) == 0 {
		return errors.New("ssh: at least one user or authorized key is required")
	}
	return nil
}

// Server is a running SSH VPN responder. Like SSTP it is connection-oriented: one
// TCP/SSH connection per client, all sharing one TUN, which is routed to each
// client by the inner address the server learns from that client's traffic. It
// owns the TUN but does not configure host networking.
type Server struct {
	sshCfg  *cryptossh.ServerConfig
	pool    *dataplane.AddrPool
	gateway net.IP
	network *net.IPNet
	logger  *log.Logger

	listenAddr *net.TCPAddr
	tun        *dataplane.TUN
	listener   net.Listener

	mu      sync.Mutex
	clients map[uint32]*sshClient // keyed by the client's learned inner address

	closeOnce sync.Once
	closed    chan struct{}
}

// NewServer builds a server from cfg: it parses the host key, authorized keys and
// pool, and opens the TUN. It does not bind until ListenAndServe. Opening a TUN
// requires CAP_NET_ADMIN.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	sshCfg, err := serverSSHConfig(&cfg)
	if err != nil {
		return nil, err
	}

	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = "10.200.0.0/24"
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("ssh: pool: %w", err)
	}

	port := cfg.ListenPort
	if port == 0 {
		port = 22
	}
	listenIP := net.ParseIP(cfg.ListenIP)
	if cfg.ListenIP == "" {
		listenIP = net.IPv4zero
	}
	if listenIP == nil {
		return nil, fmt.Errorf("ssh: invalid listen IP %q", cfg.ListenIP)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("ssh: open TUN: %w", err)
	}

	return &Server{
		sshCfg:     sshCfg,
		pool:       pool,
		gateway:    gateway,
		network:    pool.Network(),
		logger:     logger,
		listenAddr: &net.TCPAddr{IP: listenIP, Port: port},
		tun:        tun,
		clients:    make(map[uint32]*sshClient),
		closed:     make(chan struct{}),
	}, nil
}

// TUNName is the interface the data path is bound to.
func (s *Server) TUNName() string { return s.tun.Name() }

// Gateway is the server's own tunnel-side address (the pool's first host).
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet, for routing and NAT rules.
func (s *Server) Network() *net.IPNet { return s.network }

// ListenAndServe binds the TCP listener, starts the TUN read loop, and serves
// clients until Close. It blocks.
func (s *Server) ListenAndServe() error {
	ln, err := net.ListenTCP("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("ssh: listen: %w", err)
	}
	s.listener = ln
	s.logger.Printf("ssh: listening on %s, gateway %s", s.listenAddr, s.gateway)

	go s.tunLoop()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
				return fmt.Errorf("ssh: accept: %w", err)
			}
		}
		go s.handleConn(conn)
	}
}

// tunLoop reads packets off the TUN and routes each to the client that owns its
// destination address.
func (s *Server) tunLoop() {
	buf := make([]byte, 65535)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		dst, ok := ipv4Dst(buf[:n])
		if !ok {
			continue
		}
		s.mu.Lock()
		cl := s.clients[dst]
		s.mu.Unlock()
		if cl != nil {
			cl.write(buf[:n])
		}
	}
}

// handleConn runs the SSH handshake for one connection and serves its tunnel
// channel.
func (s *Server) handleConn(nc net.Conn) {
	defer nc.Close()
	sshConn, chans, reqs, err := cryptossh.NewServerConn(nc, s.sshCfg)
	if err != nil {
		s.logger.Printf("ssh: handshake from %s: %v", nc.RemoteAddr(), err)
		return
	}
	defer sshConn.Close()
	go cryptossh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != sshtun.ChannelType {
			_ = newCh.Reject(cryptossh.UnknownChannelType, "only tunnel forwarding is served")
			continue
		}
		if _, _, ok := sshtun.ParseOpenData(newCh.ExtraData()); !ok {
			_ = newCh.Reject(cryptossh.ConnectionFailed, "bad tunnel request")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go cryptossh.DiscardRequests(chReqs)
		s.serveTunnel(ch, sshConn.RemoteAddr())
	}
}

// serveTunnel forwards packets for one tunnel channel: it writes inbound packets
// to the TUN and registers the client by the source address it uses so the TUN
// loop can route replies back. It blocks until the channel closes.
func (s *Server) serveTunnel(ch cryptossh.Channel, remote net.Addr) {
	cl := &sshClient{ch: ch, srv: s}
	defer cl.close()

	for {
		pkt, err := sshtun.ReadPacket(ch)
		if err != nil {
			return
		}
		src, ok := ipv4Src(pkt)
		if !ok {
			continue
		}
		// Learn the client's address on first sight (and on change), accepting only
		// addresses within the pool that are not the gateway.
		if src != cl.ip {
			if !s.network.Contains(u32IP(src)) || src == binary.BigEndian.Uint32(s.gateway.To4()) {
				continue
			}
			s.rebind(cl, src, remote)
		}
		if _, err := s.tun.Write(pkt); err != nil {
			s.logger.Printf("ssh: TUN write: %v", err)
		}
	}
}

// rebind points the routing map at cl for address src.
func (s *Server) rebind(cl *sshClient, src uint32, remote net.Addr) {
	s.mu.Lock()
	if cl.ip != 0 {
		delete(s.clients, cl.ip)
	}
	cl.ip = src
	s.clients[src] = cl
	s.mu.Unlock()
	s.logger.Printf("ssh: client %s using %s", remote, u32IP(src))
}

// Close stops the server: the listener, the TUN, and every client channel.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.listener != nil {
			s.listener.Close()
		}
		s.mu.Lock()
		for _, cl := range s.clients {
			cl.ch.Close()
		}
		s.mu.Unlock()
		if s.tun != nil {
			s.tun.Close()
		}
	})
	return nil
}

// sshClient is one accepted client's tunnel channel and learned address.
type sshClient struct {
	ch      cryptossh.Channel
	srv     *Server
	writeMu sync.Mutex
	ip      uint32
}

// write frames an IP packet and sends it to the client, serialized against the
// channel's other writer.
func (c *sshClient) write(ipPacket []byte) {
	frame := sshtun.Encode(ipPacket)
	if frame == nil {
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, _ = c.ch.Write(frame)
}

func (c *sshClient) close() {
	c.ch.Close()
	if c.ip != 0 {
		c.srv.mu.Lock()
		if c.srv.clients[c.ip] == c {
			delete(c.srv.clients, c.ip)
		}
		c.srv.mu.Unlock()
	}
}

// serverSSHConfig builds the x/crypto/ssh server config: the host key and the
// password / public-key auth callbacks.
func serverSSHConfig(cfg *ServerConfig) (*cryptossh.ServerConfig, error) {
	signer, err := cryptossh.ParsePrivateKey(cfg.HostKey)
	if err != nil {
		return nil, fmt.Errorf("ssh: host key: %w", err)
	}

	authorized := map[string]bool{}
	for _, line := range cfg.AuthorizedKeys {
		if strings.TrimSpace(line) == "" {
			continue
		}
		pub, _, _, _, perr := cryptossh.ParseAuthorizedKey([]byte(line))
		if perr != nil {
			return nil, fmt.Errorf("ssh: authorized key: %w", perr)
		}
		authorized[string(pub.Marshal())] = true
	}

	sc := &cryptossh.ServerConfig{}
	if len(cfg.Users) > 0 {
		users := cfg.Users
		sc.PasswordCallback = func(conn cryptossh.ConnMetadata, pass []byte) (*cryptossh.Permissions, error) {
			if want, ok := users[conn.User()]; ok && subtleEqual(want, string(pass)) {
				return &cryptossh.Permissions{}, nil
			}
			return nil, fmt.Errorf("ssh: authentication failed")
		}
	}
	if len(authorized) > 0 {
		sc.PublicKeyCallback = func(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			if authorized[string(key.Marshal())] {
				return &cryptossh.Permissions{}, nil
			}
			return nil, fmt.Errorf("ssh: unauthorized key")
		}
	}
	sc.AddHostKey(signer)
	return sc, nil
}

// subtleEqual compares two strings in constant time.
func subtleEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ipv4Dst / ipv4Src return the destination / source address of an IPv4 packet.
func ipv4Dst(pkt []byte) (uint32, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[16:20]), true
}

func ipv4Src(pkt []byte) (uint32, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[12:16]), true
}

func u32IP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

// Server option keys for client.NewServer("ssh", opts).
const (
	OptServerHostKey        = "host-key"
	OptServerListenIP       = "listen"
	OptServerPort           = "port"
	OptServerPool           = "pool"
	OptServerDNS            = "dns"
	OptServerUser           = "user"
	OptServerPassword       = "password"
	OptServerAuthorizedKeys = "authorized-keys"
	OptServerTUN            = "tun"
)

func init() { client.RegisterServer("ssh", parseServerOptions) }

// parseServerOptions builds an SSH responder from string options.
func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		ListenIP: opts[OptServerListenIP],
		Pool:     opts[OptServerPool],
		TUNName:  opts[OptServerTUN],
		Users:    map[string]string{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
	var err error
	if cfg.HostKey, err = os.ReadFile(opts[OptServerHostKey]); err != nil {
		return nil, fmt.Errorf("ssh: host-key: %w", err)
	}
	if u := opts[OptServerUser]; u != "" {
		cfg.Users[u] = opts[OptServerPassword]
	}
	if path := opts[OptServerAuthorizedKeys]; path != "" {
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, fmt.Errorf("ssh: authorized-keys: %w", rerr)
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if strings.TrimSpace(line) != "" {
				cfg.AuthorizedKeys = append(cfg.AuthorizedKeys, line)
			}
		}
	}
	if v := opts[OptServerPort]; v != "" {
		p, perr := strconv.Atoi(v)
		if perr != nil {
			return nil, fmt.Errorf("ssh: invalid port %q", v)
		}
		cfg.ListenPort = p
	}
	cfg.DNS = parseIPList(opts[OptServerDNS])
	return NewServer(cfg)
}
