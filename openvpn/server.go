package openvpn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/openvpn/control"
	"github.com/xen0bit/veepin/internal/openvpn/data"
	"github.com/xen0bit/veepin/internal/openvpn/keys"
	"github.com/xen0bit/veepin/internal/openvpn/wire"
)

// ServerConfig configures an OpenVPN responder and its userspace data path. It
// mirrors the client's certificate-authenticated, AES-256-GCM profile: mutual
// TLS against a shared CA, key method 2, and P_DATA_V2 with server-assigned
// peer-ids.
type ServerConfig struct {
	// CA, Cert, Key are PEM: the CA that client certificates must chain to, and
	// the server's own certificate and private key (all required).
	CA   []byte
	Cert []byte
	Key  []byte

	// ListenIP is the local address to bind the UDP socket on; empty binds all.
	ListenIP string
	// ListenPort is the UDP port to accept clients on (default 1194).
	ListenPort int

	// Pool is the internal address pool handed to clients in CIDR form (default
	// 10.8.0.0/24). Its first host is the server's tunnel address.
	Pool string
	// DNS servers pushed to clients.
	DNS []net.IP
	// MTU pushed to clients as tun-mtu (0 uses the default).
	MTU int

	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string
	// Logger receives progress logs; nil discards them.
	Logger *log.Logger
}

func (c *ServerConfig) validate() error {
	switch {
	case len(c.CA) == 0:
		return errors.New("openvpn: server CA is required")
	case len(c.Cert) == 0 || len(c.Key) == 0:
		return errors.New("openvpn: server certificate and key are required")
	}
	return nil
}

// Server is a running OpenVPN responder: one UDP socket serving many clients, a
// TUN device, an address pool, and the shared data-path pump. It owns the TUN but
// does not configure host networking — Gateway and Network report what a caller
// needs to do that itself.
type Server struct {
	tlsCfg  *tls.Config
	pool    *dataplane.AddrPool
	gateway net.IP
	dns     []net.IP
	mtu     int
	logger  *log.Logger
	gate    *dataplane.Gate

	listenAddr *net.UDPAddr
	tun        *dataplane.TUN
	conn       *dataplane.PacketConn
	pump       *dataplane.Pump

	nextPeerID atomic.Uint32

	mu      sync.Mutex
	clients map[string]*serverClient

	closeOnce sync.Once
	closed    chan struct{}
}

// NewServer builds a server from cfg: it parses the certificates and pool and
// opens the TUN device. It does not bind the socket until ListenAndServe. Opening
// a TUN device requires CAP_NET_ADMIN.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	tlsCfg, err := serverTLSConfig(&cfg)
	if err != nil {
		return nil, fmt.Errorf("openvpn: %w", err)
	}

	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = "10.8.0.0/24"
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("openvpn: pool: %w", err)
	}

	port := cfg.ListenPort
	if port == 0 {
		port = 1194
	}
	listenIP := net.ParseIP(cfg.ListenIP)
	if cfg.ListenIP == "" {
		listenIP = net.IPv4zero
	}
	if listenIP == nil {
		return nil, fmt.Errorf("openvpn: invalid listen IP %q", cfg.ListenIP)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	// GSO: the kernel may hand the pump TCP super-frames to segment and batch
	// (doc/scaling-the-data-path.md); falls back to a plain TUN transparently.
	tun, err := dataplane.OpenTUNGSO(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("openvpn: open TUN: %w", err)
	}

	return &Server{
		tlsCfg:     tlsCfg,
		gate:       dataplane.NewGate(dataplane.AdmissionConfig{}),
		pool:       pool,
		gateway:    gateway,
		dns:        cfg.DNS,
		mtu:        mtu,
		logger:     logger,
		listenAddr: &net.UDPAddr{IP: listenIP, Port: port},
		tun:        tun,
		clients:    make(map[string]*serverClient),
		closed:     make(chan struct{}),
	}, nil
}

// TUNName is the interface the data path is bound to.
func (s *Server) TUNName() string { return s.tun.Name() }

// Gateway is the server's own tunnel-side address (the pool's first host).
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet, for routing and NAT rules.
func (s *Server) Network() *net.IPNet { return s.pool.Network() }

// ListenAndServe binds the UDP socket, starts the data path, and serves clients
// until Close. It blocks.
func (s *Server) ListenAndServe() error {
	conn, err := net.ListenUDP("udp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("openvpn: listen: %w", err)
	}
	s.conn = dataplane.NewPacketConn(conn)

	// The pump routes TUN packets to a client tunnel by destination /32, and sends
	// each encapsulated packet to that tunnel's current peer address; inbound data
	// packets are demuxed by their P_DATA_V2 peer-id.
	send := func(pkt []byte, to *net.UDPAddr) {
		if to == nil {
			return
		}
		if _, werr := conn.WriteToUDP(pkt, to); werr != nil {
			s.logger.Printf("openvpn: send to %s: %v", to, werr)
		}
	}
	s.pump = dataplane.NewPump(s.tun, send, serverDataDemux, s.logger)
	// GSO bursts flush with one sendmmsg, source-pinned like every send.
	s.pump.SetBatchSender(func(pkts [][]byte, to *net.UDPAddr) {
		if to == nil {
			return
		}
		if _, werr := s.conn.WriteBatch(pkts, to); werr != nil {
			s.logger.Printf("openvpn: batch send to %s: %v", to, werr)
		}
	})
	s.pump.SetInnerMTU(s.mtu)
	go s.pump.Run()

	s.logger.Printf("openvpn: listening on %s, gateway %s", s.listenAddr, s.gateway)
	s.readLoop()
	return nil
}

// readLoop reads datagrams from every client on the shared socket and dispatches
// each by opcode: data packets to the pump, control packets to the owning (or a
// new) client session. Reads are batched (dataplane.PacketConn.ReadBatch): one
// recvmmsg drains up to readBatch datagrams under load and blocks like a plain
// read when idle.
func (s *Server) readLoop() {
	const readBatch = 16
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	froms := make([]*net.UDPAddr, readBatch)
	for {
		n, err := s.conn.ReadBatch(bufs, sizes, froms)
		for i := range n {
			pkt, from := bufs[i][:sizes[i]], froms[i]
			op, keyID, ok := wire.Opcode(pkt)
			if !ok {
				continue
			}
			switch {
			case data.IsDataOpcode(op):
				// No copy: the pump decrypts in place and writes the TUN before
				// returning; bufs[i] is not touched again until the next
				// ReadBatch.
				s.pump.HandleInbound(pkt, from)
			case wire.IsControl(op):
				// Copied out: control handling queues the packet to the owning
				// session, beyond this batch's buffers.
				s.handleControl(op, keyID, append([]byte(nil), pkt...), from)
			}
		}
		if err != nil {
			return // socket closed
		}
	}
}

// handleControl routes a control datagram to its client session, creating one
// when a new client opens with a hard reset.
func (s *Server) handleControl(op, keyID uint8, pkt []byte, from *net.UDPAddr) {
	key := from.String()
	s.mu.Lock()
	cl, exists := s.clients[key]
	if !exists {
		if op != wire.PControlHardResetClientV2 {
			s.mu.Unlock()
			return // not a known session and not a new-connection opener
		}
		// A new session means a TLS handshake and the key exchange behind it,
		// all for an unauthenticated peer on a spoofable UDP source.
		if r := s.gate.Admit(from); r != dataplane.Admitted {
			s.mu.Unlock()
			s.logger.Printf("openvpn: refusing new client %s: %v", from, r)
			return
		}
		cl, err := s.newClient(from, keyID)
		if err != nil {
			s.gate.Done()
			s.mu.Unlock()
			s.logger.Printf("openvpn: client %s: %v", from, err)
			return
		}
		s.clients[key] = cl
		s.mu.Unlock()
		cl.ch.Deliver(pkt)
		go func() {
			// The reservation is held for the whole handshake, which is the
			// expensive part; once it returns the client is either established
			// or gone.
			defer s.gate.Done()
			s.handshake(cl)
		}()
		return
	}
	s.mu.Unlock()
	cl.ch.Deliver(pkt)
}

// newClient builds the control channel for a freshly-seen client. Its send
// closure targets the client's current address on the shared socket.
func (s *Server) newClient(from *net.UDPAddr, keyID uint8) (*serverClient, error) {
	dst := *from
	send := func(b []byte) error {
		_, err := s.conn.WriteToUDP(b, &dst)
		return err
	}
	ch, err := control.NewServer(send, keyID, controlTimeout, nil)
	if err != nil {
		return nil, fmt.Errorf("control channel: %w", err)
	}
	return &serverClient{ch: ch, addr: from, keyID: keyID}, nil
}

// handshake runs the server side of the post-reset negotiation for one client:
// TLS, the key_method_2 exchange, and the config push, then installs the client's
// data tunnel in the pump.
func (s *Server) handshake(cl *serverClient) {
	deadline := time.Now().Add(handshakeTimeout)
	_ = cl.ch.SetDeadline(deadline)

	tlsConn := tls.Server(cl.ch, s.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		s.dropClient(cl, fmt.Sprintf("TLS handshake: %v", err))
		return
	}
	s.logger.Printf("openvpn: client %s TLS established, reading keys", cl.addr)

	hello, err := readClientKeys(tlsConn)
	if err != nil {
		s.dropClient(cl, fmt.Sprintf("read client keys: %v", err))
		return
	}

	serverKS, err := keys.NewServerKeySource()
	if err != nil {
		s.dropClient(cl, err.Error())
		return
	}
	if _, err := tlsConn.Write(serverKS.MarshalServer(s.occOptions())); err != nil {
		s.dropClient(cl, fmt.Sprintf("send server keys: %v", err))
		return
	}

	if err := readPushRequest(tlsConn); err != nil {
		s.dropClient(cl, fmt.Sprintf("await push request: %v", err))
		return
	}

	ip, err := s.pool.Allocate()
	if err != nil {
		s.dropClient(cl, fmt.Sprintf("allocate address: %v", err))
		return
	}
	peerID := s.nextPeerID.Add(1)

	// Derive the AES-256-GCM data keys as the server (the reverse direction of the
	// client), and build the cipher tagged with the peer-id we just assigned.
	remoteSID, _ := cl.ch.RemoteSessionID()
	clientSID := keys.SessionID(remoteSID)
	serverSID := keys.SessionID(cl.ch.LocalSessionID())
	ks2 := &keys.KeySource2{Client: hello.KeySource, Server: *serverKS}
	dk := ks2.Derive(clientSID, serverSID, true)
	cipher, err := data.New(dk, peerID, cl.keyID)
	if err != nil {
		s.pool.Release(ip)
		s.dropClient(cl, fmt.Sprintf("data cipher: %v", err))
		return
	}

	if _, err := tlsConn.Write(s.buildPushReply(ip, peerID)); err != nil {
		s.pool.Release(ip)
		s.dropClient(cl, fmt.Sprintf("send push reply: %v", err))
		return
	}
	_ = cl.ch.SetDeadline(time.Time{})

	ipAddr, _ := netip.AddrFromSlice(ip.To4())
	tun := &serverTunnel{
		cipher: cipher,
		peerID: peerID,
		routes: []netip.Prefix{netip.PrefixFrom(ipAddr, 32)},
	}
	tun.peer.Store(cl.addr)

	cl.tunnel = tun
	cl.assignedIP = ip
	s.pump.AddTunnel(tun)

	s.logger.Printf("openvpn: client %s up, assigned %s (peer-id %d)", cl.addr, ip, peerID)
	go s.keepalive(cl)
}

// keepalive sends a data-channel ping to the client on an interval, so an idle
// tunnel is not torn down by the ping-restart timer pushed to the client.
func (s *Server) keepalive(cl *serverClient) {
	tick := time.NewTicker(keepaliveInterval)
	defer tick.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-cl.ch.Closed():
			return
		case <-tick.C:
			pkt, err := cl.tunnel.cipher.Seal(data.Ping)
			if err != nil {
				return
			}
			if to := cl.tunnel.PeerAddr(); to != nil {
				_, _ = s.conn.WriteToUDP(pkt, to)
			}
		}
	}
}

// dropClient tears down a half-open client after a handshake failure.
func (s *Server) dropClient(cl *serverClient, reason string) {
	s.logger.Printf("openvpn: client %s dropped: %s", cl.addr, reason)
	cl.ch.Close()
	s.mu.Lock()
	delete(s.clients, cl.addr.String())
	s.mu.Unlock()
}

// occOptions is the server's advisory OCC options string, matching the client's
// AES-256-GCM profile from the responder side.
func (s *Server) occOptions() string {
	return "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"
}

// buildPushReply constructs the NUL-terminated PUSH_REPLY: the subnet-topology
// address assignment, the tunnel gateway, the negotiated cipher and peer-id, the
// keepalive timers, and any DNS servers.
func (s *Server) buildPushReply(ip net.IP, peerID uint32) []byte {
	var b strings.Builder
	b.WriteString("PUSH_REPLY")
	fmt.Fprintf(&b, ",route-gateway %s", s.gateway)
	b.WriteString(",topology subnet")
	b.WriteString(",ping 10,ping-restart 60")
	fmt.Fprintf(&b, ",ifconfig %s %s", ip, s.pool.Netmask())
	for _, d := range s.dns {
		fmt.Fprintf(&b, ",dhcp-option DNS %s", d)
	}
	fmt.Fprintf(&b, ",tun-mtu %d", s.mtu)
	b.WriteString(",cipher AES-256-GCM")
	fmt.Fprintf(&b, ",peer-id %d", peerID)
	return append([]byte(b.String()), 0)
}

// Close stops the server: the socket, the pump, and the TUN. It is idempotent.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.pump != nil {
			s.pump.Close()
		}
		if s.conn != nil {
			s.conn.Close()
		}
		if s.tun != nil {
			s.tun.Close()
		}
	})
	return nil
}

// serverClient is one accepted client's control-channel state plus, once up, its
// data tunnel and assignment.
type serverClient struct {
	ch    *control.Channel
	addr  *net.UDPAddr
	keyID uint8

	tunnel     *serverTunnel
	assignedIP net.IP
}

// serverTunnel is the data-path view of one client, implementing dataplane.Tunnel:
// TUN packets destined to its /32 are sealed to it, and its inbound data packets
// are opened (dropping keepalive pings).
type serverTunnel struct {
	cipher *data.Cipher
	peerID uint32
	routes []netip.Prefix
	peer   atomic.Pointer[net.UDPAddr]
}

func (t *serverTunnel) InboundKey() uint32                   { return t.peerID }
func (t *serverTunnel) Routes() []netip.Prefix               { return t.routes }
func (t *serverTunnel) PeerAddr() *net.UDPAddr               { return t.peer.Load() }
func (t *serverTunnel) Encapsulate(p []byte) ([]byte, error) { return t.cipher.Seal(p) }

func (t *serverTunnel) Decapsulate(pkt []byte) ([]byte, error) {
	pt, err := t.cipher.Open(pkt)
	if err != nil {
		return nil, err
	}
	if data.IsPing(pt) {
		return nil, nil // keepalive: authenticated but nothing to deliver
	}
	return pt, nil
}

// serverTLSConfig builds the mutual-TLS config for the responder: the server's
// certificate, and RequireAndVerifyClientCert against the CA (OpenVPN's trust
// model is the shared CA, not hostnames).
func serverTLSConfig(cfg *ServerConfig) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.CA) {
		return nil, errors.New("ca: no certificates parsed")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// Cap at TLS 1.2: OpenVPN runs TLS over its own reliable control channel,
		// and TLS 1.3's post-handshake NewSessionTicket messages do not fit that
		// half-duplex request/response model cleanly, stalling some clients before
		// they send key_method_2.
		MaxVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	}, nil
}

// readClientKeys reads TLS bytes until a complete client key_method_2 message is
// present, then parses it.
func readClientKeys(tlsConn *tls.Conn) (*keys.ClientHello, error) {
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(tmp)
		if err != nil {
			return nil, err
		}
		buf = append(buf, tmp[:n]...)
		h, perr := keys.ParseClient(buf)
		if perr == nil {
			return h, nil
		}
		if !errors.Is(perr, keys.ErrShortMessage) {
			return nil, perr
		}
		if len(buf) > 8192 {
			return nil, errors.New("client key message too long")
		}
	}
}

// readPushRequest reads TLS control strings until a PUSH_REQUEST arrives, so a
// client that repeats it (until it gets a reply) is handled.
func readPushRequest(tlsConn *tls.Conn) error {
	buf := make([]byte, 0, 128)
	tmp := make([]byte, 512)
	for {
		n, err := tlsConn.Read(tmp)
		if err != nil {
			return err
		}
		buf = append(buf, tmp[:n]...)
		for {
			i := indexByte(buf, 0)
			if i < 0 {
				break
			}
			msg := string(buf[:i])
			buf = buf[i+1:]
			if strings.HasPrefix(msg, "PUSH_REQUEST") {
				return nil
			}
			// Ignore other control strings (e.g. an early OCC exchange).
		}
		if len(buf) > 4096 {
			return errors.New("push request not seen")
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// Server option keys for client.NewServer("openvpn", opts).
const (
	OptServerCA         = "ca"
	OptServerCert       = "cert"
	OptServerKey        = "key"
	OptServerListenIP   = "listen"
	OptServerListenPort = "port"
	OptServerPool       = "pool"
	OptServerDNS        = "dns"
	OptServerTUN        = "tun"
)

// serverDataDemux extracts the P_DATA_V2 peer-id (bytes 1..3) as the pump's
// inbound key, so each client's packets route to the tunnel keyed by the peer-id
// the server assigned it. P_DATA_V1 (no peer-id) is not accepted.
func serverDataDemux(pkt []byte) (uint32, bool) {
	op, _, ok := wire.Opcode(pkt)
	if !ok || op != wire.PDataV2 || len(pkt) < 4 {
		return 0, false
	}
	return uint32(pkt[1])<<16 | uint32(pkt[2])<<8 | uint32(pkt[3]), true
}

func init() { client.RegisterServer("openvpn", parseServerOptions) }

// parseServerOptions builds an OpenVPN responder from string options, reading the
// CA/cert/key from the paths given.
func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		ListenIP: opts[OptServerListenIP],
		Pool:     opts[OptServerPool],
		TUNName:  opts[OptServerTUN],
		Logger:   log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
	var err error
	if cfg.CA, err = readFileOpt(opts[OptServerCA]); err != nil {
		return nil, fmt.Errorf("openvpn: ca: %w", err)
	}
	if cfg.Cert, err = readFileOpt(opts[OptServerCert]); err != nil {
		return nil, fmt.Errorf("openvpn: cert: %w", err)
	}
	if cfg.Key, err = readFileOpt(opts[OptServerKey]); err != nil {
		return nil, fmt.Errorf("openvpn: key: %w", err)
	}
	if v := opts[OptServerListenPort]; v != "" {
		p, perr := parsePort(v)
		if perr != nil {
			return nil, perr
		}
		cfg.ListenPort = p
	}
	cfg.DNS = append(cfg.DNS, splitCommaIPs(opts[OptServerDNS])...)
	return NewServer(cfg)
}

func readFileOpt(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("required")
	}
	return os.ReadFile(path)
}

func parsePort(v string) (int, error) {
	var p int
	if _, err := fmt.Sscanf(v, "%d", &p); err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("openvpn: invalid port %q", v)
	}
	return p, nil
}

func splitCommaIPs(list string) []net.IP {
	var out []net.IP
	for s := range strings.SplitSeq(list, ",") {
		if s = strings.TrimSpace(s); s != "" {
			if ip := net.ParseIP(s); ip != nil {
				out = append(out, ip)
			}
		}
	}
	return out
}
