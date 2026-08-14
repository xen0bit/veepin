package wireguard

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/wireguard/noise"
	"github.com/xen0bit/veepin/internal/wireguard/transport"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// keySize is the length of a Curve25519 key, matching what decodeKey returns.
const keySize = 32

// ServerConfig configures a WireGuard responder and its userspace data path.
type ServerConfig struct {
	// PrivateKey is the server's static private key, base64 (required).
	PrivateKey string
	// ListenPort is the UDP port to accept handshakes on (required).
	ListenPort int
	// ListenIP is the local address to bind on; empty binds all interfaces.
	ListenIP string
	// Address is the server's own tunnel address in CIDR form, e.g.
	// "10.10.0.1/24" (required). Its host is the gateway; its network is used
	// for routing and NAT.
	Address string
	// MTU is the inner-interface MTU (0 uses the default).
	MTU int

	// Peers are the clients this server accepts, each keyed by its static public
	// key (required: a server with no peers accepts no one).
	Peers []ServerPeer

	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string
	// Logger receives progress logs; nil discards them.
	// Obfuscation, if non-zero enables DPI-resistant wire-format transforms
	// (AmneziaWG-style). Zero values reproduce stock WireGuard on the wire.
	Obfuscation ObfuscationConfig

	// Shape enables downstream traffic shaping: how much padded output each
	// inner flow is given before shaping stops for that flow, so it bounds what
	// shaping costs. A flow gets Shape/MTU padded packets whatever sizes it
	// carries. Zero, the default, disables it.
	//
	// It hides the size pattern of an inner TLS handshake, which otherwise
	// survives encapsulation (see dataplane/shape.go). Peers need no support
	// for it — WireGuard's inner packet delimits itself, so the filler is inert
	// to any conforming receiver, the official clients included.
	// dataplane.DefaultShapeBytes is a reasonable value.
	Shape int

	Logger *log.Logger
}

// ServerPeer is one client the server will accept: its static public key, the
// inner addresses it may use, and an optional preshared key. The JSON tags are
// the on-disk shape of the OptServerPeers option: the management plane appends
// a peer to that array when it provisions a client config, and the parse below
// reads the same shape back.
type ServerPeer struct {
	PublicKey    string   `json:"public-key"`              // the client's static public key, base64 (required)
	PresharedKey string   `json:"preshared-key,omitempty"` // optional symmetric key, base64
	AllowedIPs   []string `json:"allowed-ips"`             // inner destinations routed to and accepted from this peer
}

// Server option keys for client.NewServer("wireguard", opts).
const (
	OptServerConfig           = "config"             // wg-quick server config file (interface + peers)
	OptServerPrivateKey       = "private-key"        // server static private key, base64
	OptServerListenIP         = "listen"             // local IP to bind the UDP socket on
	OptServerListenPort       = "listen-port"        // UDP port to listen on (default 51820)
	OptServerAddress          = "address"            // server tunnel address, CIDR
	OptServerMTU              = "mtu"                // inner MTU
	OptServerTUN              = "tun"                // TUN interface name (empty = kernel picks)
	OptServerPeerPublicKey    = "peer-public-key"    // a single peer's static public key, base64
	OptServerPeerPresharedKey = "peer-preshared-key" // that peer's preshared key, base64 (optional)
	OptServerPeerAllowedIPs   = "peer-allowed-ips"   // that peer's allowed IPs, comma-separated CIDRs
	OptServerPeers            = "peers"              // additional peers as a JSON array of ServerPeer
	OptServerShape            = "shape"              // per-flow downstream shaping budget in bytes (0 = off)
)

func init() {
	client.RegisterServer("wireguard", parseServerOptions)
	client.RegisterServerOpts("wireguard", []client.OptSpec{
		// Neither the private key nor the address is Required, despite both being
		// mandatory for a working server: a wg-quick file supplied via
		// OptServerConfig carries them, and parseServerOptions accepts that. A
		// spec marked Required makes the panel refuse a form that a config file
		// would have completed. AmneziaWG, which reuses this Server type and the
		// same parse, marks neither -- the two must agree.
		{Key: OptServerConfig, Kind: client.OptFilePath, Help: "wg-quick server config file (interface + peers)"},
		{Key: OptServerPrivateKey, Kind: client.OptStr, Secret: true, Generate: "wg-keypair", Help: "server static private key, base64 (required unless in -config)"},
		{Key: OptServerListenIP, Kind: client.OptStr, Default: "0.0.0.0", Help: "local IP to bind the UDP socket on (default 0.0.0.0)"},
		{Key: OptServerListenPort, Kind: client.OptInt, Default: "51820", Help: "UDP port to listen on (default 51820)"},
		{Key: OptServerAddress, Kind: client.OptCIDR, Help: "server tunnel address in CIDR form (required unless in -config)"},
		{Key: OptServerMTU, Kind: client.OptInt, Default: "1420", Help: "inner MTU (default 1420)"},
		client.TUNOpt(OptServerTUN),
		{Key: OptServerPeerPublicKey, Kind: client.OptStr, Help: "a single peer's static public key, base64"},
		{Key: OptServerPeerPresharedKey, Kind: client.OptStr, Secret: true, Help: "the -peer-public-key peer's preshared key, base64 (optional)"},
		{Key: OptServerPeerAllowedIPs, Kind: client.OptCommaList, Help: "the -peer-public-key peer's allowed IPs, comma-separated CIDRs"},
		// OptStr, not OptCommaList: the value is a JSON document, and a
		// comma-list editor in the panel would split it on the commas inside it.
		{Key: OptServerPeers, Kind: client.OptStr, Help: "additional peers as a JSON array, e.g. [{\"public-key\":\"...\",\"allowed-ips\":[\"10.0.0.2/32\"]}] (managed by client-config generation)"},
		client.ShapeOpt(OptServerShape, "downstream"),
	})
}

// parseServerOptions builds a WireGuard responder from string options, the
// server-side counterpart of parseOptions. Peers come from a wg-quick -config
// file; a single peer can also be supplied with the peer-* options for a quick
// server without a file.
// ServerConfigFromOptions builds a ServerConfig from the CLI option map. It is
// exported because AmneziaWG is WireGuard with a perturbed wire format and
// needs precisely this surface plus its obfuscation parameters; duplicating the
// parse there is how the two drift apart.
func ServerConfigFromOptions(opts map[string]string) (ServerConfig, error) {
	var sc ServerConfig
	if path := opts[OptServerConfig]; path != "" {
		parsed, err := ParseConfigFile(path)
		if err != nil {
			return sc, err
		}
		if sc, err = ServerConfigFromFile(parsed); err != nil {
			return sc, err
		}
	}
	if v := opts[OptServerPrivateKey]; v != "" {
		sc.PrivateKey = v
	}
	if v := opts[OptServerAddress]; v != "" {
		sc.Address = v
	}
	if v := opts[OptServerListenPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return sc, fmt.Errorf("wireguard: invalid %s %q", OptServerListenPort, v)
		}
		sc.ListenPort = p
	}
	if sc.ListenPort == 0 {
		sc.ListenPort = 51820
	}
	if v := opts[OptServerMTU]; v != "" {
		m, err := strconv.Atoi(v)
		if err != nil {
			return sc, fmt.Errorf("wireguard: invalid %s %q", OptServerMTU, v)
		}
		sc.MTU = m
	}
	if v := opts[OptServerTUN]; v != "" {
		sc.TUNName = v
	}
	if v := opts[OptServerShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return sc, fmt.Errorf("wireguard: invalid %s %q", OptServerShape, v)
		}
		sc.Shape = n
	}
	if v := opts[OptServerPeerPublicKey]; v != "" {
		sc.Peers = append(sc.Peers, ServerPeer{
			PublicKey:    v,
			PresharedKey: opts[OptServerPeerPresharedKey],
			AllowedIPs:   SplitList(opts[OptServerPeerAllowedIPs]),
		})
	}
	// The management plane appends provisioned clients here as a JSON array; a
	// wg-quick -config file's peers (above) and these merge, so a listener can
	// mix a static file with dynamically provisioned clients.
	if v := opts[OptServerPeers]; v != "" {
		var extra []ServerPeer
		if err := json.Unmarshal([]byte(v), &extra); err != nil {
			return sc, fmt.Errorf("wireguard: invalid %s JSON: %w", OptServerPeers, err)
		}
		sc.Peers = append(sc.Peers, extra...)
	}
	sc.ListenIP = opts[OptServerListenIP]
	sc.Logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	return sc, nil
}

func parseServerOptions(opts map[string]string) (client.Server, error) {
	sc, err := ServerConfigFromOptions(opts)
	if err != nil {
		return nil, err
	}
	return NewServer(sc)
}

// ServerConfigFromFile builds a ServerConfig from a parsed wg-quick file: the
// [Interface] is the server, and each [Peer] is a client. It is how the CLI
// turns `-config wg0.conf` into a server.
func ServerConfigFromFile(cfg *Config) (ServerConfig, error) {
	if len(cfg.Address) == 0 {
		return ServerConfig{}, fmt.Errorf("%s is required", OptAddress)
	}
	sc := ServerConfig{
		PrivateKey: cfg.PrivateKey,
		ListenPort: cfg.ListenPort,
		Address:    cfg.Address[0],
		MTU:        cfg.MTU,
		TUNName:    cfg.TUNName,
		Logger:     cfg.Logger,
	}
	for _, p := range cfg.Peers {
		sc.Peers = append(sc.Peers, ServerPeer{
			PublicKey:    p.PublicKey,
			PresharedKey: p.PresharedKey,
			AllowedIPs:   p.AllowedIPs,
		})
	}
	return sc, nil
}

// serverPeer is a configured client plus its live session state. Only the
// server's single read loop mutates lastTS and tunnel, so they need no lock of
// their own.
type serverPeer struct {
	pubKey     [keySize]byte
	psk        [keySize]byte
	allowedIPs []netip.Prefix

	lastTS [wire.TimestampLen]byte // newest handshake timestamp, for replay rejection
	tunnel *wgTunnel               // current session, nil until the first handshake
}

// Server is a running WireGuard responder: a UDP socket, a TUN device, the
// transport pump, and the set of peers it accepts. It owns the TUN but does not
// configure host networking — Gateway and Network report what a caller needs to
// do that itself.
type Server struct {
	localStatic [keySize]byte
	listenAddr  *net.UDPAddr
	mtu         int
	shape       int // per-flow downstream shaping budget; 0 disables it
	gateway     net.IP
	network     *net.IPNet
	obfCfg      ObfuscationConfig // AmneziaWG wire obfuscation (zero = stock)

	logger *log.Logger
	tun    *dataplane.TUN
	// gate bounds unauthenticated handshake work; see internal admission notes.
	gate *dataplane.Gate

	mu    sync.Mutex
	peers map[[keySize]byte]*serverPeer

	conn *dataplane.PacketConn
	pump *dataplane.Pump

	closeOnce sync.Once
	closeErr  error
	closed    chan struct{}
}

// NewServer builds a server from cfg: it decodes keys, parses the address and
// peers, and opens the TUN device. It does not bind the socket until
// ListenAndServe. Opening a TUN device requires CAP_NET_ADMIN.
func NewServer(cfg ServerConfig) (*Server, error) {
	priv, err := decodeKey(cfg.PrivateKey, OptPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf("wireguard: %s %d out of range", OptListenPort, cfg.ListenPort)
	}
	if cfg.Address == "" {
		return nil, fmt.Errorf("wireguard: %s is required", OptAddress)
	}
	gwAddr, network, err := parseCIDR(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %s: %w", OptAddress, err)
	}
	if len(cfg.Peers) == 0 {
		return nil, errors.New("wireguard: a server needs at least one peer")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	peers, err := resolvePeers(cfg.Peers)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}

	// GSO: the kernel may hand the pump TCP super-frames to segment and batch
	// (doc/scaling-the-data-path.md); falls back to a plain TUN transparently.
	tun, err := dataplane.OpenTUNGSO(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("wireguard: open TUN: %w", err)
	}

	return &Server{
		localStatic: priv,
		listenAddr:  &net.UDPAddr{IP: net.ParseIP(cfg.ListenIP), Port: cfg.ListenPort},
		obfCfg:      cfg.Obfuscation,
		mtu:         mtu,
		shape:       cfg.Shape,
		gateway:     gwAddr,
		network:     network,
		logger:      logger,
		tun:         tun,
		gate:        dataplane.NewGate(dataplane.AdmissionConfig{}),
		peers:       peers,
		closed:      make(chan struct{}),
	}, nil
}

// resolvePeers decodes the configured peers into the runtime map keyed by static
// public key.
func resolvePeers(cfgPeers []ServerPeer) (map[[keySize]byte]*serverPeer, error) {
	peers := make(map[[keySize]byte]*serverPeer, len(cfgPeers))
	for i, p := range cfgPeers {
		pub, err := decodeKey(p.PublicKey, OptPublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %d: %w", i, err)
		}
		if _, dup := peers[pub]; dup {
			return nil, fmt.Errorf("peer %d: duplicate %s", i, OptPublicKey)
		}
		sp := &serverPeer{pubKey: pub}
		if p.PresharedKey != "" {
			psk, err := decodeKey(p.PresharedKey, OptPresharedKey)
			if err != nil {
				return nil, fmt.Errorf("peer %d: %w", i, err)
			}
			sp.psk = psk
		}
		if len(p.AllowedIPs) == 0 {
			return nil, fmt.Errorf("peer %d: %s is required", i, OptAllowedIPs)
		}
		sp.allowedIPs, err = prefixes(p.AllowedIPs)
		if err != nil {
			return nil, fmt.Errorf("peer %d: %s: %w", i, OptAllowedIPs, err)
		}
		peers[pub] = sp
	}
	return peers, nil
}

// TUNName is the interface the data path is bound to.
func (s *Server) TUNName() string { return s.tun.Name() }

// Gateway is the server's own tunnel-side address.
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet, for routing and NAT rules.
func (s *Server) Network() *net.IPNet { return s.network }

// MTU is the recommended inner-interface MTU.
func (s *Server) MTU() int { return s.mtu }

// ListenAndServe binds the UDP socket, starts the data path, and serves
// handshakes and transport traffic until Close. It blocks.
func (s *Server) ListenAndServe() error {
	conn, err := net.ListenUDP("udp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("wireguard: listen %s: %w", s.listenAddr, err)
	}
	s.conn = dataplane.NewPacketConn(conn)

	// Unconnected socket: each send addresses a specific peer, so the pump's send
	// uses the tunnel's current PeerAddr.
	send := func(pkt []byte, to *net.UDPAddr) {
		if to == nil {
			return
		}
		pkt = obfuscateSend(pkt, s.obfCfg)
		if _, werr := conn.WriteToUDP(pkt, to); werr != nil {
			s.logger.Printf("wireguard: send to %s: %v", to, werr)
		}
	}
	s.pump = dataplane.NewPump(s.tun, send, wire.Demux, s.logger)
	// GSO bursts flush with one sendmmsg, source-pinned like every send.
	s.pump.SetBatchSender(func(pkts [][]byte, to *net.UDPAddr) {
		if to == nil {
			return
		}
		for i := range pkts {
			pkts[i] = obfuscateSend(pkts[i], s.obfCfg)
		}
		if _, werr := s.conn.WriteBatch(pkts, to); werr != nil {
			s.logger.Printf("wireguard: batch send to %s: %v", to, werr)
		}
	})
	if s.shape > 0 {
		s.pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: s.shape}))
		s.logger.Printf("wireguard: downstream shaping on, %d bytes per flow", s.shape)
	}
	// Oversized inner packets are answered with ICMP rather than dropped, so a
	// client learns the tunnel MTU instead of black-holing.
	s.pump.SetInnerMTU(s.mtu)
	go s.pump.Run()

	s.logger.Printf("wireguard: serving on %s, gateway %s, %d peer(s)",
		conn.LocalAddr(), s.gateway, len(s.peers))
	s.readLoop()
	return nil
}

// readLoop dispatches inbound datagrams: initiations to the handshake, transport
// data to the pump, everything else dropped. It runs until the socket closes.
// Reads are batched (dataplane.PacketConn.ReadBatch): one recvmmsg drains up to
// readBatch datagrams under load and blocks like a plain read when idle, so
// batching adds no latency to a quiet tunnel.
func (s *Server) readLoop() {
	const readBatch = 16
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	froms := make([]*net.UDPAddr, readBatch)
	data := make([][]byte, 0, readBatch)
	dataFroms := make([]*net.UDPAddr, 0, readBatch)
	for {
		n, err := s.conn.ReadBatch(bufs, sizes, froms)
		data, dataFroms = data[:0], dataFroms[:0]
		for i := range n {
			pkt, from := bufs[i][:sizes[i]], froms[i]
			pkt = deobfuscateRecv(pkt, s.obfCfg)
			if pkt == nil {
				continue
			}
			typ, ok := wire.Type(pkt)
			if !ok {
				continue
			}
			switch typ {
			case wire.TypeHandshakeInitiation:
				// Copied out: handshake handling should not be trusted with a
				// buffer the next batch will overwrite.
				s.handleInitiation(append([]byte(nil), pkt...), from)
			case wire.TypeTransportData:
				// Collected without a copy: the whole batch goes to the pump
				// at once so inbound TCP can coalesce (GRO); the pump decrypts
				// in place, updates each peer's return address from its source
				// (so a roaming client's replies follow it), and writes the
				// TUN before returning — bufs[i] is not touched again until
				// the next ReadBatch.
				data = append(data, pkt)
				dataFroms = append(dataFroms, from)
			default:
				// Handshake responses and cookie replies are the initiator's to send,
				// not to receive; drop them.
			}
		}
		if len(data) > 0 {
			s.pump.HandleInboundBatch(data, dataFroms)
		}
		if err != nil {
			return // socket closed on Close
		}
	}
}

// handleInitiation runs the responder handshake for one initiation and, on
// success, installs the peer's transport session in the pump.
func (s *Server) handleInitiation(pkt []byte, from *net.UDPAddr) {
	// A handshake initiation costs the responder two DH operations and the
	// keypair state that follows, all for a peer that has proved nothing at an
	// address that is spoofable. WireGuard's own answer is the cookie reply
	// under load (which veepin does not implement, so a peer under pressure
	// sees a refused handshake rather than a cookie); this bounds the cost in
	// the meantime.
	//
	// The reservation covers only the initiation: by the time this returns the
	// work is done and the session, if any, is authenticated.
	if r := s.gate.Admit(from); r != dataplane.Admitted {
		s.logger.Printf("wireguard: refusing initiation from %s: %v", from, r)
		return
	}
	defer s.gate.Done()

	r, err := noise.NewResponderWithTypes(s.localStatic, s.obfCfg.TypeInitiation, s.obfCfg.TypeResponse)
	if err != nil {
		s.logger.Printf("wireguard: responder: %v", err)
		return
	}
	peerStatic, ts, err := r.Consume(pkt)
	if err != nil {
		// ErrMAC1 means the packet was not addressed to us — common noise on an
		// open port, not worth logging loudly.
		if !errors.Is(err, noise.ErrMAC1) {
			s.logger.Printf("wireguard: rejecting initiation from %s: %v", from, err)
		}
		return
	}

	s.mu.Lock()
	peer := s.peers[peerStatic]
	if peer == nil {
		s.mu.Unlock()
		s.logger.Printf("wireguard: initiation from unknown peer %s (%s)", shortKey(peerStatic), from)
		return
	}
	// Reject a replayed or stale initiation: its timestamp must advance.
	if peer.lastTS != ([wire.TimestampLen]byte{}) && !wire.After(ts, peer.lastTS) {
		s.mu.Unlock()
		s.logger.Printf("wireguard: replayed initiation from %s", shortKey(peerStatic))
		return
	}

	respPkt, kp, err := r.Response(peer.psk)
	if err != nil {
		s.mu.Unlock()
		s.logger.Printf("wireguard: building response for %s: %v", shortKey(peerStatic), err)
		return
	}
	sess, err := transport.NewSession(kp.Send, kp.Recv, kp.Local, kp.Remote)
	if err != nil {
		s.mu.Unlock()
		s.logger.Printf("wireguard: transport keys for %s: %v", shortKey(peerStatic), err)
		return
	}
	peer.lastTS = ts
	var evicted *transport.Session
	firstHandshake := peer.tunnel == nil
	if firstHandshake {
		peer.tunnel = newTunnel(sess, peer.allowedIPs, from, true)
	} else {
		// A re-handshake (the client's rekey): rotate the new keypair in as
		// current, keeping the old one live as previous so in-flight packets under
		// it still decrypt, and follow the source in case the client roamed.
		peer.tunnel.SetPeerAddr(from)
		evicted = peer.tunnel.install(sess)
	}
	tunnel := peer.tunnel
	s.mu.Unlock()

	// Register the new session's receiver index with the pump and retire the one
	// that fell out. The first handshake also installs the peer's routes; a rekey
	// reuses the same tunnel, so its routes are already in place. The read loop is
	// single-threaded, so no concurrent initiation races this.
	if firstHandshake {
		s.pump.AddTunnel(tunnel)
	} else {
		s.pump.AddInboundKey(sess.LocalIndex(), tunnel)
		if evicted != nil {
			s.pump.RemoveInboundKey(evicted.LocalIndex())
		}
	}

	// Obfuscated like every other outbound message. This is not on the pump's
	// send path, so it does not inherit the transform applied there — and a
	// stock-shaped response to an obfuscated initiation is dropped by the peer
	// as unparseable, which looks exactly like the server never answering.
	if _, err := s.conn.WriteToUDP(obfuscateSend(respPkt, s.obfCfg), from); err != nil {
		s.logger.Printf("wireguard: send response to %s: %v", from, err)
		return
	}
	s.logger.Printf("wireguard: handshake complete with %s at %s", shortKey(peerStatic), from)
}

// Close stops the data path and releases the socket and TUN device. It is
// idempotent.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		if s.pump != nil {
			s.pump.Close()
		}
		if s.conn != nil {
			s.closeErr = s.conn.Close() // unblocks readLoop
		}
		s.tun.Close()
		close(s.closed)
	})
	return s.closeErr
}

// Peers returns every configured peer with their live state, implementing
// client.PeerDescriber so the management panel shows a peer list for WireGuard
// and AmneziaWG (which reuses this Server type). An unknown peer — one that
// has never completed a handshake — reports State "disconnected" with an empty
// LastHandshake. A connected peer's last-handshake time is the wall-clock time
// at which the current tunnel session was installed (rekeyed sessions update
// it). The public key is short-prefix-abbreviated for the panel; the full key
// is always available in the listener config file.
func (s *Server) Peers() []client.PeerInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]client.PeerInfo, 0, len(s.peers))
	for _, p := range s.peers {
		pk := base64.StdEncoding.EncodeToString(p.pubKey[:])
		addr := ""
		if len(p.allowedIPs) > 0 {
			addr = p.allowedIPs[0].String()
		}
		info := client.PeerInfo{
			ID:      pk,
			Address: addr,
			State:   "disconnected",
		}
		if t := p.tunnel; t != nil {
			t.mu.RLock()
			if !t.established.IsZero() {
				info.State = "connected"
				info.LastHandshake = t.established.UTC().Format(time.RFC3339)
			}
			t.mu.RUnlock()
			if st, ok := s.pump.TunnelStats(t); ok {
				info = info.WithTraffic(st.RxPackets, st.RxBytes, st.TxPackets, st.TxBytes, st.LastSeen, true)
			}
		}
		out = append(out, info)
	}
	return out
}

// parseCIDR splits "10.10.0.1/24" into the host address and its network.
func parseCIDR(s string) (net.IP, *net.IPNet, error) {
	ip, network, err := net.ParseCIDR(s)
	if err != nil {
		return nil, nil, err
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip, network, nil
}

// shortKey is a base64 key abbreviated for logs — enough to tell peers apart
// without filling a line.
func shortKey(k [keySize]byte) string {
	s := base64.StdEncoding.EncodeToString(k[:])
	return s[:8] + "…"
}
