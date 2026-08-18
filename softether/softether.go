// Package softether implements the SoftEther VPN native protocol (SE-VPN):
// Ethernet frames over TLS, using the SoftEther PACK serialisation for the
// control exchange. SoftEther's UDP acceleration is NOT implemented -- the data
// path is TLS only, and so carries TCP's head-of-line blocking.
//
// This is one of veepin's two layer-2 (TAP-mode) protocols, alongside l2tpv3:
// it requires a TAP device rather than the TUN interface most protocols use.
// Note that the frames are switched between connected clients only -- nothing
// yet bridges them to the host TAP, so l2tpv3 is the one with a working
// layer-2 data path. See internal/softether/README.md for the full caveats.
package softether

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/softether"
)

// Opt* constants for CLI option parsing.
const (
	OptServer   = "server"
	OptPort     = "port"
	OptUser     = "user"
	OptPassword = "password"
	OptHub      = "hub"
	OptTUN      = "tun"
	OptInsecure = "insecure"
	OptShape    = "shape" // per-flow upstream shaping budget in bytes (0 = off)
)

// Frame geometry for shaping. SoftEther carries Ethernet, so the shaper's
// target is a frame length: the tunnel's inner IP MTU plus the 14-octet
// Ethernet header the frame already carries.
const (
	tunnelMTU    = 1500
	ethHeaderLen = 14

	OptServerListen = "listen"
	OptServerPort   = "port"
	OptServerCert   = "cert"
	OptServerKey    = "key"
	OptServerPool   = "pool"
	OptServerUser   = "user"
	OptServerPass   = "pass"
	OptServerTUN    = "tun"
	OptServerShape  = "shape" // per-flow downstream shaping budget in bytes (0 = off)
)

// Config configures the SoftEther VPN client.
type Config struct {
	Server   string // gateway host or IP
	Port     int    // gateway port (default 443)
	User     string // username (required)
	Password string // password (required)
	Hub      string // virtual hub name (default "VPN")
	TUNName  string // TAP interface name

	// InsecureSkipVerify disables gateway certificate verification. Needed for
	// the self-signed certificates SoftEther ships with by default, and a
	// downgrade to unauthenticated transport wherever it is set.
	InsecureSkipVerify bool

	// Shape pads the first N bytes of each inner flow out towards the frame
	// MTU, so the size pattern of an inner handshake does not survive
	// encapsulation. 0 is off, which is the default. See
	// doc/traffic-shaping.md.
	Shape int
}

// Session wraps a client connection.
type Session struct {
	cs  *softether.ClientSession
	tap *dataplane.TUN

	// done is closed by Close, so the two pump goroutines stop rather than
	// logging a read error against a device that is going away on purpose.
	done      chan struct{}
	closeOnce sync.Once
}

// pump moves Ethernet frames between the TAP and the TLS session, in both
// directions, for the tunnel's lifetime.
//
// This did not exist. Dial opened a TAP, returned it in the Result, and started
// nothing -- so every SoftEther tunnel came up, authenticated, reported an
// interface, and carried no traffic at all. It is why every cell in the interop
// matrix's SoftEther row is a dash, and reading that row as "the cells have not
// been built yet" is what kept it hidden.
//
// Two goroutines rather than one, because both directions block: a TAP read
// waits for the host to send something and a frame read waits for the peer, and
// neither can be polled from the other's loop without one starving the other.
//
// This is deliberately not dataplane.Pump. The pump routes layer-3 packets to a
// tunnel by inner destination address, and there is nothing to route here: every
// frame goes to the one session, and the switching happens at the far end. A
// pump with one route and no demux would be more machinery describing less.
func (s *Session) pump() {
	// TAP -> tunnel.
	go func() {
		buf := make([]byte, softether.MaxFrameSize)
		for {
			n, err := s.tap.Read(buf)
			if err != nil {
				s.stop()
				return
			}
			if n == 0 {
				continue
			}
			if err := s.cs.WriteFrame(buf[:n]); err != nil {
				s.stop()
				return
			}
		}
	}()
	// Tunnel -> TAP.
	go func() {
		for {
			frame, err := s.cs.ReadFrame()
			if err != nil {
				s.stop()
				return
			}
			if len(frame) == 0 {
				continue
			}
			if _, err := s.tap.Write(frame); err != nil {
				s.stop()
				return
			}
		}
	}()
}

// stop closes done exactly once, whichever direction notices first.
func (s *Session) stop() { s.closeOnce.Do(func() { close(s.done) }) }

// Dial connects to a SoftEther VPN server.
func Dial(ctx context.Context, cfg Config) (*Session, client.Result, error) {
	if cfg.Server == "" {
		return nil, client.Result{}, fmt.Errorf("softether: server is required")
	}
	if cfg.User == "" {
		return nil, client.Result{}, fmt.Errorf("softether: user is required")
	}
	port := cfg.Port
	if port == 0 {
		port = 443
	}
	hub := cfg.Hub
	if hub == "" {
		hub = "VPN"
	}

	// Verify the gateway's certificate by default. SoftEther deployments often
	// use a self-signed certificate, so InsecureSkipVerify has to be reachable —
	// but it is opt-in and named, not the silent default it was.
	tlsCfg := &tls.Config{ServerName: cfg.Server, InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // gated on an explicit opt-in
	addr := net.JoinHostPort(cfg.Server, strconv.Itoa(port))

	cs, err := softether.Connect(addr, tlsCfg, cfg.User, cfg.Password, hub)
	if err != nil {
		// A refused login has to reach the caller as client.ErrAuth. SoftEther
		// VPN Server locks an account out after a run of failures, so a retry
		// loop through a wrong password is the one case where waiting and
		// trying again makes the situation worse rather than merely slower.
		return nil, client.Result{}, client.WrapAuth(
			fmt.Errorf("softether: connect: %w", err), softether.ErrAuth)
	}

	if cfg.Shape > 0 {
		// The frame MTU, Ethernet header included: this is a layer-2 carrier,
		// so the target the shaper pads towards is a frame length rather than
		// an IP packet length.
		cs.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape}), tunnelMTU+ethHeaderLen)
	}

	tap, err := dataplane.OpenTAP(cfg.TUNName)
	if err != nil {
		cs.Close()
		return nil, client.Result{}, err
	}

	sess := &Session{cs: cs, tap: tap, done: make(chan struct{})}
	sess.pump()
	return sess, client.Result{
		TUNName: tap.Name(),
		Layer2:  true,
		MTU:     1500,
	}, nil
}

// Wait blocks until the tunnel ends: either the caller cancels, or a pump
// direction fails, which is how a dropped TLS connection now surfaces. Before
// the pump existed nothing here could ever notice a dead peer, so Wait only
// returned when the caller gave up -- and the reconnection loop had nothing to
// react to.
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return fmt.Errorf("softether: the tunnel data path stopped")
	}
}

// Close tears down the session.
func (s *Session) Close() error {
	s.stop()
	csErr := s.cs.Close()
	tapErr := s.tap.Close()
	if csErr != nil {
		return csErr
	}
	return tapErr
}

type dialer struct{ cfg Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, d.cfg)
}

func parseOptions(opts map[string]string) (client.Dialer, error) {
	var cfg Config
	cfg.Server = opts[OptServer]
	cfg.User = opts[OptUser]
	cfg.Password = opts[OptPassword]
	cfg.Hub = opts[OptHub]
	cfg.TUNName = opts[OptTUN]
	cfg.InsecureSkipVerify = opts[OptInsecure] == "true"
	if v := opts[OptShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("softether: invalid %s %q", OptShape, v)
		}
		cfg.Shape = n
	}
	if p := opts[OptPort]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("softether: bad %s %q: %w", OptPort, p, err)
		}
		cfg.Port = n
	}
	return dialer{cfg: cfg}, nil
}

func init() {
	client.Register("softether", parseOptions)
}

// Server is a SoftEther VPN server.
type Server struct {
	tap        *dataplane.TUN
	server     *softether.Server
	ln         net.Listener
	tlsCfg     *tls.Config
	listenIP   string
	listenPort int
	log        *log.Logger
	closed     chan struct{}
}

// pumpTAP puts the server's own interface on the switch and feeds it.
//
// Like the client's pump, this did not exist: the TAP was opened, named and
// closed, and no frame ever crossed it. AttachLocal makes it an ordinary bridge
// port -- learned, flooded to and excluded as a source exactly like a client's
// -- so a host on the server's segment and a connected client can reach each
// other, which is what a layer-2 VPN is for.
//
// The read loop runs until the TAP is closed, which Close does.
func (s *Server) pumpTAP() {
	s.server.AttachLocal(func(frame []byte) error {
		_, err := s.tap.Write(frame)
		return err
	})
	go func() {
		defer s.server.DetachLocal()
		buf := make([]byte, softether.MaxFrameSize)
		for {
			n, err := s.tap.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			s.server.InjectLocal(buf[:n])
		}
	}()
}

// ServerConfig configures the SoftEther VPN server.
type ServerConfig struct {
	Listen  string // local IP to bind (default 0.0.0.0)
	Port    int    // TLS port (default 443)
	Cert    string // path to TLS cert PEM
	Key     string // path to TLS key PEM
	Pool    string // address pool CIDR
	User    string // username (required)
	Pass    string // password (required)
	TUNName string // TAP interface name
	// Shape pads the first N bytes of each inner flow out towards the frame
	// MTU. 0 is off, which is the default.
	Shape  int
	Logger *log.Logger
}

// NewServer creates a SoftEther VPN server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.User == "" {
		return nil, fmt.Errorf("softether: server user is required")
	}
	if cfg.Pass == "" {
		return nil, fmt.Errorf("softether: server pass is required")
	}
	if cfg.Cert == "" || cfg.Key == "" {
		return nil, fmt.Errorf("softether: cert and key are required")
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("softether: load cert: %w", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	tap, err := dataplane.OpenTAP(cfg.TUNName)
	if err != nil {
		return nil, err
	}

	bridge := softether.NewBridge(softether.DefaultAgeTime)
	gatewayMAC := softether.MACAddr{0x00, 0x0c, 0x29, 0x01, 0x02, 0x03}
	gatewayIP := net.ParseIP("10.70.0.1")

	srv := softether.NewServer(tlsCfg, bridge, gatewayMAC, gatewayIP,
		softether.SingleUser(cfg.User, cfg.Pass))

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	srv.SetLogger(logger.Printf)

	if cfg.Shape > 0 {
		srv.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape}), tunnelMTU+ethHeaderLen)
	}

	listenIP := cfg.Listen
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	port := cfg.Port
	if port == 0 {
		port = softether.DefaultPort
	}
	return &Server{
		tap:        tap,
		server:     srv,
		tlsCfg:     tlsCfg,
		listenIP:   listenIP,
		listenPort: port,
		log:        logger,
		closed:     make(chan struct{}),
	}, nil
}

// ListenAndServe binds the TLS listener and starts serving. Per the contract in
// client/client.go, NewServer opened the TAP and validated; the socket is bound
// only here.
func (s *Server) ListenAndServe() error {
	ln, err := tls.Listen("tcp", net.JoinHostPort(s.listenIP, strconv.Itoa(s.listenPort)), s.tlsCfg)
	if err != nil {
		return fmt.Errorf("softether: listen: %w", err)
	}
	s.ln = ln
	defer ln.Close()

	s.pumpTAP()
	s.log.Printf("softether: listening on %s", ln.Addr())
	err = s.server.Serve(ln)
	close(s.closed)
	return err
}

// Close shuts down the server.
func (s *Server) Close() error {
	s.server.Close()
	if s.ln != nil {
		s.ln.Close()
	}
	return s.tap.Close()
}

// TUNName returns the TAP interface name.
func (s *Server) TUNName() string { return s.tap.Name() }

// Gateway returns the server's tunnel address.
func (s *Server) Gateway() net.IP { return net.ParseIP("10.70.0.1") }

// Network returns the tunnel subnet.
func (s *Server) Network() *net.IPNet {
	_, n, _ := net.ParseCIDR("10.70.0.0/24")
	return n
}

func parseServerOptions(opts map[string]string) (client.Server, error) {
	sc := ServerConfig{
		Listen:  opts[OptServerListen],
		User:    opts[OptServerUser],
		Pass:    opts[OptServerPass],
		Cert:    opts[OptServerCert],
		Key:     opts[OptServerKey],
		Pool:    opts[OptServerPool],
		TUNName: opts[OptServerTUN],
	}
	if v := opts[OptServerShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("softether: invalid %s %q", OptServerShape, v)
		}
		sc.Shape = n
	}
	if p := opts[OptServerPort]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("softether: bad %s %q: %w", OptServerPort, p, err)
		}
		sc.Port = n
	}
	return NewServer(sc)
}

func init() {
	client.RegisterServer("softether", parseServerOptions)
	client.RegisterServerOpts("softether", []client.OptSpec{
		{Key: OptServerCert, Kind: client.OptFilePath, Required: true, Generate: "tls", Help: "path to TLS certificate PEM"},
		{Key: OptServerKey, Kind: client.OptFilePath, Required: true, Secret: true, Generate: "tls", Help: "path to TLS private key PEM"},
		{Key: OptServerUser, Kind: client.OptStr, Required: true, Help: "username to accept"},
		{Key: OptServerPass, Kind: client.OptStr, Required: true, Secret: true, Help: "password to accept"},
		{Key: OptServerTUN, Kind: client.OptStr, Help: "TAP interface name (empty = kernel picks)"},
		{Key: OptServerPool, Kind: client.OptCIDR, Default: "10.70.0.0/24", Help: "address pool (default 10.70.0.0/24)"},
		{Key: OptServerListen, Kind: client.OptStr, Default: "0.0.0.0", Help: "local IP to bind the TLS listener on (default 0.0.0.0)"},
		{Key: OptServerPort, Kind: client.OptInt, Default: "443", Help: "TLS port to listen on (default 443)"},
		client.ShapeOpt(OptServerShape, "downstream"),
	})
}
