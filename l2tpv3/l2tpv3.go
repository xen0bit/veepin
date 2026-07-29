package l2tpv3

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/l2tpv3"
)

const (
	OptGateway = "gateway"
	OptPort    = "port"
	OptTUN     = "tun"
	OptShape   = "shape"

	OptSessionID   = "session-id"
	OptPeerSession = "peer-session-id"
	OptCookie      = "cookie"
	OptPeerCookie  = "peer-cookie"
	OptSublayer    = "sublayer"

	// Server-side option keys.
	OptServerListen = "listen"
	OptServerShape  = "shape"
)

// Config configures an L2TPv3 Ethernet pseudowire client.
type Config struct {
	Server  string // gateway host or IP
	Port    int    // UDP port (default 1701)
	TUNName string // TAP interface name
	Shape   int    // upstream shaping budget

	SessionID   uint32 // our session ID
	PeerSession uint32 // peer's session ID
	Cookie      string // hex-encoded receive-side cookie
	PeerCookie  string // hex-encoded send-side cookie
	Sublayer    bool   // enable Default L2-Specific Sublayer
}

// Dial connects to an L2TPv3 peer over a static Ethernet pseudowire.
func Dial(ctx context.Context, cfg Config) (*Session, client.Result, error) {
	if cfg.Server == "" {
		return nil, client.Result{}, fmt.Errorf("l2tpv3: server is required")
	}

	port := cfg.Port
	if port == 0 {
		port = 1701
	}

	localCookie := parseHex(cfg.Cookie)
	remoteCookie := parseHex(cfg.PeerCookie)

	sessCfg := &l2tpv3.SessionConfig{
		LocalSessionID:  cfg.SessionID,
		RemoteSessionID: cfg.PeerSession,
		LocalCookie:     localCookie,
		RemoteCookie:    remoteCookie,
		Sublayer:        cfg.Sublayer,
	}

	serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.Server, strconv.Itoa(port)))
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("l2tpv3: resolve: %w", err)
	}
	sessCfg.PeerAddr = serverAddr

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("l2tpv3: dial: %w", err)
	}

	tap, err := dataplane.OpenTAP(cfg.TUNName)
	if err != nil {
		conn.Close()
		return nil, client.Result{}, err
	}

	logger := log.New(log.Writer(), "l2tpv3: ", log.LstdFlags)

	pump := l2tpv3.NewPump(tap,
		func(pkt []byte, to *net.UDPAddr) {
			_, _ = conn.Write(pkt)
		},
		cfg.SessionID, sessCfg, logger)

	s := &Session{
		conn: conn,
		tap:  tap,
		pump: pump,
		done: make(chan struct{}),
	}
	go pump.Run()
	go s.readLoop()

	res := client.Result{
		TUNName: tap.Name(),
		Layer2:  true,
		Gateway: net.ParseIP(cfg.Server),
		MTU:     1446,
	}
	if len(localCookie) >= 8 {
		res.MTU = 1438
	}

	return s, res, nil
}

// Session wraps an L2TPv3 tunnel.
type Session struct {
	conn *net.UDPConn
	tap  *dataplane.TUN
	pump *l2tpv3.Pump
	done chan struct{}
}

func (s *Session) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			select {
			case <-s.done:
			default:
			}
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.pump.HandleInbound(pkt)
	}
}

func (s *Session) Wait(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (s *Session) Close() error {
	close(s.done)
	s.pump.Close()
	s.conn.Close()
	return s.tap.Close()
}

func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := Config{
		Server:     opts[OptGateway],
		TUNName:    opts[OptTUN],
		Cookie:     opts[OptCookie],
		PeerCookie: opts[OptPeerCookie],
		Sublayer:   opts[OptSublayer] == "true",
	}
	if p := opts[OptPort]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("l2tpv3: bad %s %q: %w", OptPort, p, err)
		}
		cfg.Port = n
	}
	if v := opts[OptSessionID]; v != "" {
		n, err := strconv.ParseUint(v, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("l2tpv3: bad %s %q: %w", OptSessionID, v, err)
		}
		cfg.SessionID = uint32(n)
	}
	if v := opts[OptPeerSession]; v != "" {
		n, err := strconv.ParseUint(v, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("l2tpv3: bad %s %q: %w", OptPeerSession, v, err)
		}
		cfg.PeerSession = uint32(n)
	}
	if v := opts[OptShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("l2tpv3: bad %s %q", OptShape, v)
		}
		cfg.Shape = n
	}
	return dialer{cfg}, nil
}

type dialer struct{ cfg Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, d.cfg)
}

func init() {
	client.Register("l2tpv3", parseOptions)
}

func parseHex(s string) []byte {
	if s == "" {
		return nil
	}
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		var v byte
		if _, err := fmt.Sscanf(s[i:i+2], "%02x", &v); err != nil {
			return out
		}
		out = append(out, v)
	}
	return out
}
