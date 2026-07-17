// Package sstp is the public entry point for Microsoft's Secure Socket Tunneling
// Protocol (SSTP): TLS/TCP + HTTP CONNECT + PPP (MS-CHAPv2) + crypto binding.
//
// Importing this package registers "sstp" with the client registry:
//
//	import _ "github.com/xen0bit/veepin/sstp"
//	sess, res, err := client.Dial(ctx, "sstp", opts)
package sstp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/mschap"
	ppp "github.com/xen0bit/veepin/internal/ppp"
	"github.com/xen0bit/veepin/internal/sstp/wire"
)

func init() { client.Register("sstp", parseOptions) }

// Option names for client.Dial.
const (
	OptServer   = "server"
	OptPort     = "port"
	OptUser     = "user"
	OptPassword = "password"
	OptTUNName  = "tun"
)

// Config holds the parameters for a single SSTP tunnel.
type Config struct {
	Server   string
	Port     int
	Username string
	Password string
	TUNName  string
	Logger   *log.Logger
}

func (c *Config) validate() error {
	if c.Server == "" {
		return fmt.Errorf("sstp: server is required")
	}
	if c.Username == "" || c.Password == "" {
		return fmt.Errorf("sstp: username and password are required")
	}
	return nil
}

func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := &Config{}
	if v := opts[OptServer]; v != "" {
		cfg.Server = v
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("sstp: invalid port %q", v)
		}
		cfg.Port = p
	}
	cfg.Username = opts[OptUser]
	cfg.Password = opts[OptPassword]
	cfg.TUNName = opts[OptTUNName]
	if cfg.Port == 0 {
		cfg.Port = 443
	}
	return dialer{cfg}, cfg.validate()
}

type dialer struct{ cfg *Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, *d.cfg)
}

// Dial performs the full SSTP handshake, opens a TUN device, and starts the data
// path. It returns a running Session and the Result the caller must apply.
func Dial(ctx context.Context, cfg Config) (client.Session, client.Result, error) {
	if err := cfg.validate(); err != nil {
		return nil, client.Result{}, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	addr := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))

	tlsCfg := &tls.Config{
		ServerName: cfg.Server,
	}
	tlsConn, err := dialTLS(ctx, addr, tlsCfg)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("sstp: TLS dial: %w", err)
	}

	if err := httpConnect(tlsConn, addr); err != nil {
		tlsConn.Close()
		return nil, client.Result{}, fmt.Errorf("sstp: CONNECT: %w", err)
	}

	if err := sendCallConnectRequest(tlsConn); err != nil {
		tlsConn.Close()
		return nil, client.Result{}, fmt.Errorf("sstp: CallConnectRequest: %w", err)
	}

	serverNonce, err := readCallConnectAck(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, client.Result{}, fmt.Errorf("sstp: CallConnectAck: %w", err)
	}

	s := &session{
		tlsConn:     tlsConn,
		logger:      logger,
		cfg:         cfg,
		serverNonce: serverNonce,
		done:        make(chan struct{}),
		ipReady:     make(chan struct{}),
	}
	s.ppp = ppp.New(cfg.Username, cfg.Password, s, s)
	s.ppp.Start()

	go s.readLoop()

	select {
	case <-s.ipReady:
	case <-ctx.Done():
		s.Close()
		return nil, client.Result{}, ctx.Err()
	case <-s.done:
		s.Close()
		return nil, client.Result{}, fmt.Errorf("sstp: %w", s.closeErr)
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		s.Close()
		return nil, client.Result{}, fmt.Errorf("sstp: open TUN: %w", err)
	}

	s.tun.Store(tun)
	go s.outboundLoop(tun)

	logger.Printf("sstp: tunnel up on %s, internal IP %s", tun.Name(), s.assignedIP)

	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: s.assignedIP,
		Netmask:    net.IPv4(255, 255, 255, 255),
		Gateway:    s.gateway,
		DNS:        s.dns,
		MTU:        client.DefaultTunnelMTU,
	}
	return s, res, nil
}

func dialTLS(ctx context.Context, addr string, tlsCfg *tls.Config) (*tls.Conn, error) {
	d := tls.Dialer{Config: tlsCfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

type session struct {
	tlsConn     *tls.Conn
	ppp         *ppp.Session
	tun         atomic.Pointer[dataplane.TUN]
	logger      *log.Logger
	cfg         Config
	serverNonce []byte

	// writeMu serializes writes to tlsConn: a TLS connection tolerates one
	// concurrent reader and writer, but the read loop (echo replies, the crypto
	// binding, PPP control) and the outbound loop (data packets) are two writers.
	writeMu sync.Mutex

	mu     sync.Mutex
	closed bool

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}

	assignedIP net.IP
	gateway    net.IP
	dns        []net.IP
	ipReady    chan struct{}
}

// writePacket sends one already-framed SSTP packet, serialized against the other
// writer and bounded by a write deadline.
func (s *session) writePacket(pkt []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.tlsConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := s.tlsConn.Write(pkt)
	return err
}

func (s *session) SendPPP(frame []byte) error {
	pkt, err := wire.EncodeData(frame)
	if err != nil {
		return err
	}
	return s.writePacket(pkt)
}

func (s *session) Authenticated(ntResponse [mschap.NTResponseLen]byte) {
	hlak := mschap.ClientHLAK(s.cfg.Password, ntResponse)

	state := s.tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		s.logger.Printf("sstp: no server certificate for crypto binding")
		return
	}
	serverCertDER := state.PeerCertificates[0].Raw

	pkt, err := buildCallConnected(s.serverNonce, serverCertDER, hlak)
	if err != nil {
		s.logger.Printf("sstp: build CallConnected: %v", err)
		return
	}
	if err := s.writePacket(pkt); err != nil {
		s.logger.Printf("sstp: send CallConnected: %v", err)
		return
	}
	s.logger.Printf("sstp: crypto binding sent")
}

func (s *session) NetworkUp(cfg ppp.IPConfig) {
	s.assignedIP = cfg.LocalIP
	s.gateway = cfg.PeerIP
	s.dns = cfg.DNS
	close(s.ipReady)
}

func (s *session) Closed(err error) {
	s.mu.Lock()
	if !s.closed {
		s.closeErr = err
	}
	s.mu.Unlock()
	s.Close()
}

func (s *session) readLoop() {
	for {
		control, body, err := wire.ReadPacket(s.tlsConn)
		if err != nil {
			s.mu.Lock()
			if !s.closed {
				s.closeErr = fmt.Errorf("read: %w", err)
			}
			s.mu.Unlock()
			s.Close()
			return
		}
		if control {
			msg, err := wire.ParseControl(body)
			if err != nil {
				s.logger.Printf("sstp: malformed control: %v", err)
				continue
			}
			switch msg.Type {
			case wire.MsgCallDisconnect:
				s.mu.Lock()
				s.closeErr = fmt.Errorf("server disconnected")
				s.mu.Unlock()
				s.Close()
				return
			case wire.MsgEchoRequest:
				resp, _ := wire.EncodeControl(wire.MsgEchoResponse, nil)
				_ = s.writePacket(resp)
			case wire.MsgCallConnected:
				s.logger.Printf("sstp: server crypto binding ack")
			default:
				s.logger.Printf("sstp: unhandled control %#x", msg.Type)
			}
			continue
		}

		// Data packet. Once the link is up its payload is an IP packet bound for the
		// TUN; before that (and for LCP echoes afterwards) it is PPP control.
		if ipPacket, ok := ppp.IsIP(body); ok {
			if tun := s.tun.Load(); tun != nil {
				if _, err := tun.Write(ipPacket); err != nil {
					s.logger.Printf("sstp: TUN write: %v", err)
				}
			}
			continue
		}
		s.ppp.Receive(body)
	}
}

func (s *session) outboundLoop(tun *dataplane.TUN) {
	buf := make([]byte, 65535)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			s.logger.Printf("sstp: TUN read: %v", err)
			s.Close()
			return
		}
		pkt, err := wire.EncodeData(ppp.EncapsulateIP(buf[:n]))
		if err != nil {
			s.logger.Printf("sstp: encode: %v", err)
			continue
		}
		if err := s.writePacket(pkt); err != nil {
			s.logger.Printf("sstp: write: %v", err)
			s.Close()
			return
		}
	}
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
		if tun := s.tun.Load(); tun != nil {
			_ = tun.Close()
		}
		if s.tlsConn != nil {
			_ = s.tlsConn.Close()
		}
	})
	return s.closeErr
}
