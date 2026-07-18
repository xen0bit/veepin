package anyconnect

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/xen0bit/veepin/dataplane"
)

// handshakeTimeout bounds the HTTP authentication and CONNECT exchange. Once the
// tunnel is up the connection carries data with no deadline.
const handshakeTimeout = 30 * time.Second

// Server-advertised liveness intervals, in seconds. DPD is what a client uses to
// notice a dead path; the keepalive holds an idle NAT binding open.
const (
	serverDPD       = 30
	serverKeepalive = 20
)

// ServerConfig configures the AnyConnect server engine.
type ServerConfig struct {
	Users   map[string]string // username -> password
	Pool    *dataplane.AddrPool
	Gateway net.IP // the server's inner address (the pool's first host)
	DNS     []net.IP
	MTU     int
	Logger  *log.Logger
}

// Server is a running AnyConnect responder. Like SSTP it is connection-oriented:
// each client rides its own TLS connection and gets one goroutine, and all share
// a single TUN routed by inner destination address.
type Server struct {
	cfg     ServerConfig
	tun     tunIO
	pool    *dataplane.AddrPool
	gateway net.IP
	logger  *log.Logger

	sessions sync.Map

	lock    sync.Mutex
	clients map[uint32]*serverClient // keyed by assigned inner address

	done      chan struct{}
	closeOnce sync.Once
}

// NewServer builds a server over a TUN. Connections are handed to Serve by the
// caller, which owns the listener.
func NewServer(tun tunIO, cfg ServerConfig) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{
		cfg:     cfg,
		tun:     tun,
		pool:    cfg.Pool,
		gateway: cfg.Gateway,
		logger:  logger,
		clients: map[uint32]*serverClient{},
		done:    make(chan struct{}),
	}
}

// Start begins routing TUN egress to connected clients.
func (s *Server) Start() { go s.tunLoop() }

// Close stops the server and drops every client.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.lock.Lock()
		for _, c := range s.clients {
			c.conn.Close()
		}
		s.lock.Unlock()
	})
	return nil
}

// ServeConn runs one client connection to completion. The caller supplies an
// established TLS connection; this drives the HTTP exchange and then the data
// path, and returns when the client disconnects.
func (s *Server) ServeConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReaderSize(conn, maxPayload+headerLen)

	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}
	cookie, err := s.serveAuth(conn, br)
	if err != nil {
		s.logger.Printf("anyconnect: %s: authentication failed: %v", conn.RemoteAddr(), err)
		return
	}
	c, err := s.serveConnect(conn, br, cookie)
	if err != nil {
		s.logger.Printf("anyconnect: %s: CONNECT failed: %v", conn.RemoteAddr(), err)
		return
	}
	defer s.removeClient(c)

	// The tunnel is up; drop the handshake deadline.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}
	s.logger.Printf("anyconnect: %s connected as %s, assigned %s",
		conn.RemoteAddr(), c.username, c.innerIP)
	c.readLoop()
}

// serveAuth runs the XML credential exchange, returning the session cookie the
// client must present on its CONNECT.
func (s *Server) serveAuth(conn net.Conn, br *bufio.Reader) (string, error) {
	for range maxAuthRounds {
		req, err := http.ReadRequest(br)
		if err != nil {
			return "", fmt.Errorf("read request: %w", err)
		}
		if req.Method != http.MethodPost {
			return "", fmt.Errorf("unexpected %s %s during authentication", req.Method, req.URL.Path)
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		req.Body.Close()
		if err != nil {
			return "", fmt.Errorf("read body: %w", err)
		}
		msg, err := parseConfigAuth(body)
		if err != nil {
			return "", err
		}
		switch msg.Type {
		case "init":
			if err := writeXML(conn, credentialForm(), nil); err != nil {
				return "", err
			}
		case "auth-reply":
			user := msg.Auth.field("username")
			pass := msg.Auth.field("password")
			if !s.authenticate(user, pass) {
				// Re-present the form with an error rather than closing, which is
				// how the protocol reports a bad password.
				_ = writeXML(conn, failureMessage("Invalid credentials"), nil)
				return "", fmt.Errorf("bad credentials for %q", user)
			}
			cookie := newSessionToken()
			s.sessions.Store(cookie, user)
			var hdr headerList
			hdr.set("Set-Cookie", sessionCookie+"="+cookie+"; path=/; Secure")
			return cookie, writeXML(conn, completeMessage(cookie, cookie), hdr)
		default:
			return "", fmt.Errorf("unexpected auth message type %q", msg.Type)
		}
	}
	return "", fmt.Errorf("authentication did not complete in %d rounds", maxAuthRounds)
}

// authenticate checks a username and password in constant time with respect to
// the password, so a wrong password cannot be distinguished from a wrong one of
// a different length by timing.
func (s *Server) authenticate(user, pass string) bool {
	want, ok := s.cfg.Users[user]
	if !ok {
		// Still compare, so a valid username is not revealed by a faster reject.
		subtle.ConstantTimeCompare([]byte(pass), []byte(pass))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pass), []byte(want)) == 1
}

// serveConnect answers the CONNECT request, allocating the client an address and
// replying with the configuration headers that carry it.
func (s *Server) serveConnect(conn net.Conn, br *bufio.Reader, cookie string) (*serverClient, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT: %w", err)
	}
	req.Body.Close()
	if req.Method != http.MethodConnect {
		return nil, fmt.Errorf("expected CONNECT, got %s %s", req.Method, req.URL.Path)
	}
	user, ok := s.sessionUser(req, cookie)
	if !ok {
		_ = writeStatus(conn, http.StatusUnauthorized)
		return nil, fmt.Errorf("CONNECT without a valid session cookie")
	}

	ip, err := s.pool.Allocate()
	if err != nil {
		_ = writeStatus(conn, http.StatusServiceUnavailable)
		return nil, fmt.Errorf("address pool exhausted: %w", err)
	}

	mtu := s.cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	cfg := TunnelConfig{
		Address: ip,
		Netmask: net.IP(s.pool.Network().Mask),
		DNS:     s.cfg.DNS,
		MTU:     mtu,
	}
	var hdr headerList
	writeTunnelConfig(&hdr, cfg, serverDPD, serverKeepalive)
	if err := writeConnectOK(conn, hdr); err != nil {
		s.pool.Release(ip)
		return nil, err
	}

	c := &serverClient{
		srv:      s,
		conn:     conn,
		br:       br,
		username: user,
		innerIP:  ip,
	}
	s.addClient(c)
	return c, nil
}

// sessionUser validates the cookie the client presents on CONNECT against the
// one issued during authentication.
func (s *Server) sessionUser(req *http.Request, issued string) (string, bool) {
	for _, ck := range req.Cookies() {
		if ck.Name != sessionCookie {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(ck.Value), []byte(issued)) != 1 {
			continue
		}
		if user, ok := s.sessions.Load(ck.Value); ok {
			name, _ := user.(string)
			return name, true
		}
	}
	return "", false
}

func (s *Server) addClient(c *serverClient) {
	if v4 := c.innerIP.To4(); v4 != nil {
		s.lock.Lock()
		s.clients[binary.BigEndian.Uint32(v4)] = c
		s.lock.Unlock()
	}
}

func (s *Server) removeClient(c *serverClient) {
	if v4 := c.innerIP.To4(); v4 != nil {
		s.lock.Lock()
		delete(s.clients, binary.BigEndian.Uint32(v4))
		s.lock.Unlock()
	}
	s.pool.Release(c.innerIP)
	s.logger.Printf("anyconnect: %s disconnected, released %s", c.username, c.innerIP)
}

func (s *Server) clientByIP(ip net.IP) *serverClient {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.clients[binary.BigEndian.Uint32(v4)]
}

// tunLoop routes TUN egress to the client owning the inner destination address.
func (s *Server) tunLoop() {
	buf := make([]byte, maxPayload)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		dst := ipv4Dst(buf[:n])
		if dst == nil {
			continue
		}
		if c := s.clientByIP(dst); c != nil {
			_ = c.send(typeData, buf[:n])
		}
	}
}

// serverClient is one connected client.
type serverClient struct {
	srv      *Server
	conn     net.Conn
	br       *bufio.Reader
	username string
	innerIP  net.IP

	writeMu sync.Mutex
}

// readLoop reads this client's packets until the connection ends.
func (c *serverClient) readLoop() {
	for {
		typ, payload, err := readPacket(c.br)
		if err != nil {
			return
		}
		switch typ {
		case typeData:
			// Only forward packets whose source is the address this client was
			// assigned, so one client cannot spoof another's traffic onto the TUN.
			if src := ipv4Src(payload); src == nil || !src.Equal(c.innerIP) {
				continue
			}
			if _, err := c.srv.tun.Write(payload); err != nil {
				return
			}
		case typeDPDReq:
			if err := c.send(typeDPDResp, payload); err != nil {
				return
			}
		case typeDPDResp, typeKeepalive:
		case typeDisconnect, typeTerminate:
			return
		}
	}
}

func (c *serverClient) send(typ byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.conn.Write(marshal(typ, payload))
	return err
}

// --- HTTP response helpers ---
//
// Responses are written by hand rather than through net/http's Server, because
// the connection stops being HTTP the moment CONNECT succeeds and has to be
// taken over for framed packets.

// writeXML sends an XML message of the authentication exchange.
func writeXML(w io.Writer, msg configAuth, extra headerList) error {
	body, err := marshalConfigAuth(msg)
	if err != nil {
		return err
	}
	h := append(headerList{}, extra...)
	h.set("Content-Type", "text/xml")
	h.setInt("Content-Length", len(body))
	h.set("Connection", "keep-alive")
	return writeResponse(w, http.StatusOK, "OK", h, body)
}

// writeConnectOK accepts the tunnel request. Its headers carry the client's
// configuration, and everything after them is CSTP framing.
func writeConnectOK(w io.Writer, h headerList) error {
	h.set("Content-Type", "application/octet-stream")
	h.set("Connection", "keep-alive")
	// No Content-Length: the body is the tunnel and never ends.
	return writeResponse(w, http.StatusOK, "Connection established", h, nil)
}

func writeStatus(w io.Writer, code int) error {
	var h headerList
	h.set("Content-Length", "0")
	return writeResponse(w, code, http.StatusText(code), h, nil)
}

func writeResponse(w io.Writer, code int, reason string, h headerList, body []byte) error {
	var buf []byte
	buf = append(buf, fmt.Sprintf("HTTP/1.1 %d %s\r\n", code, reason)...)
	for _, kv := range h {
		buf = append(buf, kv[0]...)
		buf = append(buf, ": "...)
		buf = append(buf, kv[1]...)
		buf = append(buf, "\r\n"...)
	}
	buf = append(buf, "\r\n"...)
	buf = append(buf, body...)
	_, err := w.Write(buf)
	return err
}

// newSessionToken mints an unguessable session cookie.
func newSessionToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ipv4Dst and ipv4Src extract addresses from an IPv4 packet.
func ipv4Dst(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
}

func ipv4Src(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
}
