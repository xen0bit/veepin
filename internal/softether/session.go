package softether

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// SoftEther VPN native protocol session: TLS connection, PACK-based control
// exchange, and Ethernet frame forwarding.

// Protocol constants matching SoftEther's definitions.
const (
	DefaultPort = 443

	// Frame length prefix: 4 bytes little-endian.
	framePrefixLen = 4

	// Max receive size for a single PACK message.
	maxPackSize = 512 * 1024
)

// ServerSession holds state for one connected SoftEther client.
type ServerSession struct {
	conn   *tls.Conn
	srv    *Server
	bridge *Bridge
	port   PortID
	mu     sync.Mutex

	// Client authentication state. Atomic because forwardTo reads it from a
	// *peer's* frame-loop goroutine while this session's own goroutine sets it.
	authenticated atomic.Bool
	username      string
	hubName       string
	assignedIP    net.IP

	// Random challenge sent in the hello response.
	random [20]byte

	logf func(format string, args ...interface{})
}

// CredentialLookup returns the password for a username, and whether the user
// exists. A nil lookup rejects every login: a VPN server that authenticates
// nobody must refuse everybody, not admit everybody.
type CredentialLookup func(username string) (password string, ok bool)

// Server handles incoming SoftEther VPN connections.
type Server struct {
	config      *tls.Config
	bridge      *Bridge
	gatewayMAC  MACAddr
	gatewayIP   net.IP
	credentials CredentialLookup
	logf        func(format string, args ...interface{})
	shutdown    atomic.Bool

	// sessions maps a bridge port to the session that owns it, so a frame the
	// bridge resolves to a port can actually be written to that peer. Without
	// it the switch learns addresses and forwards nothing.
	sessionsMu sync.RWMutex
	sessions   map[PortID]*ServerSession

	// local is the server's own interface as a switch port (local.go), or nil
	// when nothing is attached. Guarded separately from sessions because
	// deliver consults both, and one lock over two unrelated maps is how a
	// deadlock gets written later.
	localMu sync.RWMutex
	local   *localPort
}

// NewServer creates a SoftEther VPN server. creds authenticates logins; passing
// nil makes every login fail.
func NewServer(tlsCfg *tls.Config, bridge *Bridge, gatewayMAC MACAddr, gatewayIP net.IP, creds CredentialLookup) *Server {
	return &Server{
		config:      tlsCfg,
		bridge:      bridge,
		gatewayMAC:  gatewayMAC,
		gatewayIP:   gatewayIP,
		credentials: creds,
		sessions:    make(map[PortID]*ServerSession),
		logf:        func(string, ...interface{}) {},
	}
}

// addSession / removeSession / sessionFor keep the port-to-session registry.
func (s *Server) addSession(ss *ServerSession) {
	s.sessionsMu.Lock()
	s.sessions[ss.port] = ss
	s.sessionsMu.Unlock()
}

func (s *Server) removeSession(p PortID) {
	s.sessionsMu.Lock()
	delete(s.sessions, p)
	s.sessionsMu.Unlock()
}

func (s *Server) sessionFor(p PortID) *ServerSession {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	return s.sessions[p]
}

// SingleUser is a CredentialLookup for the one-account case the CLI exposes.
func SingleUser(username, password string) CredentialLookup {
	return func(u string) (string, bool) {
		if u != username {
			return "", false
		}
		return password, true
	}
}

// SetLogger sets the server's log function.
func (s *Server) SetLogger(f func(string, ...interface{})) {
	if f != nil {
		s.logf = f
	}
}

// Serve accepts connections on the TLS listener.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.shutdown.Load() {
				return nil
			}
			return fmt.Errorf("softether: accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// Close shuts down the server.
func (s *Server) Close() { s.shutdown.Store(true) }

func (s *Server) handleConn(raw net.Conn) {
	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		raw.Close()
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		s.logf("softether: TLS handshake: %v", err)
		tlsConn.Close()
		return
	}

	port := s.bridge.NewPort()
	ss := &ServerSession{
		conn:   tlsConn,
		srv:    s,
		bridge: s.bridge,
		port:   port,
		logf:   s.logf,
	}
	// Generate the challenge the client's password digest is bound to. A
	// predictable value here would make every login replayable.
	if _, err := rand.Read(ss.random[:]); err != nil {
		s.logf("softether: challenge generation failed: %v", err)
		tlsConn.Close()
		return
	}

	s.logf("softether: new connection from %s (port %d)", tlsConn.RemoteAddr(), port)

	s.addSession(ss)
	if err := ss.exchange(); err != nil {
		s.logf("softether: session %d: %v", port, err)
	}

	s.removeSession(port)
	s.bridge.RemovePort(port)
	tlsConn.Close()
}

// exchange runs the full control exchange and then forwards frames.
func (ss *ServerSession) exchange() error {
	// Phase 1: Hello exchange.
	if err := ss.helloExchange(); err != nil {
		return err
	}

	// Phase 2: Authentication.
	authResult, err := ss.authenticate()
	if err != nil {
		return err
	}
	if !authResult {
		return fmt.Errorf("authentication failed for %q", ss.username)
	}

	ss.authenticated.Store(true)
	ss.logf("softether: session %d authenticated as %q", ss.port, ss.username)

	// Phase 3: Frame forwarding loop.
	return ss.frameLoop()
}

func (ss *ServerSession) helloExchange() error {
	// Receive client hello.
	req, err := ss.readPack()
	if err != nil {
		return fmt.Errorf("hello read: %w", err)
	}
	method := req.GetStr("method")
	if method != "hello" {
		return fmt.Errorf("expected hello method, got %q", method)
	}

	// Build hello response.
	resp := NewPack()
	resp.Add("method", TypeStr, StrValue("hello"))
	resp.Add("random", TypeData, DataValue(ss.random[:]))
	resp.Add("ver", TypeInt, IntValue(2))
	resp.Add("build", TypeInt, IntValue(1))

	return ss.writePack(resp)
}

func (ss *ServerSession) authenticate() (bool, error) {
	req, err := ss.readPack()
	if err != nil {
		return false, fmt.Errorf("auth read: %w", err)
	}

	// Expect login with password authentication.
	method := req.GetStr("method")
	if method != "login" {
		return false, fmt.Errorf("expected login, got %q", method)
	}

	ss.username = req.GetStr("username")
	ss.hubName = req.GetStr("hubname")
	securePassword := req.GetData("secure_password")
	if len(securePassword) != 20 {
		return false, fmt.Errorf("bad secure_password length %d", len(securePassword))
	}

	// Verify the challenge response: the client sent
	// SHA1(SHA1(username+password) XOR random), and only someone who knows the
	// password can produce it for our random. Comparing in constant time keeps
	// the reply from leaking how much of the digest matched.
	if !ss.verifySecurePassword(securePassword) {
		ss.logf("softether: login rejected for %q", ss.username)
		resp := NewPack()
		resp.Add("method", TypeStr, StrValue("login"))
		resp.Add("error", TypeInt, IntValue(1))
		_ = ss.writePack(resp)
		return false, nil
	}
	ss.assignedIP = net.ParseIP("10.70.0.2")

	// Send auth response.
	resp := NewPack()
	resp.Add("method", TypeStr, StrValue("login"))
	resp.Add("error", TypeInt, IntValue(0))
	resp.Add("assigned_ip", TypeStr, StrValue(ss.assignedIP.String()))
	resp.Add("hubname", TypeStr, StrValue(ss.hubName))
	resp.Add("port", TypeInt, IntValue(uint32(ss.port)))

	if err := ss.writePack(resp); err != nil {
		return false, err
	}
	return true, nil
}

// verifySecurePassword recomputes the client's challenge response from the
// stored password and compares it against what arrived.
func (ss *ServerSession) verifySecurePassword(got []byte) bool {
	if ss.srv == nil || ss.srv.credentials == nil {
		return false
	}
	password, ok := ss.srv.credentials(ss.username)
	if !ok {
		// Still run the hash so a missing user and a wrong password take the
		// same time; otherwise the server enumerates its own accounts.
		password = ""
	}
	hash := sha1.Sum([]byte(ss.username + password))
	var xored [20]byte
	for i := range hash {
		xored[i] = hash[i] ^ ss.random[i]
	}
	want := sha1.Sum(xored[:])
	return ok && subtle.ConstantTimeCompare(want[:], got) == 1
}

func (ss *ServerSession) frameLoop() error {
	buf := make([]byte, MaxFrameSize+framePrefixLen)
	for {
		// Read the 4-byte length prefix.
		_, err := io.ReadFull(ss.conn, buf[:framePrefixLen])
		if err != nil {
			return fmt.Errorf("frame prefix: %w", err)
		}
		n := int(binary.LittleEndian.Uint32(buf[:framePrefixLen]))
		if n < 0 || n > MaxFrameSize {
			return fmt.Errorf("bad frame length %d", n)
		}

		// Read the Ethernet frame.
		_, err = io.ReadFull(ss.conn, buf[:n])
		if err != nil {
			return fmt.Errorf("frame body: %w", err)
		}

		frame, ok := ParseFrame(buf[:n])
		if !ok {
			continue
		}

		// A nil Destinations means flood (broadcast, multicast, or a destination
		// the bridge has not learned yet), which is standard switch behaviour.
		result := ss.bridge.Forward(frame, ss.port)
		dests := result.Destinations
		if dests == nil {
			dests = ss.bridge.FloodPorts(ss.port)
		}
		ss.forwardTo(dests, buf[:n])
	}
}

// forwardTo writes one frame to every destination port that still has a live
// session. A write failure is the peer's problem, not this session's: the
// sender must not be torn down because a different client went away.
func (ss *ServerSession) forwardTo(dests []PortID, frame []byte) {
	if ss.srv == nil {
		return
	}
	ss.srv.deliver(dests, frame, ss.port)
}

// writeFrame sends an Ethernet frame with the 4-byte length prefix.
func (ss *ServerSession) writeFrame(frame []byte) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	hdr := make([]byte, framePrefixLen)
	binary.LittleEndian.PutUint32(hdr, uint32(len(frame)))
	if _, err := ss.conn.Write(hdr); err != nil {
		return err
	}
	_, err := ss.conn.Write(frame)
	return err
}

// readPack reads a PACK message from the TLS connection.
func (ss *ServerSession) readPack() (*Pack, error) {
	// Read 4-byte length prefix.
	var lenBuf [4]byte
	if _, err := io.ReadFull(ss.conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n > maxPackSize {
		return nil, fmt.Errorf("PACK too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(ss.conn, buf); err != nil {
		return nil, err
	}
	return Decode(buf)
}

// writePack sends a PACK message with the 4-byte length prefix.
func (ss *ServerSession) writePack(p *Pack) error {
	data, err := p.Encode()
	if err != nil {
		return err
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()

	hdr := make([]byte, framePrefixLen)
	binary.LittleEndian.PutUint32(hdr, uint32(len(data)))
	if _, err := ss.conn.Write(hdr); err != nil {
		return err
	}
	_, err = ss.conn.Write(data)
	return err
}

// ClientSession is the SoftEther VPN client side.
type ClientSession struct {
	conn   *tls.Conn
	bridge *Bridge
	port   PortID
	mu     sync.Mutex

	serverRandom [20]byte
	assignedIP   net.IP
	hubName      string

	logf func(format string, args ...interface{})
}

// Connect dials a SoftEther VPN server and performs the control exchange.
func Connect(serverAddr string, tlsCfg *tls.Config, username, password, hubName string) (*ClientSession, error) {
	conn, err := tls.Dial("tcp", serverAddr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("softether: dial: %w", err)
	}

	bridge := NewBridge(DefaultAgeTime)
	port := bridge.NewPort()

	cs := &ClientSession{
		conn:    conn,
		bridge:  bridge,
		port:    port,
		hubName: hubName,
		logf:    func(string, ...interface{}) {},
	}

	// Phase 1: Hello.
	if err := cs.hello(); err != nil {
		conn.Close()
		return nil, err
	}

	// Phase 2: Authentication.
	if err := cs.login(username, password); err != nil {
		conn.Close()
		return nil, err
	}

	return cs, nil
}

func (cs *ClientSession) hello() error {
	req := NewPack()
	req.Add("method", TypeStr, StrValue("hello"))
	req.Add("ver", TypeInt, IntValue(2))
	req.Add("build", TypeInt, IntValue(1))

	if err := cs.writePack(req); err != nil {
		return err
	}

	resp, err := cs.readPack()
	if err != nil {
		return fmt.Errorf("hello response: %w", err)
	}
	method := resp.GetStr("method")
	if method != "hello" {
		return fmt.Errorf("expected hello response, got %q", method)
	}

	random := resp.GetData("random")
	if len(random) == 20 {
		copy(cs.serverRandom[:], random)
	}
	return nil
}

func (cs *ClientSession) login(username, password string) error {
	// Compute secure password: SHA1(SHA1(username+password) XOR random)
	hash := sha1.Sum([]byte(username + password))
	var xored [20]byte
	for i := range hash {
		xored[i] = hash[i] ^ cs.serverRandom[i]
	}
	securePass := sha1.Sum(xored[:])

	req := NewPack()
	req.Add("method", TypeStr, StrValue("login"))
	req.Add("username", TypeStr, StrValue(username))
	req.Add("hubname", TypeStr, StrValue(cs.hubName))
	req.Add("secure_password", TypeData, DataValue(securePass[:]))

	if err := cs.writePack(req); err != nil {
		return err
	}

	resp, err := cs.readPack()
	if err != nil {
		return fmt.Errorf("auth response: %w", err)
	}
	errorCode := resp.GetInt("error")
	if errorCode != 0 {
		return fmt.Errorf("server rejected auth: error %d", errorCode)
	}

	assignedStr := resp.GetStr("assigned_ip")
	if assignedStr != "" {
		cs.assignedIP = net.ParseIP(assignedStr)
	}
	return nil
}

// WriteFrame sends an Ethernet frame to the server.
func (cs *ClientSession) WriteFrame(frame []byte) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	hdr := make([]byte, framePrefixLen)
	binary.LittleEndian.PutUint32(hdr, uint32(len(frame)))
	if _, err := cs.conn.Write(hdr); err != nil {
		return err
	}
	_, err := cs.conn.Write(frame)
	return err
}

// ReadFrame reads an Ethernet frame from the server.
func (cs *ClientSession) ReadFrame() ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(cs.conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n > MaxFrameSize {
		return nil, fmt.Errorf("frame too large: %d", n)
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(cs.conn, buf)
	return buf, err
}

// Close closes the client session.
func (cs *ClientSession) Close() error {
	return cs.conn.Close()
}

// readPack reads a PACK from the connection.
func (cs *ClientSession) readPack() (*Pack, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(cs.conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n > maxPackSize {
		return nil, fmt.Errorf("PACK too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(cs.conn, buf); err != nil {
		return nil, err
	}
	return Decode(buf)
}

// writePack sends a PACK.
func (cs *ClientSession) writePack(p *Pack) error {
	data, err := p.Encode()
	if err != nil {
		return err
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	hdr := make([]byte, framePrefixLen)
	binary.LittleEndian.PutUint32(hdr, uint32(len(data)))
	if _, err := cs.conn.Write(hdr); err != nil {
		return err
	}
	_, err = cs.conn.Write(data)
	return err
}
