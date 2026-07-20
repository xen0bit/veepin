package fortinet

// The server engine: an HTTPS handler that authenticates, hands out a config,
// and turns the tunnel request into a framed PPP link.
//
// It is an http.Handler so the TLS, request routing and cookies are the standard
// library's; the one unusual move is the tunnel endpoint, which hijacks the
// connection and speaks framed PPP over it with no HTTP response, as the protocol
// requires. One QUIC-free, connection-per-client shape: each tunnel is one PPP
// server session on a NoAuth link, registered under its assigned inner address so
// the shared TUN's read loop can route a packet to the right client.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/ppp"
)

// ServerConfig configures a Fortinet SSL VPN server.
type ServerConfig struct {
	// Users maps a username to its password. A user absent here is rejected.
	Users map[string]string
	// Pool allocates client addresses.
	Pool *dataplane.AddrPool
	// ServerIP is the server's own inner address (the client's gateway).
	ServerIP net.IP
	// DNS is offered to clients in the config XML.
	DNS []net.IP
	// Logger receives progress messages; nil discards them.
	Logger *log.Logger
	// Gate bounds unauthenticated work; nil installs one with the defaults.
	Gate *dataplane.Gate
}

// Server is a running Fortinet SSL VPN server. It satisfies http.Handler for the
// control and tunnel endpoints, and RunTUN drives the shared TUN's egress.
type Server struct {
	cfg  ServerConfig
	tun  io.ReadWriteCloser
	gate *dataplane.Gate
	log  *log.Logger

	mu       sync.Mutex
	pending  map[string]net.IP       // cookie -> assigned address, between login and tunnel
	links    map[netip.Addr]*pppLink // assigned address -> active tunnel
	closed   bool
	closedCh chan struct{}
}

// NewServer builds the server around a shared TUN. It does not listen; the
// caller runs an http.Server with the Server as its Handler, plus RunTUN.
func NewServer(cfg ServerConfig, tun io.ReadWriteCloser) (*Server, error) {
	if cfg.Pool == nil {
		return nil, errors.New("fortinet: no address pool configured")
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("fortinet: no users configured")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	gate := cfg.Gate
	if gate == nil {
		gate = dataplane.NewGate(dataplane.AdmissionConfig{})
	}
	return &Server{
		cfg:      cfg,
		tun:      tun,
		gate:     gate,
		log:      logger,
		pending:  map[string]net.IP{},
		links:    map[netip.Addr]*pppLink{},
		closedCh: make(chan struct{}),
	}, nil
}

// ServeHTTP dispatches the Fortinet endpoints.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case PathLoginCheck:
		s.handleLogin(w, r)
	case PathConfigXML:
		s.handleConfig(w, r)
	case PathTunnel:
		s.handleTunnel(w, r)
	case "/", "/remote/login":
		// A real client's first request is a GET for the login page. It builds
		// its own credential form and POSTs to logincheck regardless of the body,
		// so a minimal 200 with no JavaScript redirect is all it needs to proceed.
		s.handleLoginPage(w)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleLoginPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = io.WriteString(w, `<html><body><form action="`+PathLoginCheck+`" method="post">`+
		`<input name="username"><input name="credential" type="password"></form></body></html>`)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	req, err := ParseLoginForm(string(body))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pass, ok := s.cfg.Users[req.Username]
	if !ok || !cryptoutil.SecretEqual([]byte(pass), []byte(req.Password)) {
		s.log.Printf("fortinet: login failed for %q", req.Username)
		// FortiOS answers a bad login with ret=1 on a permit-all portal or an
		// error page otherwise; a plain 403 is unambiguous and is what a client
		// treats as auth failure.
		http.Error(w, "ret=4", http.StatusForbidden)
		return
	}

	if s.gate.Admit(remoteAddr(r)) != dataplane.Admitted {
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	addr, err := s.cfg.Pool.Allocate()
	if err != nil {
		s.gate.Done()
		http.Error(w, "no addresses", http.StatusServiceUnavailable)
		return
	}

	cookie := newCookie()
	s.mu.Lock()
	s.pending[cookie] = addr
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: cookie, Path: "/"})
	_, _ = io.WriteString(w, BuildLoginSuccess(PathConfigXML))
	s.log.Printf("fortinet: %q authenticated, assigned %s", req.Username, addr)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	addr, ok := s.cookieAddr(r)
	if !ok {
		http.Error(w, "no session", http.StatusForbidden)
		return
	}
	cfg := Config{
		AssignedIP: addr,
		DNS:        s.cfg.DNS,
		// No Include routes: a full tunnel, so the client installs a default route.
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write(BuildConfigXML(cfg))
}

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	addr, ok := s.cookieAddr(r)
	if !ok {
		http.Error(w, "no session", http.StatusForbidden)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot hijack", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}

	// The session moves from "pending" (holding a pool address) to an active
	// link. Admission was released for it here — its cost is now the connection,
	// not the gate.
	na, _ := netip.AddrFromSlice(addr.To4())
	na = na.Unmap()

	link := &pppLink{
		conn:        conn,
		reader:      buf.Reader, // the hijacked reader may hold buffered bytes
		tun:         s.tun,
		ownsTUN:     false,
		assignedSrc: addr,
		logger:      s.log,
		done:        make(chan struct{}),
	}
	srv := ppp.NewServer(ppp.ServerConfig{
		NoAuth:   true,
		ClientIP: addr,
		ServerIP: s.cfg.ServerIP,
		DNS:      s.cfg.DNS,
	}, link, &serverLinkHandler{})
	link.server = srv

	s.mu.Lock()
	delete(s.pending, cookieValueFrom(r))
	s.links[na] = link
	s.mu.Unlock()
	s.gate.Done()
	s.log.Printf("fortinet: tunnel up for %s", addr)

	go link.readLoop()
	srv.Start()

	// Block until the link ends, then release its address and route.
	go func() {
		_ = link.Wait()
		s.mu.Lock()
		delete(s.links, na)
		s.mu.Unlock()
		s.cfg.Pool.Release(addr)
		s.log.Printf("fortinet: tunnel for %s closed", addr)
	}()
}

// RunTUN reads the shared TUN and routes each packet to the client that owns its
// destination. It blocks until the server closes.
func (s *Server) RunTUN() {
	buf := make([]byte, maxInnerPacket)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		dst, ok := destAddr(buf[:n])
		if !ok {
			continue
		}
		s.mu.Lock()
		link := s.links[dst]
		s.mu.Unlock()
		if link == nil {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if err := link.SendPPP(ppp.EncapsulateIP(pkt)); err != nil {
			s.log.Printf("fortinet: send to %s: %v", dst, err)
		}
	}
}

// Clients reports how many tunnels are active, for tests.
func (s *Server) Clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.links)
}

// Close stops the server: it tears down active links and closes the TUN.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closedCh)
	links := make([]*pppLink, 0, len(s.links))
	for _, l := range s.links {
		links = append(links, l)
	}
	s.mu.Unlock()

	for _, l := range links {
		_ = l.Close()
	}
	if s.tun != nil {
		return s.tun.Close()
	}
	return nil
}

func (s *Server) cookieAddr(r *http.Request) (net.IP, bool) {
	cookie := cookieValueFrom(r)
	if cookie == "" {
		return nil, false
	}
	s.mu.Lock()
	addr, ok := s.pending[cookie]
	s.mu.Unlock()
	return addr, ok
}

// serverLinkHandler is the PPP server handler. With NoAuth there is nothing to
// do on these events beyond let the link proceed; routing is the TUN loop's job.
type serverLinkHandler struct{}

func (serverLinkHandler) Authenticated(_, _ string, _ [mschap.NTResponseLen]byte) {}
func (serverLinkHandler) NetworkUp()                                              {}
func (serverLinkHandler) Closed(error)                                            {}

func cookieValueFrom(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func remoteAddr(r *http.Request) *net.UDPAddr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return &net.UDPAddr{IP: net.ParseIP(host)}
}

func newCookie() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// destAddr returns the destination address of an inner IPv4 packet.
func destAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
}
