package toy

// The server engine: one socket, many clients, one shared TUN.
//
// The multi-client shape is the interesting half of the example. Handshakes are
// handled here; established sessions are handed to the pump, which routes
// outbound packets to the right client by inner destination and inbound packets
// to the right session by demux key. A server never looks at a source address
// to decide who a packet is from.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xen0bit/veepin/dataplane"
)

// SessionTimeout is how long a session survives without inbound traffic. The
// keepalive interval is well inside it, so a live peer never trips it.
const SessionTimeout = 60 * time.Second

// ServerConfig is what the server engine needs.
type ServerConfig struct {
	// Users maps a username to its secret. A user absent here is rejected.
	Users map[string]string
	// Pool allocates client addresses.
	Pool *dataplane.AddrPool
	// DNS is offered to clients in WELCOME.
	DNS []netip.Addr
	// MTU is offered to clients in WELCOME.
	MTU uint16
	// Logger receives progress messages; nil discards them.
	Logger *log.Logger
}

// pending is a handshake between CHALLENGE and AUTH.
type pending struct {
	clientNonce [NonceLen]byte
	serverNonce [NonceLen]byte
	user        string
	assigned    net.IP
	created     time.Time
}

// Server is a running TOY server.
type Server struct {
	conn *net.UDPConn
	tun  *dataplane.TUN
	pump *dataplane.Pump
	cfg  ServerConfig
	log  *log.Logger

	mu       sync.Mutex
	pending  map[uint16]*pending
	sessions map[uint16]*Session
	assigned map[uint16]net.IP
	closed   bool

	done chan struct{}
	wg   sync.WaitGroup
}

// NewServer builds a server around an open socket and TUN.
func NewServer(conn *net.UDPConn, tun *dataplane.TUN, cfg ServerConfig) (*Server, error) {
	if cfg.Pool == nil {
		return nil, errors.New("toy: no address pool configured")
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("toy: no users configured")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(discard{}, "", 0)
	}

	s := &Server{
		conn:     conn,
		tun:      tun,
		cfg:      cfg,
		log:      logger,
		pending:  map[uint16]*pending{},
		sessions: map[uint16]*Session{},
		assigned: map[uint16]net.IP{},
		done:     make(chan struct{}),
	}

	send := func(pkt []byte, to *net.UDPAddr) {
		if _, err := conn.WriteToUDP(pkt, to); err != nil {
			logger.Printf("toy: send: %v", err)
		}
	}
	s.pump = dataplane.NewPump(tun, send, SessionOf, logger)
	return s, nil
}

// Run serves until Close. It blocks.
func (s *Server) Run() error {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.pump.Run()
	}()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.expireLoop()
	}()

	buf := make([]byte, 65535)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("toy: read: %w", err)
		}
		s.handle(buf[:n], from)
	}
}

func (s *Server) handle(pkt []byte, from *net.UDPAddr) {
	h, body, err := ParseHeader(pkt)
	if err != nil {
		// Anything that is not TOY is ignored without comment; a public UDP
		// port receives a lot of noise.
		return
	}

	switch h.Type {
	case MsgHello:
		s.handleHello(body, from)
	case MsgAuth:
		s.handleAuth(h, body, from)
	case MsgData, MsgKeepalive:
		s.handleSealed(h, pkt, from)
	case MsgBye:
		// Advisory only: unauthenticated, so acting on it would let anyone
		// disconnect anyone. Logged and dropped.
		s.log.Printf("toy: session %d sent BYE (advisory; ignoring)", h.Session)
	}
}

func (s *Server) handleHello(body []byte, from *net.UDPAddr) {
	hello, err := ParseHello(body)
	if err != nil {
		s.log.Printf("toy: malformed HELLO from %v: %v", from, err)
		return
	}
	if _, ok := s.cfg.Users[hello.User]; !ok {
		// The username is not confirmed until AUTH, so this only says the name
		// is unknown. Rejecting here avoids allocating for a name that can
		// never authenticate.
		s.reject(from, 0, "unknown user")
		s.log.Printf("toy: HELLO from %v for unknown user %q", from, hello.User)
		return
	}

	// A HELLO is retransmitted whenever the CHALLENGE is lost, so handling it
	// must be idempotent. Allocating a fresh session and a fresh pool address
	// per HELLO would let a lossy link burn one address per retransmission --
	// ten attempts, ten addresses, until the pending timeout reclaims them --
	// and a peer that simply repeated the message could exhaust the pool.
	//
	// The client nonce identifies the attempt, so a repeat replays the same
	// CHALLENGE for the same session instead.
	if id, ok := s.pendingFor(hello.Nonce); ok {
		s.mu.Lock()
		p := s.pending[id]
		s.mu.Unlock()
		if p != nil {
			out := AppendHeader(nil, Header{Type: MsgChallenge, Session: id, Counter: 1})
			out = AppendNonce(out, p.serverNonce[:])
			if _, err := s.conn.WriteToUDP(out, from); err != nil {
				s.log.Printf("toy: resending CHALLENGE to %v: %v", from, err)
			}
			return
		}
	}

	id, err := s.newSessionID()
	if err != nil {
		s.reject(from, 0, "no session available")
		return
	}
	assigned, err := s.cfg.Pool.Allocate()
	if err != nil {
		s.reject(from, 0, "address pool exhausted")
		s.log.Printf("toy: pool exhausted for %v", from)
		return
	}

	p := &pending{user: hello.User, assigned: assigned, created: time.Now()}
	p.clientNonce = hello.Nonce
	if _, err := rand.Read(p.serverNonce[:]); err != nil {
		s.cfg.Pool.Release(assigned)
		s.log.Printf("toy: generating nonce: %v", err)
		return
	}

	s.mu.Lock()
	s.pending[id] = p
	s.mu.Unlock()

	out := AppendHeader(nil, Header{Type: MsgChallenge, Session: id, Counter: 1})
	out = AppendNonce(out, p.serverNonce[:])
	if _, err := s.conn.WriteToUDP(out, from); err != nil {
		s.log.Printf("toy: sending CHALLENGE to %v: %v", from, err)
	}
}

func (s *Server) handleAuth(h Header, body []byte, from *net.UDPAddr) {
	proof, err := ParseFixed(body, TagLen)
	if err != nil {
		return
	}

	s.mu.Lock()
	p, ok := s.pending[h.Session]
	s.mu.Unlock()
	if !ok {
		// Either a stale retransmission after the session was established, or a
		// guess at a session ID. Neither deserves a reply.
		return
	}

	secret := s.cfg.Users[p.user]
	if !CheckProof(secret, p.clientNonce[:], p.serverNonce[:], proof) {
		// The handshake is deliberately left intact.
		//
		// Session IDs travel in the clear, so anyone who saw the CHALLENGE knows
		// this one. Discarding the pending state here would mean a single forged
		// AUTH -- which costs an attacker nothing and requires no secret --
		// cancels a legitimate client's handshake and strands the address it had
		// been promised. Keeping it lets the real client still complete, and the
		// pending timeout reclaims the address if nobody ever does.
		//
		// This is the same rule as checking a packet tag before touching the
		// replay window: unauthenticated input must not be able to destroy state.
		s.reject(from, h.Session, "authentication failed")
		s.log.Printf("toy: session %d: authentication failed for %q", h.Session, p.user)
		return
	}

	key := DeriveKey(secret, p.clientNonce[:], p.serverNonce[:])

	addr, ok := netip.AddrFromSlice(p.assigned.To4())
	if !ok {
		s.log.Printf("toy: session %d: assigned address %v is not IPv4", h.Session, p.assigned)
		return
	}
	// A server-side tunnel carries exactly one inner address: the client's.
	// That is what makes the pump route the right packet to the right client.
	routes := []netip.Prefix{netip.PrefixFrom(addr, 32)}

	sess := NewSession(h.Session, key, from, routes)
	sess.User = p.user
	sess.counter.Store(2) // counters 1 and 2 belonged to the handshake

	s.mu.Lock()
	delete(s.pending, h.Session)
	s.sessions[h.Session] = sess
	s.assigned[h.Session] = p.assigned
	s.mu.Unlock()

	s.pump.AddTunnel(sess)

	gw, _ := netip.AddrFromSlice(s.cfg.Pool.Gateway().To4())
	mask, _ := netip.AddrFromSlice(s.cfg.Pool.Netmask().To4())
	w := Welcome{
		AssignedIP: addr,
		Netmask:    mask,
		Gateway:    gw,
		MTU:        s.cfg.MTU,
		DNS:        s.cfg.DNS,
	}

	out := AppendHeader(nil, Header{Type: MsgWelcome, Session: h.Session, Counter: 2})
	out = AppendWelcome(out, w)
	if _, err := s.conn.WriteToUDP(out, from); err != nil {
		s.log.Printf("toy: sending WELCOME to %v: %v", from, err)
	}
	s.log.Printf("toy: session %d established for %q at %v, assigned %v",
		h.Session, p.user, from, addr)
}

// handleSealed routes an authenticated data or keepalive packet.
func (s *Server) handleSealed(h Header, pkt []byte, from *net.UDPAddr) {
	s.mu.Lock()
	sess, ok := s.sessions[h.Session]
	s.mu.Unlock()
	if !ok {
		return
	}

	// A packet may be opened exactly once: opening it consumes its counter in
	// the replay window, so a second attempt on the same datagram would be
	// rejected as a replay of itself.
	//
	// Keepalives are opened here, because nothing downstream wants them. Data is
	// handed to the pump, which opens it via Decapsulate and writes the inner
	// packet to the TUN -- that is the whole reason the pump exists, and doing
	// it by hand here would leave the example demonstrating nothing.
	if h.Type == MsgKeepalive {
		if _, _, err := sess.OpenAny(pkt); err != nil {
			s.log.Printf("toy: session %d: bad keepalive: %v", h.Session, err)
			return
		}
		s.roam(h.Session, sess, from)
		return
	}

	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	s.pump.HandleInbound(cp, from)

	// Liveness is recorded by Session.open itself, on the one code path that can
	// vouch for it. Roaming still has to happen here, because Decapsulate never
	// learns the source address -- but it is only safe once something on this
	// session has authenticated, so an unopened packet cannot move a peer.
	if !sess.LastSeen().IsZero() {
		s.roam(h.Session, sess, from)
	}
}

// roam follows a peer that has started arriving from a new address.
func (s *Server) roam(id uint16, sess *Session, from *net.UDPAddr) {
	if cur := sess.PeerAddr(); cur == nil || cur.String() != from.String() {
		s.log.Printf("toy: session %d roamed to %v", id, from)
		sess.SetPeerAddr(from)
	}
}

func (s *Server) reject(to *net.UDPAddr, session uint16, reason string) {
	out := AppendHeader(nil, Header{Type: MsgReject, Session: session, Counter: 1})
	out = AppendReject(out, reason)
	_, _ = s.conn.WriteToUDP(out, to)
}

// pendingFor finds a handshake already under way for a client nonce, so a
// retransmitted HELLO replays its CHALLENGE rather than starting again.
func (s *Server) pendingFor(nonce [NonceLen]byte) (uint16, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, p := range s.pending {
		if p.clientNonce == nonce {
			return id, true
		}
	}
	return 0, false
}

// newSessionID picks an unused, unpredictable session ID.
//
// Unpredictability matters more than it looks: the ID is the only session
// selector a packet carries, so a guessable one would let an off-path attacker
// aim forged packets at a specific session.
func (s *Server) newSessionID() (uint16, error) {
	var b [2]byte
	for range 64 {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		id := binary.BigEndian.Uint16(b[:])
		if id == 0 {
			continue // reserved for "not yet assigned"
		}
		s.mu.Lock()
		_, p := s.pending[id]
		_, e := s.sessions[id]
		s.mu.Unlock()
		if !p && !e {
			return id, nil
		}
	}
	return 0, errors.New("toy: no free session ID")
}

// expireLoop drops sessions that have gone quiet, releasing their addresses.
func (s *Server) expireLoop() {
	t := time.NewTicker(SessionTimeout / 4)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.expire()
		}
	}
}

func (s *Server) expire() {
	now := time.Now()

	s.mu.Lock()
	var dead []uint16
	for id, sess := range s.sessions {
		// A session that has authenticated nothing yet is judged from when it
		// was established, which WELCOME set as its first liveness mark.
		seen := sess.LastSeen()
		if seen.IsZero() {
			seen = sess.established
		}
		if now.Sub(seen) > SessionTimeout {
			dead = append(dead, id)
		}
	}
	// A handshake that never completed also holds an address.
	var stale []uint16
	for id, p := range s.pending {
		if now.Sub(p.created) > SessionTimeout {
			stale = append(stale, id)
		}
	}

	type doomed struct {
		sess *Session
		ip   net.IP
	}
	var drop []doomed
	for _, id := range dead {
		drop = append(drop, doomed{s.sessions[id], s.assigned[id]})
		delete(s.sessions, id)
		delete(s.assigned, id)
	}
	for _, id := range stale {
		drop = append(drop, doomed{nil, s.pending[id].assigned})
		delete(s.pending, id)
	}
	s.mu.Unlock()

	for _, d := range drop {
		if d.sess != nil {
			s.pump.RemoveTunnel(d.sess)
			s.log.Printf("toy: session %d expired", d.sess.ID)
		}
		if d.ip != nil {
			s.cfg.Pool.Release(d.ip)
		}
	}
}

// Sessions reports how many sessions are established, for tests.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	s.mu.Unlock()

	s.pump.Close()
	err := s.conn.Close()
	if s.tun != nil {
		_ = s.tun.Close()
	}
	s.wg.Wait()
	return err
}
