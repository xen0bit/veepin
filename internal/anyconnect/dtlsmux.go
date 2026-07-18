package anyconnect

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/xen0bit/veepin/internal/dtls"
)

// The server's DTLS listener.
//
// One UDP socket serves every client, so datagrams have to be routed to the
// right session before any key is available to authenticate them. A datagram
// from a known peer address goes to that peer; one from an unknown address is
// examined for a ClientHello whose session-id is an App-ID this server issued
// over HTTPS, which is the only thing that can start a new session here.
//
// The App-ID is unauthenticated at that point and is used purely as a lookup
// key. Forging one gets an attacker as far as a handshake they cannot complete,
// since the pre-shared key is derived from the TLS session and still has to
// match at Finished.

// peerQueueDepth bounds the datagrams buffered for a peer that is not reading.
// Dropping is the right response to a full queue: this is UDP, and the DTLS
// layer above already tolerates loss.
const peerQueueDepth = 64

// dtlsListener demultiplexes one UDP socket into per-peer connections.
type dtlsListener struct {
	conn   *net.UDPConn
	logger interface{ Printf(string, ...any) }

	mu      sync.Mutex
	peers   map[string]*peerConn // by remote address
	pending map[string]*pendingSession
	closed  bool
}

// pendingSession is an App-ID a server has issued but whose UDP flow has not
// arrived yet, together with the key that flow will be authenticated with.
type pendingSession struct {
	psk    []byte
	accept func(*dtls.Conn)
	mtu    int
}

func newDTLSListener(conn *net.UDPConn, logger interface{ Printf(string, ...any) }) *dtlsListener {
	return &dtlsListener{
		conn:    conn,
		logger:  logger,
		peers:   map[string]*peerConn{},
		pending: map[string]*pendingSession{},
	}
}

// expect registers an App-ID this server has handed to a client, so the UDP flow
// that presents it can be matched to the session that authorised it.
func (l *dtlsListener) expect(appID string, s *pendingSession) {
	l.mu.Lock()
	l.pending[appID] = s
	l.mu.Unlock()
}

// forget drops an App-ID once its session ends.
func (l *dtlsListener) forget(appID string) {
	l.mu.Lock()
	delete(l.pending, appID)
	l.mu.Unlock()
}

// serve routes datagrams until the socket closes.
func (l *dtlsListener) serve() {
	buf := make([]byte, maxPayload)
	for {
		n, addr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			l.shutdown()
			return
		}
		pkt := append([]byte(nil), buf[:n]...)

		l.mu.Lock()
		p, known := l.peers[addr.String()]
		l.mu.Unlock()
		if known {
			p.deliver(pkt)
			continue
		}
		l.maybeStart(addr, pkt)
	}
}

// maybeStart begins a session when a datagram is a ClientHello naming an App-ID
// this server issued. Anything else is ignored — an unknown peer cannot make the
// server allocate.
func (l *dtlsListener) maybeStart(addr *net.UDPAddr, pkt []byte) {
	id, ok := dtls.ClientHelloSessionID(pkt)
	if !ok {
		return
	}
	l.mu.Lock()
	sess, expected := l.pending[string(id)]
	if !expected || l.closed {
		l.mu.Unlock()
		return
	}
	p := newPeerConn(l, addr)
	l.peers[addr.String()] = p
	l.mu.Unlock()

	p.deliver(pkt)
	go l.handshake(p, sess)
}

// handshake completes the DTLS server handshake for a newly seen peer and hands
// the connection to the session that was waiting for it.
func (l *dtlsListener) handshake(p *peerConn, sess *pendingSession) {
	conn, err := dtls.Server(p, dtls.Config{
		PSK:              sess.psk,
		MTU:              sess.mtu,
		HandshakeTimeout: dtlsHandshakeTimeout,
	})
	if err != nil {
		l.logger.Printf("anyconnect: DTLS handshake with %s failed: %v", p.peer, err)
		l.drop(p)
		return
	}
	sess.accept(conn)
}

func (l *dtlsListener) drop(p *peerConn) {
	l.mu.Lock()
	if l.peers[p.peer.String()] == p {
		delete(l.peers, p.peer.String())
	}
	l.mu.Unlock()
	p.closeQueue()
}

func (l *dtlsListener) shutdown() {
	l.mu.Lock()
	l.closed = true
	peers := make([]*peerConn, 0, len(l.peers))
	for _, p := range l.peers {
		peers = append(peers, p)
	}
	l.peers = map[string]*peerConn{}
	l.mu.Unlock()
	for _, p := range peers {
		p.closeQueue()
	}
}

func (l *dtlsListener) close() error { return l.conn.Close() }

// peerConn is a net.Conn for one peer over the shared socket: reads come from
// the demultiplexer's queue, writes go straight out addressed to that peer.
type peerConn struct {
	l    *dtlsListener
	peer *net.UDPAddr

	queue chan []byte

	mu       sync.Mutex
	closed   bool
	deadline time.Time
}

func newPeerConn(l *dtlsListener, peer *net.UDPAddr) *peerConn {
	return &peerConn{l: l, peer: peer, queue: make(chan []byte, peerQueueDepth)}
}

// deliver hands a datagram to the peer, dropping it if the peer is not keeping
// up rather than blocking the shared read loop.
func (p *peerConn) deliver(pkt []byte) {
	select {
	case p.queue <- pkt:
	default:
	}
}

func (p *peerConn) Read(b []byte) (int, error) {
	p.mu.Lock()
	deadline := p.deadline
	p.mu.Unlock()

	var timeout <-chan time.Time
	if !deadline.IsZero() {
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case pkt, ok := <-p.queue:
		if !ok {
			return 0, io.EOF
		}
		return copy(b, pkt), nil
	case <-timeout:
		return 0, errTimeout{}
	}
}

func (p *peerConn) Write(b []byte) (int, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	return p.l.conn.WriteToUDP(b, p.peer)
}

func (p *peerConn) Close() error {
	p.l.drop(p)
	return nil
}

func (p *peerConn) closeQueue() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	close(p.queue)
}

func (p *peerConn) LocalAddr() net.Addr  { return p.l.conn.LocalAddr() }
func (p *peerConn) RemoteAddr() net.Addr { return p.peer }

func (p *peerConn) SetDeadline(t time.Time) error    { return p.SetReadDeadline(t) }
func (p *peerConn) SetWriteDeadline(time.Time) error { return nil }
func (p *peerConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	return nil
}

// errTimeout is a net.Error the DTLS retransmission logic recognises as a
// timeout rather than a fatal read error.
type errTimeout struct{}

func (errTimeout) Error() string   { return "anyconnect: DTLS read timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }

var _ net.Error = errTimeout{}
