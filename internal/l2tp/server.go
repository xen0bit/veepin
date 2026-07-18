package l2tp

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev1"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/ppp"
)

// ServerConfig configures the L2TP/IPsec server engine.
type ServerConfig struct {
	PSK     []byte
	Users   map[string]string   // username -> password for MS-CHAPv2
	Pool    *dataplane.AddrPool // inner address pool
	Gateway net.IP              // server's inner address (pool's first host)
	DNS     []net.IP
	Logger  *log.Logger
}

// Server is a running L2TP/IPsec responder. Every client rides one shared UDP
// socket, demultiplexed by source address into a per-peer IKEv1 responder, ESP
// transport SA, L2TP LNS tunnel and PPP session. A single TUN is shared, with
// inbound IP routed to the owning peer by inner destination address.
type Server struct {
	cfg     ServerConfig
	conn    *net.UDPConn
	tun     tunIO
	pool    *dataplane.AddrPool
	gateway net.IP
	logger  *log.Logger

	mu    sync.Mutex
	peers map[string]*serverPeer // keyed by remote address
	byIP  map[uint32]*serverPeer // inner IP -> peer, for TUN egress

	done      chan struct{}
	closeOnce sync.Once
}

// NewServer builds a server over a bound UDP socket and a TUN.
func NewServer(conn *net.UDPConn, tun tunIO, cfg ServerConfig) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{
		cfg:     cfg,
		conn:    conn,
		tun:     tun,
		pool:    cfg.Pool,
		gateway: cfg.Gateway,
		logger:  logger,
		peers:   map[string]*serverPeer{},
		byIP:    map[uint32]*serverPeer{},
		done:    make(chan struct{}),
	}
}

// Serve runs the data path until Close. It blocks.
func (s *Server) Serve() error {
	go s.tunLoop()
	s.recvLoop()
	return nil
}

// Close stops the server.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.conn.Close()
	})
	return nil
}

func (s *Server) recvLoop() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		if msg, ok := isIKE(pkt); ok {
			s.peerFor(addr).ike.HandleInbound(msg)
			continue
		}
		if p := s.peerByAddr(addr); p != nil {
			p.handleESP(pkt)
		}
	}
}

// peerFor returns the peer for a remote address, creating an IKE responder for a
// newly seen one.
func (s *Server) peerFor(addr *net.UDPAddr) *serverPeer {
	key := addr.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.peers[key]; ok {
		return p
	}
	p := &serverPeer{srv: s, addr: addr}
	p.ike = ikev1.NewSession(ikev1.Config{
		Role:    ikev1.Responder,
		PSK:     s.cfg.PSK,
		LocalIP: s.gateway,
		PeerIP:  addr.IP,
		Send:    func(m []byte) error { _, err := s.conn.WriteToUDP(markIKE(m), addr); return err },
		Handler: p,
		Logger:  s.logger,
	})
	s.peers[key] = p
	s.logger.Printf("l2tp: new peer %s", key)
	return p
}

func (s *Server) peerByAddr(addr *net.UDPAddr) *serverPeer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peers[addr.String()]
}

func (s *Server) peerByIP(ip net.IP) *serverPeer {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byIP[binary.BigEndian.Uint32(v4)]
}

func (s *Server) mapIP(ip net.IP, p *serverPeer) {
	if v4 := ip.To4(); v4 != nil {
		s.mu.Lock()
		s.byIP[binary.BigEndian.Uint32(v4)] = p
		s.mu.Unlock()
	}
}

func (s *Server) removePeer(p *serverPeer, err error) {
	s.mu.Lock()
	if _, ok := s.peers[p.addr.String()]; !ok {
		s.mu.Unlock()
		return
	}
	delete(s.peers, p.addr.String())
	if v4 := p.innerIP.To4(); v4 != nil {
		delete(s.byIP, binary.BigEndian.Uint32(v4))
	}
	s.mu.Unlock()

	if p.innerIP != nil {
		s.pool.Release(p.innerIP)
	}
	p.mu.Lock()
	t := p.tunnel
	p.mu.Unlock()
	if t != nil {
		t.Close()
	}
	s.logger.Printf("l2tp: peer %s gone: %v", p.addr, err)
}

func (s *Server) auth(username string) (string, bool) {
	pw, ok := s.cfg.Users[username]
	return pw, ok
}

// tunLoop routes TUN egress to the peer owning the inner destination address.
func (s *Server) tunLoop() {
	buf := make([]byte, 65535)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		dst := ipv4Dst(buf[:n])
		if dst == nil {
			continue
		}
		p := s.peerByIP(dst)
		if p == nil {
			continue
		}
		p.mu.Lock()
		t := p.tunnel
		p.mu.Unlock()
		if t != nil {
			_ = t.SendPPP(ppp.EncapsulateIP(append([]byte(nil), buf[:n]...)))
		}
	}
}

// serverPeer is one client's state on the server.
type serverPeer struct {
	srv  *Server
	addr *net.UDPAddr
	ike  *ikev1.Session

	mu      sync.Mutex
	sa      *esp.SA
	tunnel  *Tunnel
	ppp     *ppp.ServerSession
	innerIP net.IP
}

func (p *serverPeer) handleESP(pkt []byte) {
	p.mu.Lock()
	sa, tun := p.sa, p.tunnel
	p.mu.Unlock()
	if sa == nil || tun == nil {
		return
	}
	inner, nh, err := sa.Decapsulate(pkt)
	if err != nil || nh != ipProtoUDP {
		return
	}
	if l2, ok := unwrapUDP(inner); ok {
		tun.HandleInbound(l2)
	}
}

// --- ikev1.Handler ---

func (p *serverPeer) Established(r ikev1.Result) {
	p.mu.Lock()
	p.sa = newESPSA(r)
	p.tunnel = NewTunnel(RoleLNS, p.espSend, p) // LNS starts passively on SCCRQ
	p.mu.Unlock()
	p.srv.logger.Printf("l2tp: IPsec SA established with %s", p.addr)
}

func (p *serverPeer) Failed(err error) { p.srv.removePeer(p, err) }

func (p *serverPeer) espSend(l2tp []byte) error {
	p.mu.Lock()
	sa := p.sa
	p.mu.Unlock()
	if sa == nil {
		return errors.New("l2tp: ESP SA not ready")
	}
	pkt, err := sa.Encapsulate(wrapUDP(l2tp), ipProtoUDP)
	if err != nil {
		return err
	}
	_, err = p.srv.conn.WriteToUDP(pkt, p.addr)
	return err
}

// --- l2tp.Handler ---

func (p *serverPeer) SessionUp() {
	ip, err := p.srv.pool.Allocate()
	if err != nil {
		p.srv.removePeer(p, err)
		return
	}
	p.mu.Lock()
	p.innerIP = ip
	p.ppp = ppp.NewServer(ppp.ServerConfig{
		ClientIP: ip,
		ServerIP: p.srv.gateway,
		DNS:      p.srv.cfg.DNS,
		Auth:     p.srv.auth,
	}, p.tunnel, serverPPP{p})
	ps := p.ppp
	p.mu.Unlock()
	p.srv.mapIP(ip, p)
	p.srv.logger.Printf("l2tp: L2TP session up for %s, assigning %s", p.addr, ip)
	ps.Start()
}

func (p *serverPeer) DataFrame(frame []byte) {
	if ip, ok := ppp.IsIP(frame); ok {
		_, _ = p.srv.tun.Write(ip)
		return
	}
	p.mu.Lock()
	ps := p.ppp
	p.mu.Unlock()
	if ps != nil {
		ps.Receive(frame)
	}
}

func (p *serverPeer) Closed(err error) { p.srv.removePeer(p, err) }

// serverPPP adapts serverPeer to ppp.ServerHandler.
type serverPPP struct{ p *serverPeer }

func (h serverPPP) Authenticated(u, pw string, nt [mschap.NTResponseLen]byte) {}
func (h serverPPP) NetworkUp() {
	h.p.srv.logger.Printf("l2tp: PPP up for %s", h.p.addr)
}
func (h serverPPP) Closed(err error) { h.p.srv.removePeer(h.p, err) }

// ipv4Dst extracts the destination address from an IPv4 packet.
func ipv4Dst(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
}
