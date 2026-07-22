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
	PSK   []byte
	Users map[string]string // username -> password for MS-CHAPv2
	// PublicIP is the server's outer address as clients reach it. It becomes the
	// IKE identity and the phase-2 traffic selector, so a server listening on the
	// wildcard — where the socket cannot name it — must be told.
	PublicIP net.IP
	Pool     *dataplane.AddrPool // inner address pool
	Gateway  net.IP              // server's inner address (pool's first host)
	DNS      []net.IP
	Logger   *log.Logger
}

// Server is a running L2TP/IPsec responder. It binds two sockets — the IKE port
// for Main Mode and the NAT-T port for everything after the float — and gives
// each client a per-peer IKEv1 responder, ESP transport SA, L2TP LNS tunnel and
// PPP session. A single TUN is shared, with inbound IP routed to the owning peer
// by inner destination address.
//
// Peers are keyed by initiator cookie for IKE and by inbound SPI for ESP, not by
// remote address: NAT-T moves a session to a different port mid-exchange, and a
// NAT rebinding can move it again afterwards, so the address is tracked as
// mutable state rather than used as identity.
type Server struct {
	cfg      ServerConfig
	ikeConn  *dataplane.PacketConn // port 500: Main Mode
	nattConn *dataplane.PacketConn // port 4500: floated IKE + UDP-encapsulated ESP
	tun      tunIO
	pool     *dataplane.AddrPool
	gateway  net.IP
	logger   *log.Logger
	gate     *dataplane.Gate

	mu       sync.Mutex
	byCookie map[[8]byte]*serverPeer // initiator cookie -> peer, for IKE
	bySPI    map[uint32]*serverPeer  // our inbound ESP SPI -> peer
	byIP     map[uint32]*serverPeer  // inner IP -> peer, for TUN egress

	done      chan struct{}
	closeOnce sync.Once
}

// NewServer builds a server over the two bound UDP sockets and a TUN.
func NewServer(rawIKE, rawNATT *net.UDPConn, tun tunIO, cfg ServerConfig) *Server {
	ikeConn := dataplane.NewPacketConn(rawIKE)
	nattConn := dataplane.NewPacketConn(rawNATT)
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{
		cfg:      cfg,
		ikeConn:  ikeConn,
		nattConn: nattConn,
		tun:      tun,
		pool:     cfg.Pool,
		gateway:  cfg.Gateway,
		logger:   logger,
		gate:     dataplane.NewGate(dataplane.AdmissionConfig{}),
		byCookie: map[[8]byte]*serverPeer{},
		bySPI:    map[uint32]*serverPeer{},
		byIP:     map[uint32]*serverPeer{},
		done:     make(chan struct{}),
	}
}

// Serve runs the data path until Close. It blocks.
func (s *Server) Serve() error {
	go s.tunLoop()
	go s.recvIKE()
	s.recvNATT()
	return nil
}

// Close stops the server.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.ikeConn.Close()
		s.nattConn.Close()
	})
	return nil
}

// recvIKE reads the plain IKE port. Every datagram here is a bare Main Mode
// message — the float moves a session off this socket for good.
func (s *Server) recvIKE() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.ikeConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.dispatchIKE(append([]byte(nil), buf[:n]...), addr, false)
	}
}

// recvNATT reads the NAT-T port, where IKE and ESP share a socket and the
// non-ESP marker tells them apart. Reads are batched
// (dataplane.PacketConn.ReadBatch): one recvmmsg drains up to readBatch
// datagrams under load and blocks like a plain read when idle. Unlike the flat
// ESP protocols, every datagram is still copied out: the L2TP engine behind
// handleESP parses control AVPs whose handling may alias the packet beyond
// this loop, so only the syscalls are batched, not the buffer ownership.
func (s *Server) recvNATT() {
	const readBatch = 16
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	froms := make([]*net.UDPAddr, readBatch)
	for {
		n, err := s.nattConn.ReadBatch(bufs, sizes, froms)
		for i := range n {
			pkt, addr := append([]byte(nil), bufs[i][:sizes[i]]...), froms[i]
			if msg, ok := isIKE(pkt); ok {
				s.dispatchIKE(msg, addr, true)
				continue
			}
			if p := s.peerBySPI(pkt); p != nil {
				p.noteAddr(addr)
				p.handleESP(pkt)
			}
		}
		if err != nil {
			return
		}
	}
}

// dispatchIKE routes an IKE message to the peer owning its initiator cookie,
// creating a responder for a cookie not seen before.
func (s *Server) dispatchIKE(msg []byte, addr *net.UDPAddr, natt bool) {
	cookie, ok := ikev1.InitiatorCookie(msg)
	if !ok {
		return
	}
	p := s.peerFor(cookie, addr)
	if p == nil {
		// Refused by admission control; already logged.
		return
	}
	p.noteIKEAddr(addr, natt)
	p.ike.HandleInbound(msg)
}

// peerFor returns the peer owning an initiator cookie, creating an IKE responder
// for a newly seen one. It returns nil when admission control refuses.
//
// This is where an unauthenticated peer makes the server allocate: the cookie is
// chosen by the initiator, so without a bound, traffic with a varying cookie
// creates one IKE responder -- with its Diffie-Hellman state -- per message.
func (s *Server) peerFor(cookie [8]byte, addr *net.UDPAddr) *serverPeer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.byCookie[cookie]; ok {
		return p
	}

	if r := s.gate.Admit(addr); r != dataplane.Admitted {
		s.logger.Printf("l2tp: refusing new peer %s: %v", addr, r)
		return nil
	}

	p := &serverPeer{
		srv:    s,
		cookie: cookie,
		addr:   addr,
		// Until the client's floated source port is observed, assume it binds the
		// NAT-T port itself, which an un-NATed peer does.
		nattAddr: &net.UDPAddr{IP: addr.IP, Port: nattPort},
	}
	p.ike = ikev1.NewSession(ikev1.Config{
		Role:      ikev1.Responder,
		PSK:       s.cfg.PSK,
		LocalIP:   s.publicIP(),
		PeerIP:    addr.IP,
		LocalPort: defaultIKEPort,
		PeerPort:  uint16(addr.Port),
		Send:      p.sendIKE,
		Handler:   p,
		Logger:    s.logger,
	})
	s.byCookie[cookie] = p
	s.logger.Printf("l2tp: new peer %s (cookie %x)", addr, cookie)
	return p
}

// publicIP is the address the server presents as its IKE identity and phase-2
// traffic selector: the configured one, else the IKE socket's bound address when
// it is concrete. Listening on the wildcard without configuring one leaves it
// nil, which yields an empty ID — workable only with a peer matching on %any.
func (s *Server) publicIP() net.IP {
	if s.cfg.PublicIP != nil {
		return s.cfg.PublicIP
	}
	if la, ok := s.ikeConn.LocalAddr().(*net.UDPAddr); ok && !la.IP.IsUnspecified() {
		return la.IP
	}
	return nil
}

// peerBySPI finds the peer an inbound ESP packet belongs to by its SPI.
func (s *Server) peerBySPI(pkt []byte) *serverPeer {
	if len(pkt) < 4 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bySPI[binary.BigEndian.Uint32(pkt[:4])]
}

func (s *Server) mapSPI(spi uint32, p *serverPeer) {
	s.mu.Lock()
	s.bySPI[spi] = p
	s.mu.Unlock()
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

// removePeer drops a peer from every index and releases its resources. It is
// idempotent: the tunnel's Closed callback re-enters it during teardown, and the
// map-presence check makes the second call a no-op.
func (s *Server) removePeer(p *serverPeer, err error) {
	s.mu.Lock()
	if _, ok := s.byCookie[p.cookie]; !ok {
		s.mu.Unlock()
		return
	}
	delete(s.byCookie, p.cookie)
	if p.inSPI != 0 {
		delete(s.bySPI, p.inSPI)
	}
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
	srv    *Server
	cookie [8]byte
	ike    *ikev1.Session

	mu       sync.Mutex
	addr     *net.UDPAddr // where Main Mode came from
	nattAddr *net.UDPAddr // where floated IKE and ESP go
	sa       *esp.SA
	inSPI    uint32
	tunnel   *Tunnel
	ppp      *ppp.ServerSession
	innerIP  net.IP
}

// noteIKEAddr records where a peer's IKE now comes from. After the float that is
// a new source port, and a NAT rebinding can change it again, so replies follow
// the address the last message actually arrived from.
func (p *serverPeer) noteIKEAddr(addr *net.UDPAddr, natt bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if natt {
		p.nattAddr = addr
	} else {
		p.addr = addr
	}
}

// noteAddr tracks the source of inbound ESP, so outbound ESP follows a peer
// whose NAT binding moves.
func (p *serverPeer) noteAddr(addr *net.UDPAddr) {
	p.mu.Lock()
	if p.nattAddr.Port != addr.Port || !p.nattAddr.IP.Equal(addr.IP) {
		p.nattAddr = addr
	}
	p.mu.Unlock()
}

func (p *serverPeer) sendIKE(msg []byte, natt bool) error {
	p.mu.Lock()
	ike, nat := p.addr, p.nattAddr
	p.mu.Unlock()
	if natt {
		_, err := p.srv.nattConn.WriteToUDP(markIKE(msg), nat)
		return err
	}
	_, err := p.srv.ikeConn.WriteToUDP(msg, ike)
	return err
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
	p.inSPI = r.InSPI
	p.tunnel = NewTunnel(RoleLNS, p.espSend, p) // LNS starts passively on SCCRQ
	p.mu.Unlock()
	p.srv.mapSPI(r.InSPI, p)
	p.srv.logger.Printf("l2tp: IPsec SA established with %s (spi in=%#x out=%#x)", p.addr, r.InSPI, r.OutSPI)
}

func (p *serverPeer) Failed(err error) { p.srv.removePeer(p, err) }

func (p *serverPeer) espSend(l2tp []byte) error {
	p.mu.Lock()
	sa, to := p.sa, p.nattAddr
	p.mu.Unlock()
	if sa == nil {
		return errors.New("l2tp: ESP SA not ready")
	}
	pkt, err := sa.Encapsulate(wrapUDP(l2tp), ipProtoUDP)
	if err != nil {
		return err
	}
	_, err = p.srv.nattConn.WriteToUDP(pkt, to)
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
