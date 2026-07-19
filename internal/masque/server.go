package masque

// The server engine: one QUIC endpoint, many clients, one shared TUN.
//
// Each client is one QUIC connection carrying one CONNECT-IP request stream.
// After the request is accepted the server assigns an address from the pool,
// advertises a route, and registers the client under its inner address so the
// TUN read loop can route a packet to it. There is no source-address demux and
// no replay window: QUIC identifies the connection, and the request stream is
// the tunnel.
//
// The one thing this must not trust is the inner source address. A client may
// only send packets from the address it was assigned; a packet whose source is
// anything else is a spoof and is dropped, which is what stops one client from
// injecting traffic as another.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/masque/http3"
	"golang.org/x/net/quic"
)

// ServerConfig is what the server engine needs.
type ServerConfig struct {
	// Pool allocates client addresses.
	Pool *dataplane.AddrPool
	// MTU is the inner MTU; it is advisory here, since MASQUE has no capsule to
	// carry it, but it bounds the TUN read buffer.
	MTU int
	// Logger receives progress messages; nil discards them.
	Logger *log.Logger
	// Gate bounds unauthenticated work. Nil installs one with the package
	// defaults; an unbounded server is not a supported configuration.
	Gate *dataplane.Gate
}

// peer is one established client.
type peer struct {
	rs       *http3.RequestStream
	h3       *http3.Conn
	assigned netip.Addr

	// writeMu serialises capsule writes to this client's stream. The TUN loop is
	// the only writer today, but making that a lock rather than an assumption
	// keeps a second writer from being a silent data race later.
	writeMu sync.Mutex
}

// Server is a running CONNECT-IP proxy.
type Server struct {
	end  *quic.Endpoint
	tun  tunDevice
	gate *dataplane.Gate
	cfg  ServerConfig
	log  *log.Logger

	mu     sync.Mutex
	peers  map[netip.Addr]*peer
	closed bool

	done chan struct{}
	wg   sync.WaitGroup
}

// NewServer builds a server around a QUIC endpoint and a shared TUN.
func NewServer(end *quic.Endpoint, tun tunDevice, cfg ServerConfig) (*Server, error) {
	if cfg.Pool == nil {
		return nil, errors.New("masque: no address pool configured")
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
		end:   end,
		tun:   tun,
		gate:  gate,
		cfg:   cfg,
		log:   logger,
		peers: map[netip.Addr]*peer{},
		done:  make(chan struct{}),
	}, nil
}

// Run serves until Close. It blocks.
func (s *Server) Run() error {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.tunLoop()
	}()

	for {
		qc, err := s.end.Accept(context.Background())
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("masque: accept: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(qc)
		}()
	}
}

// handleConn runs one client connection from CONNECT to teardown.
func (s *Server) handleConn(qc *quic.Conn) {
	remote := udpAddrOf(qc.RemoteAddr())
	if r := s.gate.Admit(remote); r != dataplane.Admitted {
		s.log.Printf("masque: refusing connection from %v: %v", remote, r)
		qc.Abort(errServerBusy)
		return
	}
	// Admission is released once the client is established or the attempt fails;
	// admitted() is deferred so no early return leaks a slot.
	admitted := true
	defer func() {
		if admitted {
			s.gate.Done()
		}
	}()

	ctx := context.Background()
	h3conn, err := http3.Server(ctx, qc)
	if err != nil {
		s.log.Printf("masque: http/3 setup from %v: %v", remote, err)
		return
	}

	rs, fields, err := h3conn.AcceptConnect(ctx)
	if err != nil {
		s.log.Printf("masque: awaiting CONNECT from %v: %v", remote, err)
		_ = h3conn.Close()
		return
	}
	if !IsConnectIP(fields) {
		_ = rs.WriteResponse([]http3.Field{{Name: ":status", Value: "400"}})
		s.log.Printf("masque: non-CONNECT-IP request from %v", remote)
		_ = h3conn.Close()
		return
	}

	assigned, err := s.cfg.Pool.Allocate()
	if err != nil {
		_ = rs.WriteResponse([]http3.Field{{Name: ":status", Value: "503"}})
		s.log.Printf("masque: pool exhausted for %v", remote)
		_ = h3conn.Close()
		return
	}
	addr, ok := netip.AddrFromSlice(assigned.To4())
	if !ok {
		s.cfg.Pool.Release(assigned)
		_ = h3conn.Close()
		return
	}
	addr = addr.Unmap()

	if err := rs.WriteResponse([]http3.Field{
		{Name: ":status", Value: "200"},
		{Name: "capsule-protocol", Value: "?1"},
	}); err != nil {
		s.cfg.Pool.Release(assigned)
		_ = h3conn.Close()
		return
	}

	// Advertise a full-tunnel route, then assign the address. The order matters
	// for a client that treats ADDRESS_ASSIGN as the end of setup: sending the
	// route first means it is in hand before the client stops reading. The
	// assignment is a /32 -- one client, one host address.
	route := EncodeRoutes([]RouteEntry{{
		Start:    netip.IPv4Unspecified(),
		End:      netip.AddrFrom4([4]byte{255, 255, 255, 255}),
		Protocol: 0,
	}})
	if err := WriteCapsule(rs, CapsuleRouteAdvertisement, route); err != nil {
		s.cfg.Pool.Release(assigned)
		_ = h3conn.Close()
		return
	}
	// The address is assigned with the pool's prefix length rather than as a
	// bare /32, so the inner gateway lands on the client's connected subnet and
	// is reachable without a separate route -- the same shape every other
	// protocol here hands back.
	ones, _ := s.cfg.Pool.Network().Mask.Size()
	assign := EncodeAddresses([]AddressEntry{{RequestID: 0, Prefix: netip.PrefixFrom(addr, ones)}})
	if err := WriteCapsule(rs, CapsuleAddressAssign, assign); err != nil {
		s.cfg.Pool.Release(assigned)
		_ = h3conn.Close()
		return
	}

	p := &peer{rs: rs, h3: h3conn, assigned: addr}
	s.mu.Lock()
	s.peers[addr] = p
	s.mu.Unlock()

	// The client is established: its cost is now bounded by the connection
	// lifetime rather than the admission gate.
	s.gate.Done()
	admitted = false
	s.log.Printf("masque: client %v established, assigned %v", remote, addr)

	s.serveClient(p, remote)
}

// serveClient reads datagrams from one client and writes them to the TUN, until
// the stream ends. It releases the client's resources on the way out.
func (s *Server) serveClient(p *peer, remote *net.UDPAddr) {
	defer func() {
		s.mu.Lock()
		delete(s.peers, p.assigned)
		s.mu.Unlock()
		s.cfg.Pool.Release(net.IP(p.assigned.AsSlice()))
		_ = p.h3.Close()
		s.log.Printf("masque: client %v (%v) disconnected", remote, p.assigned)
	}()

	for {
		capsule, err := ReadCapsule(p.rs)
		if err != nil {
			return
		}
		if capsule.Type != CapsuleDatagram {
			// ADDRESS_REQUEST after setup, or an unknown capsule: not part of the
			// data path here.
			continue
		}
		ip, ok, err := DecodeDatagramPayload(capsule.Value)
		if err != nil || !ok {
			continue
		}
		// A client may only send from the address it was assigned. Anything else
		// is a spoof: drop it rather than let one client source traffic as
		// another.
		if src, ok := innerSrc(ip); !ok || src != p.assigned {
			continue
		}
		if _, err := s.tun.Write(ip); err != nil {
			s.log.Printf("masque: TUN write: %v", err)
			return
		}
	}
}

// tunLoop reads packets leaving the shared TUN and routes each to the client
// that owns its destination address.
func (s *Server) tunLoop() {
	buf := make([]byte, maxInnerPacket)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		dst, ok := innerDst(buf[:n])
		if !ok {
			continue
		}
		s.mu.Lock()
		p := s.peers[dst]
		s.mu.Unlock()
		if p == nil {
			// No client owns this destination; nothing to deliver it to.
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		payload := EncodeDatagramPayload(pkt)

		p.writeMu.Lock()
		err = WriteCapsule(p.rs, CapsuleDatagram, payload)
		p.writeMu.Unlock()
		if err != nil {
			s.log.Printf("masque: sending to %v: %v", dst, err)
		}
	}
}

// Clients reports how many clients are established, for tests.
func (s *Server) Clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.peers)
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

	err := s.end.Close(context.Background())
	if s.tun != nil {
		_ = s.tun.Close()
	}
	s.wg.Wait()
	return err
}

var errServerBusy = errors.New("masque: server busy")

// udpAddrOf converts a netip.AddrPort to the *net.UDPAddr the admission gate
// keys on.
func udpAddrOf(ap netip.AddrPort) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(ap)
}
