package openvpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/openvpn/control"
	"github.com/xen0bit/veepin/internal/openvpn/data"
	"github.com/xen0bit/veepin/internal/openvpn/wire"
)

// muxer owns the single UDP socket and splits inbound datagrams by opcode:
// control packets go to the TLS control channel, data packets to the pump once
// the data path is up. Keeping one reader on the socket lets both channels share
// it.
type muxer struct {
	conn    *net.UDPConn
	control *control.Channel
	logger  *log.Logger

	mu   sync.Mutex
	pump *dataplane.Pump // nil until the data path is established

	closeOnce sync.Once
	closed    chan struct{}
}

func (m *muxer) setPump(p *dataplane.Pump) {
	m.mu.Lock()
	m.pump = p
	m.mu.Unlock()
}

// readLoop reads datagrams until the socket closes, dispatching each by opcode.
// Reads are batched (dataplane.BatchConn over the connected socket): one
// recvmmsg drains up to readBatch datagrams under load and blocks like a plain
// read when idle.
func (m *muxer) readLoop() {
	const readBatch = 16
	bc := dataplane.NewBatchConn(m.conn)
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	for {
		n, err := bc.ReadBatch(bufs, sizes)
		for i := range n {
			pkt := bufs[i][:sizes[i]]
			op, _, ok := wire.Opcode(pkt)
			if !ok {
				continue
			}
			switch {
			case data.IsDataOpcode(op):
				m.mu.Lock()
				pump := m.pump
				m.mu.Unlock()
				if pump != nil {
					// No copy: the pump decrypts in place and writes the TUN
					// before returning; bufs[i] is not touched again until the
					// next ReadBatch. The socket source is implicit on a
					// connected client socket, so pass nil.
					pump.HandleInbound(pkt, nil)
				}
			case wire.IsControl(op):
				m.control.Deliver(pkt) // copies internally
			}
		}
		if err != nil {
			return
		}
	}
}

func (m *muxer) Close() {
	m.closeOnce.Do(func() {
		close(m.closed)
		if m.control != nil {
			m.control.Close()
		}
		m.conn.Close() // unblocks readLoop
	})
}

// dataCipher is the data-channel crypto the tunnel drives: either the AES-256-GCM
// Cipher or the AES-256-CBC CBCCipher, chosen by the negotiated cipher.
type dataCipher interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(pkt []byte) ([]byte, error)
}

// tunnel is the data-path view of the server connection. It implements
// dataplane.Tunnel: everything from the TUN is sealed to the one server, and
// inbound data packets are opened and (if a keepalive ping) dropped.
type tunnel struct {
	cipher dataCipher
	routes []netip.Prefix
	peer   atomic.Pointer[net.UDPAddr]
}

func (t *tunnel) InboundKey() uint32                   { return dataTunnelKey }
func (t *tunnel) Routes() []netip.Prefix               { return t.routes }
func (t *tunnel) PeerAddr() *net.UDPAddr               { return t.peer.Load() }
func (t *tunnel) Encapsulate(p []byte) ([]byte, error) { return t.cipher.Seal(p) }

func (t *tunnel) Decapsulate(pkt []byte) ([]byte, error) {
	pt, err := t.cipher.Open(pkt)
	if err != nil {
		return nil, err
	}
	if data.IsPing(pt) {
		return nil, nil // keepalive: authenticated but nothing to deliver
	}
	return pt, nil
}

// session is a running OpenVPN tunnel. It implements client.Session.
type session struct {
	muxer  *muxer
	tun    *dataplane.TUN
	pump   *dataplane.Pump
	tunnel *tunnel
	conn   *net.UDPConn
	logger *log.Logger

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}
}

// keepalive sends a data-channel ping now and on an interval, so the server (and
// any NAT on the path) keeps the session alive even when the TUN is idle.
func (s *session) keepalive() {
	s.sendPing()
	tick := time.NewTicker(keepaliveInterval)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.sendPing()
		}
	}
}

func (s *session) sendPing() {
	pkt, err := s.tunnel.Encapsulate(data.Ping)
	if err != nil {
		s.logger.Printf("openvpn: keepalive: %v", err)
		return
	}
	if _, err := s.conn.Write(pkt); err != nil {
		s.logger.Printf("openvpn: keepalive send: %v", err)
	}
}

// Wait blocks until the session is closed or ctx is cancelled.
func (s *session) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the data path, control channel, socket and TUN. It is
// idempotent.
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.pump != nil {
			s.pump.Close()
		}
		if s.tun != nil {
			s.tun.Close()
		}
		s.muxer.Close()
	})
	return s.closeErr
}

// pushConfig is the subset of a PUSH_REPLY this client applies.
type pushConfig struct {
	localIP net.IP
	netmask net.IP
	gateway net.IP
	peerID  uint32
	mtu     int
	cipher  string // the data cipher the server negotiated, if it pushed one
}

// parsePush decodes a server PUSH_REPLY, extracting the tunnel address, gateway,
// peer-id and MTU. An AUTH_FAILED reply is mapped to an auth error.
func parsePush(reply string) (*pushConfig, error) {
	if strings.HasPrefix(reply, "AUTH_FAILED") {
		return nil, fmt.Errorf("%w: %s", client.ErrAuth, reply)
	}
	if !strings.HasPrefix(reply, "PUSH_REPLY") {
		return nil, fmt.Errorf("unexpected server reply: %q", reply)
	}
	p := &pushConfig{mtu: defaultMTU}
	for opt := range strings.SplitSeq(reply, ",") {
		fields := strings.Fields(opt)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "ifconfig":
			if len(fields) >= 2 {
				p.localIP = net.ParseIP(fields[1])
			}
			if len(fields) >= 3 {
				second := net.ParseIP(fields[2])
				if isNetmask(second) {
					p.netmask = second
				} else {
					p.gateway = second
					p.netmask = net.IPv4(255, 255, 255, 255)
				}
			}
		case "route-gateway":
			if len(fields) >= 2 {
				p.gateway = net.ParseIP(fields[1])
			}
		case "peer-id":
			if len(fields) >= 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil {
					p.peerID = uint32(n)
				}
			}
		case "cipher":
			if len(fields) >= 2 {
				p.cipher = fields[1]
			}
		case "tun-mtu":
			if len(fields) >= 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil {
					p.mtu = n
				}
			}
		}
	}
	if p.localIP == nil {
		return nil, errors.New("server pushed no ifconfig address")
	}
	if p.netmask == nil {
		p.netmask = net.IPv4(255, 255, 255, 0)
	}
	if p.gateway == nil {
		p.gateway = p.localIP
	}
	return p, nil
}

// isNetmask reports whether an IPv4 value looks like a subnet mask rather than a
// peer address — a mask's leading octet is 255 (topology subnet), which a tunnel
// peer address is not.
func isNetmask(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 255
}
