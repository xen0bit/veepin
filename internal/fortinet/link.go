package fortinet

// Driving a PPP session over the framed tunnel connection.
//
// Once the HTTPS handshake is done, the TLS stream carries nothing but framed
// PPP: each record is the 6-octet Fortinet header and a bare PPP frame. pppLink
// is the glue between that byte stream and internal/ppp — it reads records and
// splits them (an IP frame to the TUN, a control frame to the PPP state machine),
// and it writes the TUN's outbound packets back out as framed PPP. It serves both
// roles; only the session it drives differs.

import (
	"io"
	"log"
	"net"
	"sync"

	"github.com/xen0bit/veepin/internal/ppp"
)

// maxInnerPacket bounds a packet read from the TUN.
const maxInnerPacket = 65535

// pppLink couples a framed net.Conn to a PPP session and a TUN.
type pppLink struct {
	conn   net.Conn
	reader io.Reader // read side; nil means read from conn (a hijacked server conn sets it)
	tun    io.ReadWriteCloser
	logger *log.Logger

	// ownsTUN is true for a client, which has the TUN to itself; false for a
	// server link, which shares one TUN across clients and must not close it.
	ownsTUN bool
	// assignedSrc, when set, is the only inner source address this link may send.
	// A server sets it so one client cannot inject traffic as another; a client
	// leaves it nil.
	assignedSrc net.IP

	// Exactly one of these drives the control frames.
	client *ppp.Session
	server *ppp.ServerSession

	writeMu   sync.Mutex // serialises writes to conn (PPP negotiation vs the TUN loop)
	done      chan struct{}
	closeOnce sync.Once
	err       error
}

// rd is the read side of the link.
func (l *pppLink) rd() io.Reader {
	if l.reader != nil {
		return l.reader
	}
	return l.conn
}

// SendPPP writes one PPP frame to the tunnel, wrapped in the Fortinet header. It
// is the ppp.Transport the session calls, and the TUN loop uses it too, so it
// holds the write lock.
func (l *pppLink) SendPPP(frame []byte) error {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	_, err := l.conn.Write(EncodeFrame(frame))
	return err
}

// readLoop reads framed records and dispatches them until the connection ends.
func (l *pppLink) readLoop() {
	for {
		frame, err := ReadFrame(l.rd())
		if err != nil {
			l.stop(err)
			return
		}
		if ipPacket, ok := ppp.IsIP(frame); ok {
			if l.assignedSrc != nil && !sourceIs(ipPacket, l.assignedSrc) {
				// A client sending from an address it was not assigned is spoofing;
				// drop it rather than let it reach the shared TUN as another client.
				continue
			}
			if _, err := l.tun.Write(ipPacket); err != nil {
				l.stop(err)
				return
			}
			continue
		}
		if l.client != nil {
			l.client.Receive(frame)
		} else {
			l.server.Receive(frame)
		}
	}
}

// tunLoop reads outbound IP packets and sends each as a framed PPP IP frame. It
// starts only once the link is up, so it never races the negotiation.
func (l *pppLink) tunLoop() {
	buf := make([]byte, maxInnerPacket)
	for {
		n, err := l.tun.Read(buf)
		if err != nil {
			l.stop(err)
			return
		}
		if err := l.SendPPP(ppp.EncapsulateIP(buf[:n])); err != nil {
			l.stop(err)
			return
		}
	}
}

// stop tears the link down once, recording the first cause. It closes the TUN
// only when it owns it, so a server link ending does not take the shared TUN —
// and every other client — down with it.
func (l *pppLink) stop(cause error) {
	l.closeOnce.Do(func() {
		l.err = cause
		close(l.done)
		_ = l.conn.Close()
		if l.ownsTUN && l.tun != nil {
			_ = l.tun.Close()
		}
	})
}

// sourceIs reports whether an IPv4 packet's source address equals ip.
func sourceIs(pkt []byte, ip net.IP) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	v4 := ip.To4()
	return v4 != nil && pkt[12] == v4[0] && pkt[13] == v4[1] && pkt[14] == v4[2] && pkt[15] == v4[3]
}

// Wait blocks until the link stops and returns why.
func (l *pppLink) Wait() error {
	<-l.done
	return l.err
}

// Close tears the link down.
func (l *pppLink) Close() error {
	l.stop(nil)
	return nil
}
