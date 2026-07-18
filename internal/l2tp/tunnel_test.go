package l2tp

import (
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/ppp"
)

// endpoint wires one L2TP tunnel to a PPP link for the end-to-end test. It
// implements l2tp.Handler: SessionUp starts the role's PPP session, DataFrame
// splits inbound IP from PPP control frames.
type endpoint struct {
	role Role
	tun  *Tunnel

	cli *ppp.Session
	srv *ppp.ServerSession

	pppUp chan struct{}
	ip    chan []byte
	errc  chan error
}

func newEndpoint(role Role) *endpoint {
	return &endpoint{
		role:  role,
		pppUp: make(chan struct{}, 1),
		ip:    make(chan []byte, 4),
		errc:  make(chan error, 4),
	}
}

func (e *endpoint) SessionUp() {
	if e.role == RoleLAC {
		e.cli = ppp.New("alice", "secret", e.tun, cliPPP{e})
		e.cli.Start()
		return
	}
	e.srv = ppp.NewServer(ppp.ServerConfig{
		ClientIP: net.IPv4(10, 20, 0, 2),
		ServerIP: net.IPv4(10, 20, 0, 1),
		Auth:     func(u string) (string, bool) { return "secret", u == "alice" },
	}, e.tun, srvPPP{e})
	e.srv.Start()
}

func (e *endpoint) DataFrame(frame []byte) {
	if pkt, ok := ppp.IsIP(frame); ok {
		e.ip <- pkt
		return
	}
	if e.cli != nil {
		e.cli.Receive(frame)
	}
	if e.srv != nil {
		e.srv.Receive(frame)
	}
}

func (e *endpoint) Closed(err error) {
	if err != nil {
		e.errc <- err
	}
}

// cliPPP adapts endpoint to the client-role ppp.Handler.
type cliPPP struct{ e *endpoint }

func (c cliPPP) Authenticated(nt [mschap.NTResponseLen]byte) {}
func (c cliPPP) NetworkUp(cfg ppp.IPConfig)                  { c.e.pppUp <- struct{}{} }
func (c cliPPP) Closed(err error) {
	if err != nil {
		c.e.errc <- err
	}
}

// srvPPP adapts endpoint to the server-role ppp.ServerHandler.
type srvPPP struct{ e *endpoint }

func (s srvPPP) Authenticated(u, p string, nt [mschap.NTResponseLen]byte) {}
func (s srvPPP) NetworkUp()                                               { s.e.pppUp <- struct{}{} }
func (s srvPPP) Closed(err error) {
	if err != nil {
		s.e.errc <- err
	}
}

func TestTunnelHandshakeAndPPP(t *testing.T) {
	client := newEndpoint(RoleLAC)
	server := newEndpoint(RoleLNS)

	// Two buffered channels form a bidirectional datagram pipe; a goroutine drains
	// each into the peer's HandleInbound. Delivering asynchronously (as real UDP
	// does) is required: a tunnel's send runs under its own lock, so synchronous
	// in-line delivery could re-enter that lock.
	toServer := make(chan []byte, 64)
	toClient := make(chan []byte, 64)
	client.tun = NewTunnel(RoleLAC, func(b []byte) error { toServer <- b; return nil }, client)
	server.tun = NewTunnel(RoleLNS, func(b []byte) error { toClient <- b; return nil }, server)

	done := make(chan struct{})
	go pump(done, toServer, server.tun)
	go pump(done, toClient, client.tun)
	defer close(done)

	client.tun.Start()

	// Both PPP links must reach IPCP-up.
	waitUp(t, "client", client)
	waitUp(t, "server", server)

	// An IP packet from the client must arrive at the server's data path.
	want := []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 0x40, 0x01, 0, 0, 10, 20, 0, 2, 10, 20, 0, 1}
	if err := client.tun.SendPPP(ppp.EncapsulateIP(want)); err != nil {
		t.Fatalf("SendPPP: %v", err)
	}
	select {
	case got := <-server.ip:
		if string(got) != string(want) {
			t.Errorf("server received %x, want %x", got, want)
		}
	case err := <-server.errc:
		t.Fatalf("server error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for IP packet at server")
	}
}

func pump(done <-chan struct{}, in <-chan []byte, dst *Tunnel) {
	for {
		select {
		case b := <-in:
			dst.HandleInbound(b)
		case <-done:
			return
		}
	}
}

func waitUp(t *testing.T, who string, e *endpoint) {
	t.Helper()
	select {
	case <-e.pppUp:
	case err := <-e.errc:
		t.Fatalf("%s error before up: %v", who, err)
	case <-time.After(2 * time.Second):
		t.Fatalf("%s timed out before PPP up", who)
	}
}
