package ssh

import (
	"io"
	"net"
	"testing"

	"github.com/xen0bit/veepin/internal/vlog"
)

// fakeChannel is enough of a cryptossh.Channel for sshClient.close to call.
type fakeChannel struct{}

func (fakeChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (fakeChannel) Write(p []byte) (int, error) { return len(p), nil }
func (fakeChannel) Close() error                { return nil }
func (fakeChannel) CloseWrite() error           { return nil }
func (fakeChannel) Stderr() io.ReadWriter       { return nil }
func (fakeChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}

// TestAnAddressAnotherConnectionHoldsIsRefused: the server learns a client's
// address from its packets, so the first connection to use an address must
// keep it. If this fails, any authenticated user takes over another user's
// address with one packet and receives everything sent to it.
func TestAnAddressAnotherConnectionHoldsIsRefused(t *testing.T) {
	s := &Server{clients: map[uint32]*sshClient{}, logger: vlog.Discard()}
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	alice := &sshClient{srv: s, ch: &fakeChannel{}}
	mallory := &sshClient{srv: s, ch: &fakeChannel{}}
	const addr = 0x0ac80002 // 10.200.0.2

	if !s.bind(alice, addr, remote) {
		t.Fatal("the first connection could not take a free address")
	}
	if s.bind(mallory, addr, remote) {
		t.Fatal("a second connection took an address the first one holds")
	}
	if s.clients[addr] != alice {
		t.Fatal("the route to the address moved away from its holder")
	}

	alice.close()
	if !s.bind(mallory, addr, remote) {
		t.Fatal("an address was not freed when its holder disconnected")
	}
}
