package udpmux

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// newTestMux binds a mux on loopback and returns it with a dialer for peers.
func newTestMux(t *testing.T, start func(*net.UDPAddr, []byte) func(*Conn)) *Mux {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	m := New(sock, 2048, start)
	go m.Serve()
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// dialTo opens a connected UDP socket to the mux.
func dialTo(t *testing.T, m *Mux) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp", nil, m.Socket().LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// admit drives one datagram at the mux and returns the Conn it started.
func admit(t *testing.T, m *Mux, got <-chan *Conn) *Conn {
	t.Helper()
	peer := dialTo(t, m)
	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-got:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("the mux never started a peer")
		return nil
	}
}

// A datagram delivered after the peer was dropped must be discarded. This is not
// a corner case: Serve looks the peer up under the Mux lock and delivers outside
// it, so a Drop completing in the gap is an ordinary interleaving. Closing the
// queue on Drop made that delivery a send on a closed channel -- a panic that
// takes the whole gateway down because one peer went away.
func TestADeliveryAfterDropIsDiscarded(t *testing.T) {
	got := make(chan *Conn, 1)
	m := newTestMux(t, func(*net.UDPAddr, []byte) func(*Conn) {
		return func(p *Conn) { got <- p }
	})
	conn := admit(t, m, got)

	m.Drop(conn)
	conn.deliver([]byte("late"))
}

// The same thing with the two racing rather than ordered, for the detector.
func TestDeliveryAndDropMayRunConcurrently(t *testing.T) {
	got := make(chan *Conn, 1)
	m := newTestMux(t, func(*net.UDPAddr, []byte) func(*Conn) {
		return func(p *Conn) { got <- p }
	})
	for range 50 {
		conn := admit(t, m, got)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range queueDepth * 2 {
				conn.deliver([]byte("x"))
			}
		}()
		go func() {
			defer wg.Done()
			m.Drop(conn)
		}()
		wg.Wait()
	}
}

// A dropped peer reads EOF, so the session above ends rather than blocking on a
// queue nothing will ever fill again.
func TestADroppedPeerReadsEOF(t *testing.T) {
	got := make(chan *Conn, 1)
	m := newTestMux(t, func(*net.UDPAddr, []byte) func(*Conn) {
		return func(p *Conn) { got <- p }
	})
	peer := dialTo(t, m)
	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	conn := <-got

	// The first datagram is already queued; it must still be readable.
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("Read = %q, %v; want the first datagram", buf[:n], err)
	}

	blocked := make(chan error, 1)
	go func() {
		_, err := conn.Read(buf)
		blocked <- err
	}()
	time.Sleep(50 * time.Millisecond)
	m.Drop(conn)

	select {
	case err := <-blocked:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Read after Drop = %v, want io.EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return after the peer was dropped")
	}
}

// Writing to a dropped peer is refused rather than sent: the session is over,
// and the socket underneath is shared with every other peer.
func TestWritingToADroppedPeerIsRefused(t *testing.T) {
	got := make(chan *Conn, 1)
	m := newTestMux(t, func(*net.UDPAddr, []byte) func(*Conn) {
		return func(p *Conn) { got <- p }
	})
	peer := dialTo(t, m)
	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	conn := <-got

	if _, err := conn.Write([]byte("reply")); err != nil {
		t.Fatalf("Write to a live peer = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("reply")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close = %v, want net.ErrClosed", err)
	}
	// Close is Drop, and Drop is idempotent: a second one must not panic.
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	m.Drop(conn)
}

// Losing the socket ends every peer, not just the ones someone remembered to
// drop -- otherwise a server shutdown leaks a goroutine per client.
func TestClosingTheSocketEndsEveryPeer(t *testing.T) {
	got := make(chan *Conn, 2)
	m := newTestMux(t, func(*net.UDPAddr, []byte) func(*Conn) {
		return func(p *Conn) { got <- p }
	})
	for range 2 {
		peer := dialTo(t, m)
		if _, err := peer.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
	}
	a, b := <-got, <-got

	_ = m.Close()
	for i, conn := range []*Conn{a, b} {
		done := make(chan error, 1)
		go func() {
			buf := make([]byte, 64)
			for {
				_, err := conn.Read(buf)
				if err != nil {
					done <- err
					return
				}
			}
		}()
		select {
		case err := <-done:
			if !errors.Is(err, io.EOF) {
				t.Errorf("peer %d read %v after the socket closed, want io.EOF", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("peer %d never saw the socket close", i)
		}
	}
}

// A datagram from an address the start callback declines allocates nothing, so
// an unsolicited flood cannot fill the peer table.
func TestADeclinedDatagramAllocatesNoPeer(t *testing.T) {
	m := newTestMux(t, func(*net.UDPAddr, []byte) func(*Conn) { return nil })
	peer := dialTo(t, m)
	for range 20 {
		if _, err := peer.Write([]byte("junk")); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	m.mu.Lock()
	n := len(m.peers)
	m.mu.Unlock()
	if n != 0 {
		t.Errorf("the mux holds %d peers after %d declined datagrams, want 0", n, 20)
	}
}

// A peer that stops reading must not stall the shared read loop: its datagrams
// are dropped, which is what UDP already means.
func TestASlowPeerIsDroppedRatherThanBlockingTheLoop(t *testing.T) {
	got := make(chan *Conn, 1)
	served := make(chan struct{})
	m := newTestMux(t, func(*net.UDPAddr, []byte) func(*Conn) {
		return func(p *Conn) { got <- p; <-served }
	})
	peer := dialTo(t, m)
	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	conn := <-got

	for range queueDepth * 4 {
		if _, err := peer.Write([]byte("flood")); err != nil {
			t.Fatal(err)
		}
	}

	// The loop is still routing: a fresh peer is still admitted.
	other := dialTo(t, m)
	if _, err := other.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the read loop stalled behind a peer that was not reading")
	}
	close(served)
	_ = conn
}
