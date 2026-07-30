//go:build linux

package dataplane

// What these pin is the one property the device did not have: a read parked on
// an idle interface can be interrupted.
//
// Most of them run without CAP_NET_ADMIN by building a TUN over a pipe. That is
// not a mock -- it is the same *TUN, the same non-blocking fd, the same poll and
// the same eventfd, with a descriptor the test can control rather than a kernel
// interface it cannot open. The one test that needs a real device says so and
// skips.

import (
	"errors"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// pipeTUN builds a TUN over one end of a pipe and returns the other end. dir
// picks which end the TUN owns: "read" for the read tests, "write" for the ones
// that fill the queue.
func pipeTUN(t *testing.T, dir string) (*TUN, int) {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	own, peer := fds[0], fds[1]
	if dir == "write" {
		own, peer = fds[1], fds[0]
	}
	tun, err := newTUN(own, "pipe0", false)
	if err != nil {
		t.Fatalf("newTUN: %v", err)
	}
	t.Cleanup(func() {
		_ = tun.Close()
		_ = unix.Close(peer)
	})
	return tun, peer
}

// A read parked on an idle device must return when the device is closed. This is
// the bug: with a blocking fd, close(2) does not wake a thread already in
// read(2), so this test hangs until the timeout instead of returning ErrClosed --
// and a protocol whose Close waits for its packet pump hangs with it.
func TestCloseUnblocksAReadParkedOnAnIdleDevice(t *testing.T) {
	tun, _ := pipeTUN(t, "read")

	parked := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		_, err := tun.Read(buf)
		parked <- err
	}()

	// Give the reader time to reach poll, so this closes a genuinely parked
	// read rather than racing it to the first syscall.
	time.Sleep(50 * time.Millisecond)

	closed := make(chan error, 1)
	go func() { closed <- tun.Close() }()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return; it is waiting on the read it is supposed to interrupt")
	}

	select {
	case err := <-parked:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("parked Read returned %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read stayed parked after Close; the wake fd did not interrupt the poll")
	}
}

// Waking on close is only half of it. A device that woke on close but not on
// traffic would pass the test above and carry no packets at all, so this pins
// the other edge: a packet arriving while the reader is parked is delivered.
func TestReadDeliversAPacketThatArrivesWhileParked(t *testing.T) {
	tun, peer := pipeTUN(t, "read")

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2048)
		n, err := tun.Read(buf)
		if err != nil {
			got <- nil
			return
		}
		got <- append([]byte(nil), buf[:n]...)
	}()

	time.Sleep(50 * time.Millisecond)
	want := []byte{0x45, 0x00, 0xde, 0xad}
	if _, err := unix.Write(peer, want); err != nil {
		t.Fatalf("write to peer: %v", err)
	}

	select {
	case pkt := <-got:
		if string(pkt) != string(want) {
			t.Fatalf("read %x, want %x", pkt, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet never reached the parked reader")
	}
}

// The reason Read holds mu across its syscall. Once Close has returned, the
// descriptor number is free and the kernel hands it to the next opener; a Read
// that still named it would read from an unrelated file. It must report
// ErrClosed off the latch instead, without issuing a syscall at all.
func TestReadAfterCloseNeverTouchesARecycledDescriptor(t *testing.T) {
	tun, _ := pipeTUN(t, "read")
	number := tun.fd

	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Linux hands out the lowest free descriptor, so this should land on the
	// number the TUN just released -- which is the whole point of the test.
	f, err := os.Open("/dev/zero")
	if err != nil {
		t.Fatalf("open /dev/zero: %v", err)
	}
	defer f.Close()
	if int(f.Fd()) != number {
		t.Skipf("descriptor %d was not recycled (got %d); nothing to prove here", number, int(f.Fd()))
	}

	buf := make([]byte, 8)
	n, err := tun.Read(buf)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Read after Close returned (%d, %v), want ErrClosed -- it read from the recycled descriptor", n, err)
	}
}

// Close is idempotent, for the same reason: a second close(2) would land on
// whatever file has since taken the number. Servers do call it twice -- a
// protocol's Close and a deferred cleanup in the same path.
func TestCloseIsIdempotent(t *testing.T) {
	tun, _ := pipeTUN(t, "read")
	if err := tun.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("second Close: %v, want nil", err)
	}
}

// A blocking fd absorbed a full device queue by parking in the kernel; a
// non-blocking one returns EAGAIN, and Write has to wait for room rather than
// report a failure the caller cannot act on. Filling a pipe stands in for a
// backed-up interface.
func TestWriteWaitsForRoomRatherThanFailing(t *testing.T) {
	tun, peer := pipeTUN(t, "write")

	// Fill the pipe. The buffer is 64 KiB by default, so this reaches EAGAIN
	// well inside the loop bound.
	chunk := make([]byte, 4096)
	filled := false
	for range 64 {
		// Straight at the descriptor, bypassing Write's own wait: newTUN
		// already made it non-blocking, so this reports the full queue rather
		// than parking on it.
		if _, err := unix.Write(tun.fd, chunk); err == unix.EAGAIN {
			filled = true
			break
		} else if err != nil {
			t.Fatalf("filling the pipe: %v", err)
		}
	}
	if !filled {
		t.Skip("could not fill the pipe buffer; nothing to wait on")
	}

	done := make(chan error, 1)
	go func() {
		_, err := tun.Write(chunk)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("Write returned %v while the queue was full; it should have waited for room", err)
	case <-time.After(100 * time.Millisecond):
	}

	// Drain, and the parked write must complete.
	drain := make([]byte, 8192)
	for range 16 {
		if _, err := unix.Read(peer, drain); err != nil {
			break
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Write after the queue drained: %v", err)
			}
			return
		default:
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Write after the queue drained: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Write stayed parked after the queue drained")
	}
}

// A write parked on a full queue must be interruptible too, or Close blocks on
// the outbound half instead of the inbound one.
func TestCloseUnblocksAParkedWrite(t *testing.T) {
	tun, _ := pipeTUN(t, "write")

	chunk := make([]byte, 4096)
	filled := false
	for range 64 {
		if _, err := unix.Write(tun.fd, chunk); err == unix.EAGAIN {
			filled = true
			break
		} else if err != nil {
			t.Fatalf("filling the pipe: %v", err)
		}
	}
	if !filled {
		t.Skip("could not fill the pipe buffer; nothing to wait on")
	}

	done := make(chan error, 1)
	go func() {
		_, err := tun.Write(chunk)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)

	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("parked Write returned %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Write stayed parked after Close")
	}
}

// The level the bug actually showed up at: a pump reading an idle TUN must stop
// when the device is closed. Every protocol here closes its TUN and then waits
// for this goroutine, so a Run that does not return is a Close that does not
// either.
func TestPumpRunReturnsWhenTheTUNIsClosed(t *testing.T) {
	tun, _ := pipeTUN(t, "read")
	p := NewPump(tun, func(pkt []byte, to *net.UDPAddr) {}, nil, log.New(os.Stderr, "", 0))

	stopped := make(chan struct{})
	go func() {
		p.Run()
		close(stopped)
	}()
	time.Sleep(50 * time.Millisecond)

	p.Close()
	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Pump.Run did not return after the TUN was closed")
	}
}

// The same claim against a real kernel device, which is the one thing a pipe
// cannot stand in for: /dev/net/tun's poll implementation, and the interaction
// with TUNSETIFF. Skipped without the capability rather than passing quietly on
// a path it never entered.
func TestCloseUnblocksARealTUNRead(t *testing.T) {
	tun, err := OpenTUN("")
	if err != nil {
		t.Skipf("needs CAP_NET_ADMIN to open a TUN; run the suite as root or under `unshare -rn` (%v)", err)
	}

	parked := make(chan error, 1)
	go func() {
		buf := make([]byte, 65535)
		_, rerr := tun.Read(buf)
		parked <- rerr
	}()
	// The interface is never brought up, so nothing will ever arrive on it --
	// exactly the idle tunnel the old code could not close.
	time.Sleep(100 * time.Millisecond)

	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-parked:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("parked Read returned %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read on a real idle TUN stayed parked after Close")
	}
}
