package anyconnect

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// downTUN refuses writes with EIO until it is brought up, which is what the
// Linux tun driver does for a device whose interface is still down.
type downTUN struct {
	*fakeTUN
	up bool
}

func (d *downTUN) Write(p []byte) (int, error) {
	if !d.up {
		return 0, syscall.EIO
	}
	return d.fakeTUN.Write(p)
}

// TestInboundPacketBeforeInterfaceIsUpDoesNotKillTunnel is the regression test
// for the AnyConnect interop failure that struck about one CI run in three.
//
// Dial installs no host configuration by design — the caller applies the address
// and brings the interface up after it has the Result — so there is a window in
// which the TUN exists but is down, and Linux answers a write to a down TUN with
// EIO. The read loop treated that as fatal, so a single inbound packet arriving
// in that window destroyed the session. On a slower, busier machine the window
// is wide enough to hit routinely; on a workstation it almost never is, which is
// why this passed locally 29 times in a row while failing in CI.
func TestInboundPacketBeforeInterfaceIsUpDoesNotKillTunnel(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	tun := &downTUN{fakeTUN: newFakeTUN()}
	c := NewClient(client, tun, ClientConfig{Host: "example", Username: "u", Password: "p"})

	done := make(chan error, 1)
	go func() { done <- c.Run(0) }()

	// A packet arrives while the interface is still down: it must be dropped.
	early := makeIPv4(net.IPv4(10, 11, 0, 1), net.IPv4(10, 11, 0, 2))
	if _, err := server.Write(marshal(typeData, early)); err != nil {
		t.Fatal(err)
	}

	// The session must survive it.
	select {
	case err := <-done:
		t.Fatalf("tunnel died on a packet the TUN refused: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	if got := c.Drops(); got != 1 {
		t.Errorf("drops = %d, want 1", got)
	}

	// Once the caller has configured the interface, traffic flows.
	tun.up = true
	want := makeIPv4(net.IPv4(10, 11, 0, 1), net.IPv4(10, 11, 0, 2))
	if _, err := server.Write(marshal(typeData, want)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-tun.out:
		if string(got) != string(want) {
			t.Errorf("delivered % x, want % x", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no packet reached the TUN after the interface came up")
	}

	// A genuinely broken carrier must still end the session, so the relaxation
	// above does not mask a real failure.
	server.Close()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, syscall.EIO) {
			t.Errorf("session ended with %v, want the carrier read error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session did not end when the carrier closed")
	}
}
