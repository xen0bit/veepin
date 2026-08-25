package wireguard

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/vlog"
	"github.com/xen0bit/veepin/internal/wireguard/noise"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// testNoiseCfg is a self-consistent handshake config: a real keypair so
// NewInitiator succeeds, which is all handshake() needs to send an initiation.
func testNoiseCfg(t *testing.T) noise.Config {
	t.Helper()
	var priv [32]byte
	for i := range priv {
		priv[i] = byte(i + 3)
	}
	pub, err := noise.PublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return noise.Config{LocalStatic: priv, RemoteStatic: pub}
}

// udpResponder starts a UDP server on loopback that runs handle for each
// datagram, returning the reply (or nil to stay silent). It reports the number
// of datagrams received, so a test can assert the initiation was retransmitted.
func udpResponder(t *testing.T, handle func(req []byte) []byte) (addr *net.UDPAddr, received *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	received = &atomic.Int32{}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, rerr := conn.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			received.Add(1)
			if reply := handle(append([]byte(nil), buf[:n]...)); reply != nil {
				_, _ = conn.WriteToUDP(reply, from)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), received
}

// TestHandshakeTimesOutOnSilence checks that a silent peer does not hang the
// dial: the context deadline shrinks each read, and an expired context ends the
// loop promptly rather than after the full attempt budget.
func TestHandshakeTimesOutOnSilence(t *testing.T) {
	addr, got := udpResponder(t, func([]byte) []byte { return nil })
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = handshake(ctx, conn, testNoiseCfg(t), discardLogger(), ObfuscationConfig{})
	if err == nil {
		t.Fatal("silent peer produced no error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("handshake took %v; should give up when the context expires", elapsed)
	}
	if got.Load() == 0 {
		t.Error("no initiation reached the peer")
	}
}

// TestHandshakeRetransmitsPastJunk checks that an unparseable reply is discarded
// and the initiation retransmitted, rather than the reply being mistaken for a
// response.
func TestHandshakeRetransmitsPastJunk(t *testing.T) {
	// Reply to every initiation with a wrong-length datagram: not a valid
	// response, so Consume rejects it and the loop tries again.
	addr, got := udpResponder(t, func([]byte) []byte {
		return make([]byte, wire.SizeHandshakeResponse-1)
	})
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if _, err := handshake(ctx, conn, testNoiseCfg(t), discardLogger(), ObfuscationConfig{}); err == nil {
		t.Fatal("junk replies produced no error")
	}
	if got.Load() < 2 {
		t.Errorf("received %d initiations; junk reply should have triggered a retransmit", got.Load())
	}
}

func discardLogger() *vlog.Logger { return vlog.Discard() }

// TestParseOptionsFromFile checks the registry entry point: a wg-quick file
// named by OptConfig is loaded, and inline options override it.
func TestParseOptionsFromFile(t *testing.T) {
	conf := "[Interface]\nPrivateKey = " + b64Key(1) + "\nAddress = 10.0.0.2/32\n" +
		"[Peer]\nPublicKey = " + b64Key(2) + "\nEndpoint = 10.0.0.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	path := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	d, err := parseOptions(map[string]string{
		OptConfig:     path,
		OptAllowedIPs: "10.0.0.0/24", // override the file's 0.0.0.0/0
	})
	if err != nil {
		t.Fatal(err)
	}
	got := d.(dialer).cfg
	if len(got.Peers) != 1 {
		t.Fatalf("Peers = %d, want 1", len(got.Peers))
	}
	if ips := got.Peers[0].AllowedIPs; len(ips) != 1 || ips[0] != "10.0.0.0/24" {
		t.Errorf("override not applied: %v", ips)
	}
	if got.Peers[0].Endpoint != "10.0.0.1:51820" {
		t.Errorf("file value lost: %q", got.Peers[0].Endpoint)
	}
}

// TestParseOptionsRejectsIncomplete checks that a config missing a required
// field fails at parse time, before any dial is attempted.
func TestParseOptionsRejectsIncomplete(t *testing.T) {
	if _, err := parseOptions(map[string]string{OptPrivateKey: b64Key(1)}); err == nil {
		t.Error("parseOptions accepted a config with no peer")
	}
}

// defaultMTU is computed from the wire format rather than written down, so this
// pins it to the number every other WireGuard implementation uses. If a change
// to the transport header moves it, the tunnel would still come up and would
// still pass every interop test -- and would quietly fragment or black-hole
// against real peers. That failure is invisible without this assertion.
func TestDefaultMTUMatchesTheProtocolConvention(t *testing.T) {
	if defaultMTU != 1420 {
		t.Errorf("defaultMTU = %d, want WireGuard's conventional 1420", defaultMTU)
	}
}

// The client parsed every address on wg-quick's Address line, validated them,
// and then kept only the first — so a dual-stack config came up IPv4-only with
// nothing logged and nothing to notice. dataplane.AddrPool6 had exactly one
// consumer in the tree; this is one of the two that were missing.
func TestAClientKeepsTheIPv6AddressItUsedToDiscard(t *testing.T) {
	c := Config{
		PrivateKey: b64Key(1),
		Address:    []string{"10.10.0.2/24", "fd00:10::2/64"},
		Peers: []Peer{{
			PublicKey:  b64Key(2),
			Endpoint:   "203.0.113.1:51820",
			AllowedIPs: []string{"0.0.0.0/0"},
		}},
	}
	r, err := c.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if got := r.address.String(); got != "10.10.0.2/24" {
		t.Errorf("address = %s", got)
	}
	if got := r.address6.String(); got != "fd00:10::2/64" {
		t.Errorf("address6 = %s, want the v6 entry to survive", got)
	}
}

// Order must not decide the family, because wg-quick does not require one.
func TestTheClientReadsAddressFamiliesByFamilyAndNotByOrder(t *testing.T) {
	c := Config{
		PrivateKey: b64Key(1),
		Address:    []string{"fd00:10::2/64", "10.10.0.2/24"},
		Peers: []Peer{{
			PublicKey:  b64Key(2),
			Endpoint:   "203.0.113.1:51820",
			AllowedIPs: []string{"0.0.0.0/0"},
		}},
	}
	r, err := c.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if !r.address.Addr().Is4() || !r.address6.Addr().Is6() {
		t.Fatalf("families crossed: v4 slot = %s, v6 slot = %s", r.address, r.address6)
	}
}

// A second address of one family would be silently dropped, which is how a
// config that looks right stops working.
func TestTheClientRefusesTwoAddressesOfOneFamily(t *testing.T) {
	for _, addrs := range [][]string{
		{"10.10.0.2/24", "10.10.1.2/24"},
		{"fd00:10::2/64", "fd00:11::2/64"},
	} {
		c := Config{
			PrivateKey: b64Key(1),
			Address:    addrs,
			Peers: []Peer{{
				PublicKey:  b64Key(2),
				Endpoint:   "203.0.113.1:51820",
				AllowedIPs: []string{"0.0.0.0/0"},
			}},
		}
		if _, err := c.resolve(); err == nil {
			t.Errorf("%v was accepted", addrs)
		}
	}
}
