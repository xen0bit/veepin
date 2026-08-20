package ikev2

import (
	"context"
	"maps"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/ike"
)

func TestDialValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing server", Config{PSK: "k", LocalID: "id"}},
		{"missing psk", Config{Server: "s", LocalID: "id"}},
		{"missing localid", Config{Server: "s", PSK: "k"}},
		{"all empty", Config{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, _, err := Dial(context.Background(), tc.cfg)
			if err == nil {
				sess.Close()
				t.Fatal("expected validation error, got nil")
			}
			if sess != nil {
				t.Fatal("expected nil session on error")
			}
		})
	}
}

// TestDialConnectFailure ensures a failed handshake reports an error and leaves
// nothing running. An unresolvable host fails fast (no TUN, no root needed).
func TestDialConnectFailure(t *testing.T) {
	sess, _, err := Dial(context.Background(), Config{
		Server:  "no-such-host.invalid",
		PSK:     "k",
		LocalID: "client.example",
	})
	if err == nil {
		sess.Close()
		t.Fatal("expected connect failure, got nil")
	}
	if sess != nil {
		t.Fatalf("expected nil session on connect failure, got %v", sess)
	}
}

// TestDialContextCancelled verifies Dial aborts an in-flight handshake when the
// context is cancelled, instead of waiting out the IKE read deadlines. A silent
// UDP server accepts the SA_INIT but never replies, so the handshake would
// otherwise block for ~10s.
func TestDialContextCancelled(t *testing.T) {
	silent, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer silent.Close()
	srvPort := silent.LocalAddr().(*net.UDPAddr).Port

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	sess, _, err := Dial(ctx, Config{
		Server:  "127.0.0.1",
		Port:    srvPort,
		PSK:     "k",
		LocalID: "client.example",
	})
	elapsed := time.Since(start)

	if err == nil {
		sess.Close()
		t.Fatal("expected Dial to fail after cancellation")
	}
	if sess != nil {
		t.Fatal("expected nil session on cancellation")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Dial took %v; cancellation did not abort the handshake promptly", elapsed)
	}
}

func TestParseIdentity(t *testing.T) {
	if id := parseIdentity("10.0.0.1"); id.Type != ike.IPIdentity(net.IPv4(10, 0, 0, 1)).Type {
		t.Errorf("IP literal did not parse as an IP identity: %+v", id)
	}
	if id := parseIdentity("vpn.example.com"); id.Type != ike.FQDNIdentity("vpn.example.com").Type {
		t.Errorf("hostname did not parse as an FQDN identity: %+v", id)
	}
}

func TestServerGateway(t *testing.T) {
	// ServerAddr present: use it directly.
	res := &ike.ClientResult{ServerAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 4500}}
	if gw := serverGateway(res, "ignored.example"); !gw.Equal(net.IPv4(203, 0, 113, 5)) {
		t.Errorf("gateway from ServerAddr = %v, want 203.0.113.5", gw)
	}
	// No ServerAddr: parse an IP-literal host.
	if gw := serverGateway(&ike.ClientResult{}, "198.51.100.7"); !gw.Equal(net.IPv4(198, 51, 100, 7)) {
		t.Errorf("gateway from host literal = %v, want 198.51.100.7", gw)
	}
}

// TestAShaperUnderAConstantRateIsRefusedRatherThanIgnored.
//
// The paced data path does not go through dataplane's shaper at all -- the pump
// hands packets to the tunnel and sends nothing itself -- so accepting both
// would leave -shape doing nothing while the operator believed it was on. That
// is the same bug this tree has already had once, as `-kill-switch` under
// `-no-route`, and it is the reason the pair is a parse error.
//
// It costs nothing to refuse: constant-rate transmission fixes every datagram
// at one size, which is what -shape pads *towards*.
func TestAShaperUnderAConstantRateIsRefusedRatherThanIgnored(t *testing.T) {
	base := map[string]string{
		OptGateway: "vpn.example", OptLocalID: "client.example", OptPSK: "secret",
		OptIPTFS: "true", OptIPTFSRate: "1250000",
	}
	if _, err := parseOptions(base); err != nil {
		t.Fatalf("iptfs with a rate was rejected on its own: %v", err)
	}

	withShape := map[string]string{}
	maps.Copy(withShape, base)
	withShape[OptShape] = "16384"
	_, err := parseOptions(withShape)
	if err == nil {
		t.Fatal("-shape alongside -iptfs-rate was accepted; it would silently do nothing")
	}
	if !strings.Contains(err.Error(), OptShape) || !strings.Contains(err.Error(), OptIPTFSRate) {
		t.Errorf("error %q does not name both flags, so it does not say what to change", err)
	}
}

// TestAConstantRateWithoutTheDataPathIsRefused. -iptfs-rate paces AGGFRAG
// payloads; without -iptfs there is no AGGFRAG data path for it to pace, and
// accepting the rate would report a feature that cannot run.
func TestAConstantRateWithoutTheDataPathIsRefused(t *testing.T) {
	opts := map[string]string{
		OptGateway: "vpn.example", OptLocalID: "client.example", OptPSK: "secret",
		OptIPTFSRate: "1250000",
	}
	if _, err := parseOptions(opts); err == nil {
		t.Fatal("-iptfs-rate was accepted without -iptfs")
	}
}
