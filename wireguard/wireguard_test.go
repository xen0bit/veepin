package wireguard

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

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

// TestTheListenPortReachesTheEngine: -listen-port, and a client config's
// ListenPort line, exist to pin the source port so a NAT pinhole survives a
// reconnect. Both were parsed and then dropped on the way to the socket, which
// bound an ephemeral port whatever was asked -- accepted and ignored, the
// failure this tree's flag guards exist to prevent but cannot see past the
// option map. The engine's half, that the port is bound, is pinned in
// internal/wireguard.
func TestTheListenPortReachesTheEngine(t *testing.T) {
	cfg := &Config{}
	if err := cfg.applyOverrides(map[string]string{
		OptPrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		OptPublicKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		OptEndpoint:   "127.0.0.1:51820",
		OptAddress:    "10.0.0.2/32",
		OptAllowedIPs: "0.0.0.0/0",
		OptListenPort: "40123",
	}); err != nil {
		t.Fatal(err)
	}
	r, err := cfg.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if r.listenPort != 40123 {
		t.Fatalf("resolve kept listen port %d, want 40123", r.listenPort)
	}
	cfg.ListenPort = 70000
	if _, err := cfg.resolve(); err == nil {
		t.Fatal("a listen port out of range was accepted")
	}
}
