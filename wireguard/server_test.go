package wireguard

import (
	"strings"
	"testing"
)

const serverConf = `
[Interface]
PrivateKey = ` + /* placeholder replaced in tests */ `PLACEHOLDER
Address = 10.10.0.1/24
ListenPort = 51820

[Peer]
PublicKey = PEER1
AllowedIPs = 10.10.0.2/32

[Peer]
PublicKey = PEER2
PresharedKey = PSK2
AllowedIPs = 10.10.0.3/32, 10.10.0.4/32
`

// TestServerConfigFromFile checks a multi-peer server config parses and maps.
func TestServerConfigFromFile(t *testing.T) {
	conf := serverConf
	conf = strings.Replace(conf, "PLACEHOLDER", b64Key(1), 1)
	conf = strings.Replace(conf, "PEER1", b64Key(2), 1)
	conf = strings.Replace(conf, "PEER2", b64Key(3), 1)
	conf = strings.Replace(conf, "PSK2", b64Key(4), 1)

	cfg, err := ParseConfig(strings.NewReader(conf))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := ServerConfigFromFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Address != "10.10.0.1/24" || sc.ListenPort != 51820 {
		t.Errorf("interface = %q port %d", sc.Address, sc.ListenPort)
	}
	if len(sc.Peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(sc.Peers))
	}
	if len(sc.Peers[1].AllowedIPs) != 2 || sc.Peers[1].PresharedKey == "" {
		t.Errorf("second peer not mapped: %+v", sc.Peers[1])
	}
}

// TestResolvePeers checks the runtime peer table: keys decoded, duplicates and
// missing AllowedIPs rejected.
func TestResolvePeers(t *testing.T) {
	peers, err := resolvePeers([]ServerPeer{
		{PublicKey: b64Key(2), AllowedIPs: []string{"10.0.0.2/32"}},
		{PublicKey: b64Key(3), PresharedKey: b64Key(4), AllowedIPs: []string{"10.0.0.3/32"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(peers))
	}

	for _, tc := range []struct {
		name  string
		peers []ServerPeer
	}{
		{"duplicate key", []ServerPeer{
			{PublicKey: b64Key(2), AllowedIPs: []string{"10.0.0.2/32"}},
			{PublicKey: b64Key(2), AllowedIPs: []string{"10.0.0.3/32"}},
		}},
		{"missing allowed-ips", []ServerPeer{{PublicKey: b64Key(2)}}},
		{"bad key", []ServerPeer{{PublicKey: "notbase64!!", AllowedIPs: []string{"10.0.0.2/32"}}}},
		{"bad allowed-ip", []ServerPeer{{PublicKey: b64Key(2), AllowedIPs: []string{"nonsense"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolvePeers(tc.peers); err == nil {
				t.Errorf("%s: accepted", tc.name)
			}
		})
	}
}

// TestNewServerValidation checks the configuration errors NewServer reports
// before it ever opens a TUN device (so this runs without privileges). A valid
// config would proceed to OpenTUN, which needs CAP_NET_ADMIN, so only the
// rejection paths are exercised here; the happy path is covered by interop.
func TestNewServerValidation(t *testing.T) {
	valid := ServerConfig{
		PrivateKey: b64Key(1),
		ListenPort: 51820,
		Address:    "10.10.0.1/24",
		Peers:      []ServerPeer{{PublicKey: b64Key(2), AllowedIPs: []string{"10.10.0.2/32"}}},
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ServerConfig)
		want   string
	}{
		{"no private key", func(c *ServerConfig) { c.PrivateKey = "" }, OptPrivateKey},
		{"bad port", func(c *ServerConfig) { c.ListenPort = 0 }, OptListenPort},
		{"no address", func(c *ServerConfig) { c.Address = "" }, OptAddress},
		{"bad address", func(c *ServerConfig) { c.Address = "not-a-cidr" }, OptAddress},
		{"no peers", func(c *ServerConfig) { c.Peers = nil }, "peer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			_, err := NewServer(cfg)
			if err == nil {
				t.Fatalf("%s: accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.want)
			}
		})
	}
}

func TestParseCIDR(t *testing.T) {
	gw, network, err := parseCIDR("10.10.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if gw.String() != "10.10.0.1" {
		t.Errorf("gateway = %s, want 10.10.0.1", gw)
	}
	if network.String() != "10.10.0.0/24" {
		t.Errorf("network = %s, want 10.10.0.0/24", network)
	}
}
