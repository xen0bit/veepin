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
		{"v6 in the v4 field", func(c *ServerConfig) { c.Address = "fd00::1/64" }, OptServerAddress6},
		{"bad address6", func(c *ServerConfig) { c.Address6 = "not-a-cidr" }, OptServerAddress6},
		{"v4 in the v6 field", func(c *ServerConfig) { c.Address6 = "10.0.0.1/24" }, OptServerAddress6},
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

// wg-quick's Address line is a list, and a dual-stack interface writes both
// families on it. Reading Address[0] took whichever came first and dropped the
// rest, so `Address = 10.10.0.1/24, fd00:10::1/64` produced an IPv4-only server
// with nothing said, and the reversed order produced a server whose "IPv4"
// address was a v6 one.
func TestServerConfigFromFileKeepsBothAddressFamilies(t *testing.T) {
	for _, order := range [][]string{
		{"10.10.0.1/24", "fd00:10::1/64"},
		{"fd00:10::1/64", "10.10.0.1/24"},
	} {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			sc, err := ServerConfigFromFile(&Config{
				PrivateKey: b64Key(1),
				ListenPort: 51820,
				Address:    order,
				Peers:      []Peer{{PublicKey: b64Key(2), AllowedIPs: []string{"10.10.0.2/32"}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if sc.Address != "10.10.0.1/24" {
				t.Errorf("Address = %q, want the IPv4 entry", sc.Address)
			}
			if sc.Address6 != "fd00:10::1/64" {
				t.Errorf("Address6 = %q, want the IPv6 entry", sc.Address6)
			}
		})
	}
}

// A server installs exactly one address per family, so a config naming two of
// one family has an entry that would be silently ignored. That is how a config
// which looks right stops working, so it is an error.
func TestServerConfigFromFileRefusesTwoAddressesOfOneFamily(t *testing.T) {
	for _, addrs := range [][]string{
		{"10.10.0.1/24", "10.10.1.1/24"},
		{"fd00:10::1/64", "fd00:11::1/64", "10.10.0.1/24"},
	} {
		_, err := ServerConfigFromFile(&Config{
			PrivateKey: b64Key(1),
			ListenPort: 51820,
			Address:    addrs,
			Peers:      []Peer{{PublicKey: b64Key(2), AllowedIPs: []string{"10.10.0.2/32"}}},
		})
		if err == nil {
			t.Errorf("%v was accepted", addrs)
		}
	}
}

// A wg-quick file with no IPv4 address is rejected rather than producing a
// server whose Gateway is nil, which every host-networking step downstream
// would then hand to `ip addr add`.
func TestServerConfigFromFileRequiresAnIPv4Address(t *testing.T) {
	_, err := ServerConfigFromFile(&Config{
		PrivateKey: b64Key(1),
		ListenPort: 51820,
		Address:    []string{"fd00:10::1/64"},
		Peers:      []Peer{{PublicKey: b64Key(2), AllowedIPs: []string{"10.10.0.2/32"}}},
	})
	if err == nil {
		t.Fatal("a v6-only server config was accepted")
	}
}
