package mgmt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/supervisor"
	"github.com/xen0bit/veepin/internal/vlog"
)

// metricsServer builds an API over one running wireguard listener with the
// given peers, so each test below asserts on one scrape.
func metricsServer(t *testing.T, peers []client.PeerInfo) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := supervisor.ListenerConfig{Name: "site-a", Protocol: "wireguard", Enabled: true,
		Options: map[string]string{"private-key": "k"}}
	body, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "site-a.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr := &fakeMgr{
		statuses:   map[string]supervisor.Status{"site-a": {Name: "site-a", Protocol: "wireguard", State: "running"}},
		peerServer: &fakePeerDescriber{peers: peers},
	}
	srv, err := NewServer(dir, mgr, vlog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func scrape(t *testing.T, srv *Server) string {
	t.Helper()
	resp, body := srv.do("GET", "/api/metrics", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain; a scraper negotiates on it", ct)
	}
	return string(body)
}

// The claim: a running server can be asked whether it is carrying traffic, and
// answers per peer. Before this nothing anywhere in the tree counted a byte.
func TestMetricsExportPerPeerTraffic(t *testing.T) {
	out := scrape(t, metricsServer(t, []client.PeerInfo{
		{ID: "alice", Address: "10.10.0.2", State: "connected", RxBytes: 1234, TxBytes: 5678, RxPackets: 12, TxPackets: 34},
	}))
	for _, want := range []string{
		`veepin_peer_rx_bytes_total{listener="site-a",protocol="wireguard",peer="alice"} 1234`,
		`veepin_peer_tx_bytes_total{listener="site-a",protocol="wireguard",peer="alice"} 5678`,
		`veepin_peer_rx_packets_total{listener="site-a",protocol="wireguard",peer="alice"} 12`,
		`veepin_peer_tx_packets_total{listener="site-a",protocol="wireguard",peer="alice"} 34`,
		`veepin_listener_up{listener="site-a",protocol="wireguard"} 1`,
		`veepin_listener_peers{listener="site-a",protocol="wireguard"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape is missing:\n%s\ngot:\n%s", want, out)
		}
	}
}

// Every family needs its HELP and TYPE lines, and the type has to be right:
// a counter declared as a gauge makes rate() meaningless on the other end.
func TestMetricsDeclareTypesAndHelp(t *testing.T) {
	out := scrape(t, metricsServer(t, []client.PeerInfo{{ID: "alice", State: "connected"}}))
	for _, want := range []string{
		"# TYPE veepin_listener_up gauge",
		"# TYPE veepin_listener_peers gauge",
		"# TYPE veepin_peer_rx_bytes_total counter",
		"# TYPE veepin_peer_tx_bytes_total counter",
		"# HELP veepin_peer_rx_bytes_total ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape is missing %q\ngot:\n%s", want, out)
		}
	}
}

// Every label value on this endpoint is operator-supplied -- a listener name
// from a config file, a peer ID that may be a username. One unescaped quote
// produces an exposition that fails to parse, taking every other metric on the
// page down with it.
func TestMetricsEscapeOperatorSuppliedLabels(t *testing.T) {
	out := scrape(t, metricsServer(t, []client.PeerInfo{
		{ID: `a"b\c` + "\n" + `d`, State: "connected", RxBytes: 7},
	}))
	if !strings.Contains(out, `peer="a\"b\\c\nd"`) {
		t.Errorf("label not escaped:\n%s", out)
	}
	// The raw newline must not survive: it would end the sample line early and
	// leave the rest as a malformed one.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "veepin_") && !strings.Contains(line, "} ") {
			t.Errorf("malformed sample line %q", line)
		}
	}
}

// Zero is a claim ("no peers"); absence is the truth ("we cannot say"). A
// dashboard alerting on peers dropping to zero must not fire because a
// protocol never had the capability, or because a listener is stopped.
func TestMetricsOmitListenersThatCannotReportPeers(t *testing.T) {
	dir := t.TempDir()
	cfg := supervisor.ListenerConfig{Name: "site-a", Protocol: "masque", Enabled: true, Options: map[string]string{}}
	body, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "site-a.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	// No peerServer: fakeMgr reports the protocol cannot describe peers.
	mgr := &fakeMgr{statuses: map[string]supervisor.Status{
		"site-a": {Name: "site-a", Protocol: "masque", State: "running"},
	}}
	srv, err := NewServer(dir, mgr, vlog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	out := scrape(t, srv)

	// It is still up, and that is worth exporting.
	if !strings.Contains(out, `veepin_listener_up{listener="site-a",protocol="masque"} 1`) {
		t.Errorf("a listener that cannot report peers lost its up gauge too:\n%s", out)
	}
	if strings.Contains(out, "veepin_listener_peers{") {
		t.Errorf("a listener that cannot report peers was exported as having some:\n%s", out)
	}
}
