// Command harness is the browser-test backend for the management panel.
//
// It wires the production management plane exactly as cmd/veepin's supervisor
// mode does -- a real mgmt.Server, the embedded ui.Handler, and the RequireHost
// guard -- but with a fake ManagerBackend standing in for the supervisor, so
// the whole plane runs as an unprivileged, TUN-free process a headless browser
// can drive. The Playwright suite in ../ spawns this binary, points Chromium at
// it, and asserts on the rendered panel.
//
// The fake backend is deliberately small and deterministic: these tests are
// about the DOM and the browser, not the manager. The API surface the panel
// depends on is already pinned end-to-end by internal/mgmt/api_test.go; what
// the harness owes the browser tests is a stable, controllable world --
// listeners in every state, a peer, a profile, a log ring -- that behaves the
// way the real supervisor would when the panel mutates it. Apply and Rebuild
// learn about listeners created through the API by reading the config directory
// back, the way the real manager reconciles, so a listener created in the
// browser shows up running in the next poll.
//
// The bearer token is deterministic: the harness pre-writes <config>/mgmt/token
// before mgmt.NewServer, so bootToken reads it instead of minting one, and the
// suite does not need a conn-file round trip to learn it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/mgmt"
	"github.com/xen0bit/veepin/internal/mgmt/ui"
	"github.com/xen0bit/veepin/internal/profile"
	"github.com/xen0bit/veepin/internal/supervisor"
	"github.com/xen0bit/veepin/internal/vlog"
	"github.com/xen0bit/veepin/wireguard"

	// Blank-import every facade so the registry the API reads from knows every
	// protocol, matching the production binary. Without these the protocol
	// dropdowns render empty and create refuses every protocol.
	_ "github.com/xen0bit/veepin/amneziawg"
	_ "github.com/xen0bit/veepin/anyconnect"
	_ "github.com/xen0bit/veepin/cisco"
	_ "github.com/xen0bit/veepin/fortinet"
	_ "github.com/xen0bit/veepin/gp"
	_ "github.com/xen0bit/veepin/ikev2"
	_ "github.com/xen0bit/veepin/l2tp"
	_ "github.com/xen0bit/veepin/l2tpv3"
	_ "github.com/xen0bit/veepin/masque"
	_ "github.com/xen0bit/veepin/nebula"
	_ "github.com/xen0bit/veepin/openvpn"
	_ "github.com/xen0bit/veepin/pulse"
	_ "github.com/xen0bit/veepin/softether"
	_ "github.com/xen0bit/veepin/ssh"
	_ "github.com/xen0bit/veepin/sstp"
	_ "github.com/xen0bit/veepin/toy"
	_ "github.com/xen0bit/veepin/wireguard"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("harness: %v", err)
	}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:18555", "address to bind the management plane to")
	token := flag.String("token", "veepin-e2e-token", "bearer token the panel hands the browser")
	seedPath := flag.String("seed", "", "path to the seed JSON describing the initial world")
	flag.Parse()

	s, err := loadSeed(*seedPath)
	if err != nil {
		return err
	}

	configDir, err := os.MkdirTemp("", "veepin-e2e-config-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(configDir) }()

	profilesDir, err := os.MkdirTemp("", "veepin-e2e-profiles-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(profilesDir) }()

	// Pre-seed the bearer token so it is deterministic. bootToken reads an
	// existing file and only mints one when it is absent; writing it first
	// exercises the same read path a re-starting supervisor goes through.
	if err := os.MkdirAll(filepath.Join(configDir, "mgmt"), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(configDir, "mgmt", "token"), []byte(*token+"\n"), 0o600); err != nil {
		return err
	}

	// Seed the on-disk world through the same atomic confstore machinery the
	// API and supervisor use, so a later panel edit of a seeded entity starts
	// from a file the production parser wrote.
	for _, l := range s.Listeners {
		cfg := supervisor.ListenerConfig{
			Name:     l.Name,
			Protocol: l.Protocol,
			Options:  l.Options,
			Enabled:  l.Enabled,
		}
		if err := supervisor.WriteListenerFile(configDir, cfg); err != nil {
			return fmt.Errorf("seeding listener %s: %w", l.Name, err)
		}
	}
	for _, p := range s.Profiles {
		if err := profile.Write(profilesDir, profile.Config{Name: p.Name, Protocol: p.Protocol, Options: p.Options}); err != nil {
			return fmt.Errorf("seeding profile %s: %w", p.Name, err)
		}
	}

	// The supervisor's shared log ring, pre-filled with the seed's lines so the
	// panel's log tail has something to show before the first mutation.
	ring := mgmt.NewLogRing()
	logger := vlog.Text(os.Stdout)
	for _, line := range s.Logs {
		_, _ = ring.Write([]byte(line + "\n"))
	}

	mgr := &e2eMgr{dir: configDir}
	mgr.statuses = make(map[string]supervisor.Status, len(s.Listeners))
	mgr.rebuildErrs = make(map[string]error, len(s.Listeners))
	for _, l := range s.Listeners {
		mgr.statuses[l.Name] = supervisor.Status{
			Name:     l.Name,
			Protocol: l.Protocol,
			State:    l.State,
			TUNName:  l.TUN,
			Gateway:  l.Gateway,
			Network:  l.Network,
			Error:    l.Error,
			Since:    time.Now(),
		}
		if l.RebuildErr != "" {
			mgr.rebuildErrs[l.Name] = errors.New(l.RebuildErr)
		}
	}

	mgmtSrv, err := mgmt.NewServer(configDir, mgr, logger,
		mgmt.WithProfileDir(profilesDir), mgmt.WithLogRing(ring))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", mgmtSrv.Handler())
	uiHandler, err := ui.NewHandler(string(mgmtSrv.Token()), logger)
	if err != nil {
		return err
	}
	mux.Handle("/", uiHandler)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Handler: mgmt.RequireHost([]string{ln.Addr().String()}, mux),
		// net/http wants a *log.Logger; bridge one onto the same handler.
		ErrorLog: slog.NewLogLogger(vlog.NewTextHandler(os.Stdout, slog.LevelInfo), slog.LevelError),
	}
	// The address, not the token. It is a fixed test token so printing it leaks
	// nothing, but this log goes to CI output verbatim and a bearer token in a
	// build log is a habit worth not having. The suite gets the token from
	// lib/config.ts, which is where the default is written down.
	logger.Printf("listening on http://%s", ln.Addr())

	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.Serve(ln) }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		logger.Printf("signal %v; shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return httpSrv.Shutdown(ctx)
	case err := <-serveErr:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
	}
	return nil
}

// --- Seed ---

// seed is the initial world the browser tests assert on. It lives as JSON in
// ../fixtures/seed.json; the fields map 1:1 to what the panel renders.
type seed struct {
	Listeners []seedListener `json:"listeners"`
	Profiles  []seedProfile  `json:"profiles"`
	Logs      []string       `json:"logs"`
}

// seedListener is one listener: the on-disk config plus the visible status the
// fake manager reports for it, and optionally a rebuild failure that drives the
// panel's "saved, but the rebuild failed" banner (the PATCH-202 path).
type seedListener struct {
	Name       string            `json:"name"`
	Protocol   string            `json:"protocol"`
	State      string            `json:"state"`
	TUN        string            `json:"tun,omitempty"`
	Gateway    string            `json:"gateway,omitempty"`
	Network    string            `json:"network,omitempty"`
	Error      string            `json:"error,omitempty"`
	Enabled    bool              `json:"enabled"`
	Options    map[string]string `json:"options,omitempty"`
	RebuildErr string            `json:"rebuildErr,omitempty"`
}

type seedProfile struct {
	Name     string            `json:"name"`
	Protocol string            `json:"protocol"`
	Options  map[string]string `json:"options,omitempty"`
}

func loadSeed(path string) (*seed, error) {
	var s seed
	if path == "" {
		return &s, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading seed %s: %w", path, err)
	}
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("parsing seed %s: %w", path, err)
	}
	return &s, nil
}

// --- Fake backend ---

// e2eMgr is the ManagerBackend the harness wires in place of the real
// supervisor. Statuses are seeded; Apply and Rebuild reconcile against the
// config directory the way the real manager does, so a listener created or
// edited through the API shows the derived status on the next poll.
type e2eMgr struct {
	dir string

	mu          sync.Mutex
	statuses    map[string]supervisor.Status
	rebuildErrs map[string]error
}

func (m *e2eMgr) Apply() error {
	cfgs, err := supervisor.LoadDir(m.dir)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, cfg := range cfgs {
		if _, ok := m.statuses[name]; ok {
			continue
		}
		m.statuses[name] = deriveStatus(cfg)
	}
	return nil
}

func (m *e2eMgr) All() []supervisor.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]supervisor.Status, 0, len(m.statuses))
	for _, st := range m.statuses {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *e2eMgr) Status(name string) supervisor.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.statuses[name]; ok {
		return st
	}
	return supervisor.Status{Name: name, State: "unknown"}
}

func (m *e2eMgr) Rebuild(name string) error {
	m.mu.Lock()
	if err := m.rebuildErrs[name]; err != nil {
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()

	cfg, err := supervisor.ParseListenerFile(supervisor.ListenerPath(m.dir, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("supervisor: no listener named %q", name)
		}
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses[name] = deriveStatus(cfg)
	return nil
}

func (m *e2eMgr) Stop(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.statuses, name)
	return nil
}

func (m *e2eMgr) Close() error { return nil }

// Peers returns the WireGuard-family peer list derived from the listener's
// on-disk config, so a peer provisioned through client-config generation
// actually shows up in the panel's peer table. It mirrors the real manager's
// four cases: only a running listener has a server handle to ask.
func (m *e2eMgr) Peers(name string) ([]client.PeerInfo, supervisor.PeerAvailability) {
	cfg, err := supervisor.ParseListenerFile(supervisor.ListenerPath(m.dir, name))
	if err != nil {
		return nil, supervisor.PeersNoSuchListener
	}
	m.mu.Lock()
	st := m.statuses[name]
	m.mu.Unlock()
	if st.State != "running" {
		return nil, supervisor.PeersNotRunning
	}
	return peersFromConfig(cfg), supervisor.PeersOK
}

// deriveStatus is the fake's version of what the real manager publishes after a
// build: the gateway and network come from the listener's own tunnel address,
// like statusOf does from the live server's Gateway() and Network().
func deriveStatus(cfg supervisor.ListenerConfig) supervisor.Status {
	st := supervisor.Status{Name: cfg.Name, Protocol: cfg.Protocol, Since: time.Now()}
	if !cfg.Enabled {
		st.State = "disabled"
		return st
	}
	st.State = "running"
	if p, err := netip.ParsePrefix(cfg.Options[wireguard.OptServerAddress]); err == nil {
		st.Gateway = p.Addr().String()
		st.Network = p.Masked().String()
	}
	st.TUNName = "tun0"
	return st
}

// peersFromConfig maps the on-disk WireGuard peer shape (single-peer options
// plus the peers JSON array) onto the client.PeerInfo rows the panel renders.
func peersFromConfig(cfg supervisor.ListenerConfig) []client.PeerInfo {
	if cfg.Protocol != "wireguard" && cfg.Protocol != "amneziawg" {
		return nil
	}
	var out []client.PeerInfo
	if pub := cfg.Options[wireguard.OptServerPeerPublicKey]; pub != "" {
		out = append(out, client.PeerInfo{
			ID:      pub,
			Address: firstCIDR(cfg.Options[wireguard.OptServerPeerAllowedIPs]),
			State:   "connected",
		})
	}
	if body := cfg.Options[wireguard.OptServerPeers]; body != "" {
		var peers []wireguard.ServerPeer
		if err := json.Unmarshal([]byte(body), &peers); err == nil {
			for _, p := range peers {
				addr := ""
				if len(p.AllowedIPs) > 0 {
					addr = p.AllowedIPs[0]
				}
				out = append(out, client.PeerInfo{ID: p.PublicKey, Address: addr, State: "connected"})
			}
		}
	}
	return out
}

// firstCIDR is the first non-empty entry of a comma-separated CIDR list, the
// shape the single-peer allowed-ips option carries.
func firstCIDR(list string) string {
	for s := range strings.SplitSeq(list, ",") {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}
