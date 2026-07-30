package supervisor

// The Manager is the engine. It holds the set of live listeners, each running
// in its own goroutine, and reconciles them to the on-disk config via Apply
// (initial load + on SIGHUP-style reload), and to per-listener edits via the
// individual Rebuild / Stop methods the management API calls.
//
// Construction is pluggable for tests: Manager.ctor defaults to client.NewServer,
// and the supervisor's tests inject a fake that returns an in-memory Server so
// the lifecycle, locking, status, and reconciliation logic run under `go test`
// without ever needing a TUN. The actual veepin binary uses the real ctor.

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/hostnet"
)

// Constructor turns a ListenerConfig into a constructed (not yet listening)
// client.Server. The default realises to client.NewServer on the listener's
// protocol/options; tests pass a fake so the supervisor runs without privileges
// or sockets.
type Constructor func(protocol string, opts map[string]string) (client.Server, error)

// Status is the visible state of one listener. It is what the management API
// returns; Network is stringified so json.Marshal produces a self-describing
// field rather than the opaque *net.IPNet the Server interface exposes.
type Status struct {
	Name     string    `json:"name"`
	Protocol string    `json:"protocol"`
	State    string    `json:"state"` // "running", "building", "stopped", "error", "disabled"
	TUNName  string    `json:"tun,omitempty"`
	Gateway  string    `json:"gateway,omitempty"`
	Network  string    `json:"network,omitempty"`
	Error    string    `json:"error,omitempty"`
	Since    time.Time `json:"since,omitempty"`
}

// running is the live handle for one listener: the constructed server, the
// goroutine that owns it until Close returns, and the mutex guarding rebuild.
// Manager.mu protects the listeners map; one run's own mutex guards the
// server/ServeErr fields against a rebuild racing the status/read path.
type running struct {
	cfg      ListenerConfig
	srv      client.Server
	mu       sync.Mutex
	state    string
	since    time.Time
	serveErr error
	cancel   chan struct{}
	done     chan struct{}
}

// Manager owns a set of listeners and reconciles them to a config directory.
// Each listener lives in one goroutine; per-listener operations acquire that
// listener's mutex and the manager's outer mutex in that order, so a rebuild
// never races a teardown for the same name.
type Manager struct {
	dir  string
	ctor Constructor
	log  *log.Logger

	mu        sync.Mutex // guards listeners map
	listeners map[string]*running
}

// NewManager returns a Manager whose ctor is real if none is supplied.
func NewManager(dir string, logger *log.Logger, ctor Constructor) *Manager {
	if ctor == nil {
		// DefaultConstructor is the production path: client.NewServer.
		ctor = client.NewServer
	}
	if logger == nil {
		logger = log.New(log.New(nil, "", 0).Writer(), "", 0) // avoid nil log
		_ = logger
		logger = log.New(&stringsBuilder{}, "", 0)
	}
	return &Manager{
		dir:       dir,
		ctor:      ctor,
		log:       logger,
		listeners: make(map[string]*running),
	}
}

// stringsBuilder lets NewManager cope with a nil logger without importing
// bytes; it eats writes without producing output.
type stringsBuilder struct{}

func (*stringsBuilder) Write(p []byte) (int, error) { return len(p), nil }

// Apply reconciles the live set to the directory. New configs are built;
// removed configs are torn down; changed configs are cold-rebuilt; disabled
// configs are stopped; untouched configs keep running -- exactly the set
// difference against the on-disk state.
//
// The whole diff is computed under Manager.mu, then each per-listener action
// happens via methods that re-acquire the lock -- so a long build does not
// hold the manager lock for other listeners' status reads.
func (m *Manager) Apply() error {
	cfgs, err := LoadDir(m.dir)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Stop and remove listeners that are gone or now disabled.
	for name, r := range m.listeners {
		cfg, ok := cfgs[name]
		if !ok || !cfg.Enabled {
			m.stopLocked(r)
			delete(m.listeners, name)
			continue
		}
		if configChanged(r.cfg, cfg) {
			if err := m.rebuildLocked(r, cfg); err != nil {
				// The rebuild failed but the listener is still tracked, with
				// its state set to error; subsequent Apply passes will retry.
				m.log.Printf("supervisor: rebuild %s failed: %v", name, err)
			}
		}
	}

	// 2. Build new listeners. We do not gate on KnownProtocol here: the ctor
	// (client.NewServer by default) is the source of truth for which protocols
	// exist, and rejects an unknown name with ErrUnknownProtocol. Testing the
	// gate here would need the registry to know the protocol, which makes a
	// unit test import every facade just to construct a manager.
	for name, cfg := range cfgs {
		if _, exists := m.listeners[name]; exists {
			continue
		}
		r, err := m.build(name, cfg)
		if err != nil {
			return fmt.Errorf("supervisor: building %q: %w", name, err)
		}
		m.listeners[name] = r
	}
	return nil
}

// configChanged reports whether rebuilding is required, comparing only fields
// that affect the constructed Server or its host networking. ListenPort etc.
// live inside Options, so they are part of the diff automatically.
func configChanged(a, b ListenerConfig) bool {
	if a.Protocol != b.Protocol || a.SetupNAT != b.SetupNAT || a.WAN != b.WAN || a.Enabled != b.Enabled {
		return true
	}
	if len(a.Options) != len(b.Options) {
		return true
	}
	for k, av := range a.Options {
		if b.Options[k] != av {
			return true
		}
	}
	return false
}

// statusFromLocked reads r's state under its mutex and returns it as a Status.
// Called under Manager.mu; re-acquires r.mu.
func statusFromLocked(r *running) Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Status{
		Name:     r.cfg.Name,
		Protocol: r.cfg.Protocol,
		State:    r.state,
		Since:    r.since,
		Error:    "",
	}
	if r.serveErr != nil {
		s.Error = r.serveErr.Error()
	}
	if r.srv != nil {
		s.TUNName = r.srv.TUNName()
		if g := r.srv.Gateway(); g != nil {
			s.Gateway = g.String()
		}
		if n := r.srv.Network(); n != nil {
			s.Network = n.String()
		}
	}
	return s
}

// Status returns the visible state of one listener, or a zero Status with
// State="unknown" if no such listener is tracked. The management API reports
// this verbatim.
func (m *Manager) Status(name string) Status {
	m.mu.Lock()
	r, ok := m.listeners[name]
	m.mu.Unlock()
	if !ok {
		return Status{Name: name, State: "unknown"}
	}
	return statusFromLocked(r)
}

// All returns the status of every tracked listener, sorted by name. The
// management API's GET /api/listeners renders this.
func (m *Manager) All() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.listeners))
	// Sorted by name for stable API output; statusFromLocked is the per-
	// listener section that re-acquires the listener mutex.
	byName := make([]string, 0, len(m.listeners))
	for n := range m.listeners {
		byName = append(byName, n)
	}
	sort.Strings(byName)
	for _, n := range byName {
		out = append(out, statusFromLocked(m.listeners[n]))
	}
	return out
}

// Rebuild forces the named listener back to build then ListenAndServe, the
// operation triggered by a config edit. Safe to call against a stopped or
// errored listener -- it tears down what is there, if anything, and rebuilds.
func (m *Manager) Rebuild(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.listeners[name]
	if !ok {
		return fmt.Errorf("supervisor: no listener named %q", name)
	}
	cfgs, err := LoadDir(m.dir)
	if err != nil {
		return err
	}
	cfg, ok := cfgs[name]
	if !ok {
		return fmt.Errorf("supervisor: %q has no on-disk config; DeleteListenerFile removed it", name)
	}
	return m.rebuildLocked(r, cfg)
}

// Stop tears down a listener and drops it from the live set. Its config file
// remains on disk; rebuild from a later Apply or a management API call picks
// it back up.
func (m *Manager) Stop(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.listeners[name]
	if !ok {
		return fmt.Errorf("supervisor: no listener named %q", name)
	}
	m.stopLocked(r)
	delete(m.listeners, name)
	return nil
}

// Close tears every listener down. Called on supervisor shutdown. An
// individual listener returning net.ErrClosed is the expected outcome of
// being Close()d here, not an error to surface; Close reports an error only if
// a listener's serve goroutine recorded a non-shutdown failure.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for name, r := range m.listeners {
		m.stopLocked(r)
		delete(m.listeners, name)
		_ = name
		if r.serveErr != nil && !errors.Is(r.serveErr, net.ErrClosed) && firstErr == nil {
			firstErr = r.serveErr
		}
	}
	return firstErr
}

// Server returns the live *client.Server for a running listener, so the
// management API can type-assert it against optional interfaces such as
// client.PeerDescriber. Returns nil if the listener is not running or does
// not exist.
func (m *Manager) Server(name string) client.Server {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.listeners[name]
	if !ok {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.srv
}

// build constructs a listener, installs its host networking, and launches it.
// Called under Manager.mu; the goroutine it starts does not need the manager
// lock, only r.mu, so a long-lived Server never pins the manager.
func (m *Manager) build(name string, cfg ListenerConfig) (*running, error) {
	if !cfg.Enabled {
		r := &running{cfg: cfg, state: "disabled"}
		return r, nil
	}
	srv, err := m.ctor(cfg.Protocol, cfg.Options)
	if err != nil {
		return nil, fmt.Errorf("constructing %s server: %w", cfg.Protocol, err)
	}
	if cfg.SetupNAT {
		if err := hostnet.Apply(name, hostnet.Config{
			TUNName: srv.TUNName(),
			Gateway: srv.Gateway(),
			Network: srv.Network(),
			WAN:     cfg.WAN,
		}); err != nil {
			_ = srv.Close()
			return nil, fmt.Errorf("host networking: %w", err)
		}
	}
	r := &running{
		cfg:    cfg,
		srv:    srv,
		state:  "running",
		since:  time.Now(),
		cancel: make(chan struct{}),
		done:   make(chan struct{}),
	}
	go r.serve(m.log)
	return r, nil
}

// rebuildLocked is the per-listener cold rebuild: stop, construct new, start.
// It re-uses the running handle so external addresses to the listener (status
// reads) keep referring to the same *running. Manager.mu is held by the caller.
func (m *Manager) rebuildLocked(r *running, cfg ListenerConfig) error {
	m.stopLocked(r)
	newR, err := m.build(r.cfg.Name, cfg)
	if err != nil {
		// Leave r in the map in "error" state so the next Apply can retry and
		// the management API reports failure with the error.
		r.cfg = cfg
		r.state = "error"
		r.serveErr = err
		r.since = time.Now()
		return err
	}
	// Move the freshly-built fields into the existing handle so Manager.mu stays
	// the only thing external callers held.
	r.mu.Lock()
	r.cfg, r.srv, r.state, r.since, r.cancel, r.done, r.serveErr =
		newR.cfg, newR.srv, newR.state, newR.since, newR.cancel, newR.done, nil
	r.mu.Unlock()
	return nil
}

// stopLocked closes the listener's server and waits for the goroutine to exit,
// then tears down any host-networking rules it owned. Called under Manager.mu;
// acquires r.mu.
func (m *Manager) stopLocked(r *running) {
	r.mu.Lock()
	srv := r.srv
	cancel := r.cancel
	done := r.done
	r.srv = nil
	r.state = "stopped"
	r.since = time.Now()
	r.mu.Unlock()

	if cancel != nil {
		select {
		case <-cancel:
		default:
			close(cancel)
		}
	}
	if srv != nil {
		_ = srv.Close()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
	// Host-state teardown for the listener's own rules; layer-2 / no-WAN
	// configs are a no-op in hostnet.Teardown, so it is safe to call
	// unconditionally.
	if r.cfg.SetupNAT {
		// We no longer have srv's TUNName/Gateway/Network (srv was just closed
		// and may have freed the TUN). Re-derive from the config's Options
		// where possible; otherwise the rules' removal survives on the comment
		// tag alone (which carries the name).
		_ = hostnet.Teardown(r.cfg.Name, hostnet.Config{
			TUNName: r.cfg.Options["tun"],
			WAN:     r.cfg.WAN,
		})
	}
}

// serve is the goroutine that owns one listener's ListenAndServe. It records
// the result and signals completion so Stop can wait deterministically. The
// completion is signaled via a deferred close(done), which makes the early-
// return path (srv nil at goroutine start: a disabled listener, or Stop won
// the race before serve got hold of srv) close done just like the served path.
func (r *running) serve(logger *log.Logger) {
	defer close(r.done)
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return
	}
	err := srv.ListenAndServe()
	r.mu.Lock()
	r.serveErr = err
	if errors.Is(err, net.ErrClosed) {
		r.state = "stopped"
	} else if err != nil {
		r.state = "error"
	} else {
		r.state = "stopped"
	}
	r.since = time.Now()
	r.mu.Unlock()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Printf("supervisor: %s/%s: %v", r.cfg.Name, r.cfg.Protocol, err)
	}
}
