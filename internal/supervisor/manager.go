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
	"io"
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
// goroutine that owns it until Close returns, and the state the management API
// reads back.
//
// mu guards every field below it, without exception. That is stricter than the
// call graph makes it look, and deliberately so: Manager.Status releases
// Manager.mu before it reads a handle, so Manager.mu is NOT a second layer of
// protection over these fields the way it is over the listeners map. An earlier
// version wrote cfg/state/serveErr on the rebuild-failed path while holding only
// Manager.mu and raced Status for exactly that reason.
//
// done is also the generation marker. stopLocked clears it, so a serve goroutine
// that returns late — after the 5s wait gave up, or after a rebuild already
// installed a new server — can tell that the state it is holding is stale and
// decline to publish it.
type running struct {
	mu       sync.Mutex
	cfg      ListenerConfig
	srv      client.Server
	state    string
	since    time.Time
	serveErr error
	done     chan struct{}
}

// setState publishes a terminal build outcome (disabled, or error) on r.
func (r *running) setState(cfg ListenerConfig, state string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg = cfg
	r.srv = nil
	r.state = state
	r.serveErr = err
	r.since = time.Now()
}

// Manager owns a set of listeners and reconciles them to a config directory.
// Each listener lives in one goroutine; per-listener operations acquire that
// listener's mutex and the manager's outer mutex in that order, so a rebuild
// never races a teardown for the same name.
type Manager struct {
	dir  string
	ctor Constructor
	log  *log.Logger
	// run is the commander hostnet shells out through. Nil means the real
	// ip/iptables/sysctl; tests set it with SetCommander so the host-networking
	// half of a build is exercised without privileges, the same way ctor covers
	// the server half.
	run hostnet.Commander

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
		logger = log.New(io.Discard, "", 0)
	}
	return &Manager{
		dir:       dir,
		ctor:      ctor,
		log:       logger,
		listeners: make(map[string]*running),
	}
}

// SetCommander replaces the external command runner the host-networking calls
// use. It exists for tests -- production leaves it unset, which means
// ip/iptables/sysctl via os/exec. Call it before Apply.
func (m *Manager) SetCommander(run hostnet.Commander) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.run = run
}

// applyHostnet installs a listener's host networking through whichever commander
// this Manager was given.
func (m *Manager) applyHostnet(name string, cfg hostnet.Config) error {
	if m.run == nil {
		return hostnet.Apply(name, cfg)
	}
	return hostnet.ApplyWithName(name, cfg, m.run)
}

// teardownHostnet is applyHostnet's inverse, through the same commander.
func (m *Manager) teardownHostnet(name string, cfg hostnet.Config) error {
	if m.run == nil {
		return hostnet.Teardown(name, cfg)
	}
	return hostnet.TeardownWithName(name, cfg, m.run)
}

// Apply reconciles the live set to the directory. New configs are built;
// removed configs are torn down; changed configs are cold-rebuilt; disabled
// configs are stopped; untouched configs keep running -- exactly the set
// difference against the on-disk state.
//
// The whole diff is computed under Manager.mu, then each per-listener action
// happens via methods that re-acquire the lock -- so a long build does not
// hold the manager lock for other listeners' status reads.
//
// A listener that will not start is reported but does not abort the pass. Apply
// returns every such failure joined together, and each failed listener stays
// tracked in "error" state carrying its reason, so it appears in the API and the
// next Apply retries it. Returning on the first failure -- which this used to do
// -- meant one listener with a bad option took the whole fleet down at startup,
// including the listeners that had already come up in the same pass.
//
// An unreadable config directory is different, and still fatal: LoadDir reports
// it before any listener has been touched.
func (m *Manager) Apply() error {
	cfgs, err := LoadDir(m.dir)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error

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
				errs = append(errs, fmt.Errorf("rebuilding %q: %w", name, err))
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
		r, err := m.build(cfg)
		if err != nil {
			errs = append(errs, fmt.Errorf("building %q: %w", name, err))
		}
		// Tracked either way: start published the failure on the handle, and a
		// listener that is listed as broken is more use to an operator than one
		// that silently does not exist.
		m.listeners[name] = r
	}
	if len(errs) > 0 {
		return fmt.Errorf("supervisor: %w", errors.Join(errs...))
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

// statusOf reads r's state under r.mu and returns it as a Status. The caller may
// or may not hold Manager.mu -- r.mu is the only lock that protects these fields,
// so this is safe either way.
func statusOf(r *running) Status {
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
	return statusOf(r)
}

// All returns the status of every tracked listener, sorted by name. The
// management API's GET /api/listeners renders this.
func (m *Manager) All() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.listeners))
	// Sorted by name for stable API output; statusOf is the per-listener
	// section that acquires the listener mutex.
	byName := make([]string, 0, len(m.listeners))
	for n := range m.listeners {
		byName = append(byName, n)
	}
	sort.Strings(byName)
	for _, n := range byName {
		out = append(out, statusOf(m.listeners[n]))
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

// build allocates a fresh handle and starts it. The handle is returned whether
// the start succeeded or not -- on failure it carries the "error" state and the
// reason -- so a caller can track a listener that would not come up. Called
// under Manager.mu; the goroutine start launches does not need the manager lock,
// only r.mu, so a long-lived Server never pins the manager.
func (m *Manager) build(cfg ListenerConfig) (*running, error) {
	r := &running{}
	return r, m.start(r, cfg)
}

// start constructs the listener's server, installs its host networking, and
// launches the serve goroutine against r. It publishes the outcome on r whether
// it succeeds or fails, so a caller that keeps the handle around always has a
// state and an error to report; the error is also returned for callers that
// want to propagate it.
//
// Called with r.mu NOT held: construction can block on a TUN open and a syscall
// or two of iptables, and holding the status lock across that would stall the
// management API's reads for the duration.
func (m *Manager) start(r *running, cfg ListenerConfig) error {
	if !cfg.Enabled {
		r.setState(cfg, "disabled", nil)
		return nil
	}
	srv, err := m.ctor(cfg.Protocol, cfg.Options)
	if err != nil {
		err = fmt.Errorf("constructing %s server: %w", cfg.Protocol, err)
		r.setState(cfg, "error", err)
		return err
	}
	if cfg.SetupNAT {
		hn := hostnet.Config{
			TUNName: srv.TUNName(),
			Gateway: srv.Gateway(),
			Network: srv.Network(),
			WAN:     cfg.WAN,
		}
		switch aerr := m.applyHostnet(cfg.Name, hn); {
		case aerr == nil:
		case errors.Is(aerr, hostnet.ErrNoWAN):
			// The listener is addressed, up, and forwarding; it just has no
			// route off the host. That is a misconfiguration worth saying out
			// loud, not a reason to refuse to serve -- and certainly not a
			// reason to take the rest of the fleet down, which is what
			// returning here used to do at startup.
			m.log.Printf("supervisor: %s: %v; clients will reach this host but nothing beyond it", cfg.Name, aerr)
		default:
			// Apply may have installed part of its state before failing. Take it
			// back out so a retry starts from a clean host rather than from
			// whatever half of the rule set landed.
			_ = m.teardownHostnet(cfg.Name, hn)
			_ = srv.Close()
			aerr = fmt.Errorf("host networking: %w", aerr)
			r.setState(cfg, "error", aerr)
			return aerr
		}
	}
	done := make(chan struct{})
	r.mu.Lock()
	r.cfg, r.srv, r.state, r.since, r.serveErr, r.done =
		cfg, srv, "running", time.Now(), nil, done
	r.mu.Unlock()
	// srv and done are passed by value rather than re-read from r: by the time
	// the goroutine runs, a Stop may already have cleared both, and this
	// generation of the goroutine owns this generation's server.
	go serve(r, m.log, srv, done)
	return nil
}

// rebuildLocked is the per-listener cold rebuild: stop, construct new, start.
// It re-uses the running handle so external references to the listener (a status
// read that captured the pointer) keep referring to the same *running. On
// failure start leaves r in "error" state with the reason, so the next Apply
// retries it and the management API reports why. Manager.mu is held by the
// caller.
func (m *Manager) rebuildLocked(r *running, cfg ListenerConfig) error {
	m.stopLocked(r)
	return m.start(r, cfg)
}

// stopLocked closes the listener's server and waits for the goroutine to exit,
// then tears down any host-networking rules it owned. Called under Manager.mu;
// acquires r.mu.
func (m *Manager) stopLocked(r *running) {
	r.mu.Lock()
	srv, done, cfg := r.srv, r.done, r.cfg
	r.srv = nil
	// Clearing done retires this generation: a serve goroutine that returns
	// after this point finds r.done no longer its own and leaves the state
	// below alone.
	r.done = nil
	r.state = "stopped"
	r.since = time.Now()
	r.mu.Unlock()

	if srv != nil {
		_ = srv.Close()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			m.log.Printf("supervisor: %s: serve goroutine still running after 5s; carrying on", cfg.Name)
		}
	}
	// Host-state teardown for the listener's own rules; layer-2 / no-WAN
	// configs are a no-op in hostnet.Teardown, so it is safe to call
	// unconditionally.
	if cfg.SetupNAT {
		// We no longer have srv's TUNName/Gateway/Network (srv was just closed
		// and may have freed the TUN). Re-derive from the config's Options
		// where possible; otherwise the rules' removal survives on the comment
		// tag alone (which carries the name).
		_ = m.teardownHostnet(cfg.Name, hostnet.Config{
			TUNName: cfg.Options["tun"],
			WAN:     cfg.WAN,
		})
	}
}

// serve is the goroutine that owns one listener's ListenAndServe. It records the
// result and signals completion via a deferred close(done) so stopLocked can
// wait deterministically.
//
// srv and done are parameters, not reads off r, because this goroutine belongs
// to one generation of the listener: a rebuild installs a new server and a new
// done channel on the same handle. Publishing the result is gated on r.done
// still being this generation's channel, so a goroutine that returns after its
// server was replaced (or after stopLocked gave up waiting) cannot overwrite the
// live listener's state with its own stale outcome.
func serve(r *running, logger *log.Logger, srv client.Server, done chan struct{}) {
	defer close(done)
	err := srv.ListenAndServe()

	r.mu.Lock()
	current := r.done == done
	if current {
		r.serveErr = err
		if err != nil && !errors.Is(err, net.ErrClosed) {
			r.state = "error"
		} else {
			r.state = "stopped"
		}
		r.since = time.Now()
	}
	name, protocol := r.cfg.Name, r.cfg.Protocol
	r.mu.Unlock()

	if err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Printf("supervisor: %s/%s: %v", name, protocol, err)
	}
}
