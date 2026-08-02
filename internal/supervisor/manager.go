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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
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

	// buildMu serializes stop/start on this handle. A rebuild is stop-then-start
	// and the whole sequence takes the lock, so two concurrent rebuilds (an API
	// restart racing a SIGHUP reconcile) cannot interleave a Close with a fresh
	// ListenAndServe on the same handle. Rebuild releases Manager.mu around the
	// rebuild so the "building" state is observable and a slow build does not
	// freeze every other listener's status read; buildMu is what makes that safe.
	buildMu sync.Mutex
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

// teardownHostnetState is the persisted-state form of teardownHostnet, used by
// stopLocked so rules are removed for what Apply actually installed, not for
// whatever the listener's config now says.
func (m *Manager) teardownHostnetState(name string, st hostnet.State) error {
	if m.run == nil {
		return hostnet.TeardownState(name, st)
	}
	return hostnet.TeardownStateWithName(name, st, m.run)
}

// teardownHostnetByTag is the recovery form, used when no persisted state
// survives to say what was installed.
func (m *Manager) teardownHostnetByTag(name string) error {
	if m.run == nil {
		return hostnet.TeardownByTag(name)
	}
	return hostnet.TeardownByTagWithName(name, m.run)
}

// hostnetStatePath is where the supervisor persists what hostnet.Apply installed
// for one listener. Teardown reads it back because a listener's config may have
// been edited since (WAN dropped, address changed) and a kernel-assigned TUN
// name exists only in this record once the server that owned it is closed; a
// teardown re-derived from the config would remove nothing.
func hostnetStatePath(dir, name string) string {
	return filepath.Join(dir, "mgmt", "hostnet", name+".json")
}

// persistHostnetState records the host state Apply just installed, so a later
// stop/rebuild/delete can remove exactly that. Only reached for listeners with
// SetupNAT; a state with an empty WAN or Network installed no rules, and
// TeardownState treats it as a no-op, so the file lifecycle is uniform. Failure
// to persist is logged, not fatal -- the listener is up and serving either way.
//
// Written through a temp file, synced, and renamed, like every other config
// this daemon owns. os.WriteFile truncates in place, so a crash between
// truncate and write leaves valid-length garbage that loadHostnetState cannot
// parse, which drops teardown onto the tag-scan recovery path for no reason;
// and skipping the sync entirely leaves the same hazard one rename later, on
// filesystems whose rename is not ordered behind the data.
func (m *Manager) persistHostnetState(name string, st hostnet.State) {
	body, err := json.Marshal(st)
	if err != nil {
		m.log.Printf("supervisor: %s: persisting host state: %v", name, err)
		return
	}
	path := hostnetStatePath(m.dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		m.log.Printf("supervisor: %s: creating host-state dir: %v", name, err)
		return
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		m.log.Printf("supervisor: %s: writing host state: %v", name, err)
		return
	}
	// The temp file is never kept past its rename; if anything below fails, the
	// only harm is a stale temp that a later persist truncates again.
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		m.log.Printf("supervisor: %s: writing host state: %v", name, err)
		return
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		m.log.Printf("supervisor: %s: syncing host state: %v", name, err)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		m.log.Printf("supervisor: %s: closing host state: %v", name, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		m.log.Printf("supervisor: %s: installing host state: %v", name, err)
	}
}

// loadHostnetState reads back what Apply installed for name, or nil when nothing
// was persisted -- a listener that predates this feature, or one that never
// installed host state.
func (m *Manager) loadHostnetState(name string) *hostnet.State {
	body, err := os.ReadFile(hostnetStatePath(m.dir, name))
	if err != nil {
		return nil
	}
	var st hostnet.State
	if err := json.Unmarshal(body, &st); err != nil {
		m.log.Printf("supervisor: %s: host state unreadable; tearing down from config: %v", name, err)
		return nil
	}
	return &st
}

// removeHostnetState drops the persisted record once teardown has consumed it.
func (m *Manager) removeHostnetState(name string) {
	_ = os.Remove(hostnetStatePath(m.dir, name))
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
//
// Manager.mu is released for the rebuild itself: holding it across a slow
// construction would freeze every other listener's status read and, worse,
// make the "building" state unobservable through the API (Status needs the
// lock to look the handle up). buildMu on the handle serializes the rebuild
// against a concurrent SIGHUP reconcile, and the handle is put back if a
// concurrent Apply stopped and removed it while we were building.
func (m *Manager) Rebuild(name string) error {
	m.mu.Lock()
	r, ok := m.listeners[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("supervisor: no listener named %q", name)
	}
	cfgs, err := LoadDir(m.dir)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	cfg, ok := cfgs[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("supervisor: %q has no on-disk config; DeleteListenerFile removed it", name)
	}
	m.mu.Unlock()
	err = m.rebuildLocked(r, cfg)
	// A SIGHUP reconcile that ran while we were rebuilding may have stopped
	// this listener and dropped it from the map; a listener that just came up
	// must not be left running untracked.
	m.mu.Lock()
	if _, still := m.listeners[name]; !still {
		m.listeners[name] = r
	}
	m.mu.Unlock()
	return err
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

// Peers returns the live peer list for a running listener whose protocol
// implements client.PeerDescriber. exists is false when the listener is not
// tracked or is not running (its server handle is nil); a true exists with a
// nil slice means the protocol does not describe peers, which the caller must
// render as "no peer feature" rather than "no peers".
//
// The PeerDescriber call runs while holding r.mu. That ordering is the point:
// stopLocked clears r.srv and spawns srv.Close while holding r.mu, so a
// concurrent rebuild or stop blocks on r.mu before it can tear the server down
// underneath this call. Reading the live server through Server() and calling
// Peers() afterward released r.mu first, which left the raw handle open to a
// use-after-close exactly when a panel poll raced a rekey or a rebuild.
func (m *Manager) Peers(name string) ([]client.PeerInfo, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.listeners[name]
	if !ok {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.srv == nil {
		return nil, false
	}
	pd, ok := r.srv.(client.PeerDescriber)
	if !ok {
		return nil, true
	}
	return pd.Peers(), true
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
		// Said out loud. A listener that is present, valid, and deliberately not
		// running is indistinguishable at a glance from one that failed to start,
		// and the operator's next question is always which of the two it is.
		m.log.Printf("supervisor: %s/%s: disabled by config; not started", cfg.Name, cfg.Protocol)
		r.setState(cfg, "disabled", nil)
		return nil
	}
	// Published before construction so a slow build is visible rather than a
	// stale "running" (or a pre-rebuild "building") that makes the panel look
	// frozen. Construction can block on a TUN open and a syscall or two of
	// iptables, which is exactly the moment an operator staring at the panel
	// wants to know something is happening.
	r.mu.Lock()
	r.state = "building"
	r.since = time.Now()
	r.mu.Unlock()
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
			m.persistHostnetState(cfg.Name, hn.State())
		case errors.Is(aerr, hostnet.ErrNoWAN):
			// The listener is addressed, up, and forwarding; it just has no
			// route off the host. That is a misconfiguration worth saying out
			// loud, not a reason to refuse to serve -- and certainly not a
			// reason to take the rest of the fleet down, which is what
			// returning here used to do at startup. The state is still
			// persisted, so a later rebuild that adds a WAN tears the rules
			// it then installs down correctly.
			m.log.Printf("supervisor: %s: %v; clients will reach this host but nothing beyond it", cfg.Name, aerr)
			m.persistHostnetState(cfg.Name, hn.State())
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
// retries it and the management API reports why.
//
// Called with Manager.mu held (Apply) or not (Rebuild); buildMu serializes the
// two so a SIGHUP reconcile and an API restart cannot rebuild the same handle
// concurrently.
func (m *Manager) rebuildLocked(r *running, cfg ListenerConfig) error {
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	// Published before the stop so the whole stop-then-start sequence reads as
	// one "building" phase to the panel. Without this the listener flashes
	// "stopped" between the two halves, and a rebuild that takes a moment looks
	// like the listener was taken down rather than being reconfigured.
	r.mu.Lock()
	r.state = "building"
	r.since = time.Now()
	r.mu.Unlock()
	m.stopLockedInner(r)
	return m.start(r, cfg)
}

// stopGrace bounds how long a single listener may take to shut down before the
// supervisor stops waiting for it. It covers Close and the serve goroutine's
// exit together, so one listener's teardown cannot exceed it.
const stopGrace = 5 * time.Second

// stopLocked closes the listener's server and waits for the goroutine to exit,
// then tears down any host-networking rules it owned. Called under Manager.mu;
// acquires buildMu and r.mu. rebuildLocked calls stopLockedInner directly while
// holding buildMu, so the whole stop-then-start stays one critical section.
//
// Both waits are bounded, and Close is called on a goroutine rather than inline,
// because Close can block. The once-central cause is fixed: dataplane's TUN fd
// is held non-blocking and polled against a wake eventfd, so a Close waiting on
// its packet pump unblocks instead of hanging on an idle tunnel. But Close can
// still stall on any other blocking path a protocol owns (a wedged control
// connection, a peer that never answers), and this package's job is that one
// listener can never freeze the fleet.
//
// That is invisible to `veepin serve <proto>`: it calls Close and exits, and the
// kernel cleans up. It is not invisible here. stopLocked runs under Manager.mu,
// so an unbounded Close would freeze every Status, Apply, and Rebuild in the
// fleet behind it -- one listener wedging the entire management plane, which is
// the failure this whole package exists to avoid. Bounded, the listener is
// abandoned with a log line and the rest of the fleet keeps serving.
//
// Abandoning leaks the pump goroutine and its fd until the process exits. That
// is the lesser of the two evils here and is named in
// internal/supervisor/README.md; the real fix is for dataplane to make a blocked
// TUN read interruptible, which is a change to the allocation-guarded data path
// and belongs on its own.
func (m *Manager) stopLocked(r *running) {
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	m.stopLockedInner(r)
}

// stopLockedInner is the teardown itself. Callers must hold r.buildMu.
func (m *Manager) stopLockedInner(r *running) {
	r.mu.Lock()
	srv, done, cfg := r.srv, r.done, r.cfg
	r.srv = nil
	// Clearing done retires this generation: a serve goroutine that returns
	// after this point finds r.done no longer its own and leaves the state
	// below alone.
	r.done = nil
	if r.state != "building" {
		// A rebuild pre-sets "building" and then calls this; keeping it means
		// the whole stop-then-start sequence reads as one "building" phase
		// instead of flashing "stopped" during the (possibly slow) Close. Every
		// other caller is a real stop, where "stopped" is the truth.
		r.state = "stopped"
	}
	r.since = time.Now()
	r.mu.Unlock()

	// One deadline for the whole teardown, shared by both waits below.
	deadline := time.After(stopGrace)
	var abandoned bool
	if srv != nil {
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			_ = srv.Close()
		}()
		select {
		case <-closed:
		case <-deadline:
			abandoned = true
			m.log.Printf("supervisor: %s: Close did not return within %s; abandoning the listener "+
				"(its packet pump is blocked reading the TUN and will exit when a packet arrives)",
				cfg.Name, stopGrace)
		}
	}
	// No point waiting on the serve goroutine if Close has not even returned:
	// ListenAndServe cannot unblock before the thing it is serving is closed.
	if done != nil && !abandoned {
		select {
		case <-done:
		case <-deadline:
			m.log.Printf("supervisor: %s: serve goroutine still running after %s; carrying on",
				cfg.Name, stopGrace)
		}
	}
	// Host-state teardown for the listener's own rules; layer-2 / no-WAN
	// configs are a no-op in hostnet.Teardown, so it is safe to call
	// unconditionally.
	if cfg.SetupNAT {
		// Teardown from the persisted State, not from the current config: it
		// records the TUNName/Gateway/Network/WAN that Apply actually used,
		// where the config may have been edited since (WAN dropped) or never
		// named the interface (kernel-assigned tunN). An earlier version
		// re-derived a Config here with a nil Network, which made hostnet's
		// Teardown a silent no-op and left every tagged rule behind on
		// rebuild and delete.
		if st := m.loadHostnetState(cfg.Name); st != nil {
			_ = m.teardownHostnetState(cfg.Name, *st)
		} else {
			// No persisted record: a listener that predates this feature, or a
			// state file lost to a crash mid-write. Fall back to deleting by
			// the comment tag every rule Apply installs carries.
			//
			// The previous fallback re-derived a hostnet.Config here with a nil
			// Network, whose State() has an empty Network, which TeardownState
			// treats as "nothing rule-shaped was installed" and returns from
			// immediately. So the branch reached only in the case that leaks
			// rules was itself guaranteed to remove nothing -- the very bug the
			// persisted state was added to fix, preserved as a no-op under a
			// comment claiming it worked.
			if err := m.teardownHostnetByTag(cfg.Name); err != nil {
				m.log.Printf("supervisor: %s: tagged host-state teardown: %v", cfg.Name, err)
			}
		}
		m.removeHostnetState(cfg.Name)
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
