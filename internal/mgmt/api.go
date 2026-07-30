// Package mgmt is the supervisor's management plane: a small REST API for the
// listener directory that uses the supervisor.Manager as its data backend.
//
// It is stdlib-only by design: the strict-dependency contract (golang.org/x/*
// and nothing else at runtime) forbids a router library, so net/http.ServeMux
// pattern matching is enough for the surface below. The same contract forbids
// a logging library: a single *log.Logger writes a line per request.
//
// Auth is a bearer token generated on first run and stored at <config>/mgmt/token
// mode 0600 root-only, the same filesystem-protection posture the protocol
// facades' PEM and key files already rely on. The token is compared with
// crypto/subtle.ConstantTimeCompare.
//
// Secrets at rest in a ListenerConfig's Options map (private keys, PSKs,
// passphrases) are redacted on read by querying each protocol's
// client.ServerOptsFor metadata for Secret=true fields. Redaction replaces the
// value with the literal "<redacted>"; a PATCH that submits "<redacted>" for a
// secret key preserves the on-disk value rather than overwriting it with the
// placeholder, so a GET-then-PATCH round trip does not destroy the key.
package mgmt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/supervisor"
)

// redacted is the value the API writes in place of a secret option. It
// cannot collide with a real protocol value: it is not a valid key, not a
// valid PSK, not a valid base64; sending it back is treated as "leave
// unchanged".
const redacted = "<redacted>"

// tokenName is the mgmt-bearer-token file name within the config dir.
const tokenName = "token"

// ManagerBackend is the supervisor surface the management API uses. The real
// *supervisor.Manager implements it; tests pass a fake so the HTTP layer runs
// in plain `go test` with no TUNs or sockets.
type ManagerBackend interface {
	Apply() error
	All() []supervisor.Status
	Status(name string) supervisor.Status
	Rebuild(name string) error
	Stop(name string) error
	Close() error
	Server(name string) client.Server
}

// Server is the management HTTP server.
type Server struct {
	mgr   ManagerBackend
	dir   string
	token []byte
	log   *log.Logger
	mux   *http.ServeMux

	// startedAt is the supervisor uptime start the health endpoint reports.
	startedAt atomic.Int64
}

// NewServer prepares the management plane for the given config dir: it reads
// or mints the bearer token, then wires routes under /api/. The Manager is the
// running-supervisor backend; dir is the on-disk config root that the POST/
// PATCH/DELETE endpoints persist to. NewServer is the canonical place the token
// is generated; it writes the token file once and reads it thereafter, so the
// operator can extract it from disk if the once-only log line was missed.
func NewServer(dir string, mgr ManagerBackend, logger *log.Logger) (*Server, error) {
	if dir == "" {
		return nil, fmt.Errorf("mgmt: config dir is required")
	}
	if mgr == nil {
		return nil, fmt.Errorf("mgmt: supervisor manager is required")
	}
	if err := os.MkdirAll(filepath.Join(dir, "mgmt"), 0o700); err != nil {
		return nil, fmt.Errorf("mgmt: creating mgmt dir: %w", err)
	}
	tokenPath := filepath.Join(dir, "mgmt", tokenName)
	token, fresh, err := bootToken(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("mgmt: token boot: %w", err)
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	s := &Server{
		mgr:   mgr,
		dir:   dir,
		token: token,
		log:   logger,
		mux:   http.NewServeMux(),
	}
	// Stamped here rather than on a serve call. The supervisor mounts Handler on
	// its own mux (it also serves the panel at the root) and never went through
	// a Start method, so an uptime the serve path was supposed to set stayed
	// zero and /api/health reported the whole Unix epoch as uptime.
	s.startedAt.Store(nowUnix())
	if fresh {
		logger.Printf("mgmt: no bearer token found; generated one at %s (mode 0600)", tokenPath)
	}

	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/protocols", s.handleProtocols)
	s.mux.HandleFunc("GET /api/listeners", s.handleListListeners)
	s.mux.HandleFunc("POST /api/listeners", s.handleCreateListener)
	s.mux.HandleFunc("GET /api/listeners/{name}", s.handleGetListener)
	s.mux.HandleFunc("PATCH /api/listeners/{name}", s.handlePatchListener)
	s.mux.HandleFunc("DELETE /api/listeners/{name}", s.handleDeleteListener)
	s.mux.HandleFunc("POST /api/listeners/{name}/restart", s.handleRestartListener)
	s.mux.HandleFunc("GET /api/listeners/{name}/peers", s.handlePeerList)
	return s, nil
}

// Handler returns the mux so a caller can wrap it in TLS or run it through a
// unix-domain socket. Auth middleware is baked in: every /api/ request goes
// through requireToken.
//
// logRequest is on the outside, so a rejected request is logged too. With the
// order reversed -- which it was -- requireToken short-circuited before the
// logger ever ran, and failed authentication was the one thing the management
// plane never wrote a line about.
func (s *Server) Handler() http.Handler {
	return s.logRequest(s.requireToken(s.mux))
}

// Token returns the bearer token the panel uses to authenticate its /api
// fetches from the browser. It is exported so the caller (cmd/veepin wiring
// the UI handler) can inject it into the embedded dashboard template.
func (s *Server) Token() []byte { return s.token }

// Close delegates to the manager; it is exposed so a caller wiring the API
// server into a wider HTTP mux can tear it down cleanly the same way the
// management CLI does.
func (s *Server) Close() error { return s.mgr.Close() }

// --- Token boot ---

// bootToken reads or generates the bearer token at path. The "fresh" return is
// true on the path where the file did not exist and we minted a new one (the
// caller logs that once). The token is 256 random bits hex-encoded so it is
// safe to put on a command line and into a header line.
func bootToken(path string) ([]byte, bool, error) {
	if body, err := os.ReadFile(path); err == nil {
		trimmed := strings.TrimSpace(string(body))
		if trimmed == "" {
			return nil, false, fmt.Errorf("token file %s is empty", path)
		}
		return []byte(trimmed), false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	// Generate 32 random bytes; hex-print to keep it printable and round-trip
	// safely through a shell. The owner-only permission matches the same
	// posture the listener config files carrying private keys use.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, false, err
	}
	token := []byte(hex.EncodeToString(raw))
	if err := os.WriteFile(path, append(token, '\n'), 0o600); err != nil {
		return nil, false, err
	}
	return token, true, nil
}

// --- Middleware ---

// RequireHost rejects any request whose Host header names neither the loopback
// interface nor one of the extra hosts the operator deliberately bound to. It
// wraps the whole management listener -- panel and API together -- and the
// caller in cmd/veepin passes its -listen address as the extra.
//
// This is the DNS-rebinding guard, and it protects the panel more than the API.
// The panel is unauthenticated by necessity: it is the thing that hands the
// browser the token, so it cannot itself require one. The bearer header stops
// ordinary cross-origin abuse -- JavaScript on another site cannot set
// Authorization without a CORS preflight the supervisor never grants -- but a
// site that rebinds its own hostname to 127.0.0.1 stops being cross-origin at
// all. It can then fetch "/", read the token straight out of the page, and drive
// every endpoint with the operator's full authority.
//
// What gives it away is the Host header: the browser sends the name it dialled,
// so the rebound request arrives as `Host: attacker.example`, never as a
// loopback literal. Requiring one closes the hole. "localhost" is allowed
// alongside the IP literals because operators type it and it is not a name an
// attacker's DNS can claim.
func RequireHost(extra []string, next http.Handler) http.Handler {
	allow := make(map[string]bool, len(extra))
	for _, a := range extra {
		if h := hostOnly(a); h != "" {
			allow[h] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostAllowed(hostOnly(r.Host), allow) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "forbidden: unrecognised Host header; the management plane "+
			"answers on loopback and on its own bind address only", http.StatusForbidden)
	})
}

// hostAllowed reports whether host may address the management plane.
func hostAllowed(host string, allow map[string]bool) bool {
	if host == "" {
		return false
	}
	if allow[host] {
		return true
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// hostOnly strips the port from a "host:port" authority, tolerating a bare host
// and unwrapping the brackets around an IPv6 literal.
func hostOnly(authority string) string {
	if h, _, err := net.SplitHostPort(authority); err == nil {
		return h
	}
	return strings.Trim(authority, "[]")
}

// requireToken is the auth layer. A request without a matching
// "Authorization: Bearer <token>" header gets a 401. Token comparison is
// constant-time. Trails /api/* only; the panel's static assets live at the root
// under the same handler in Phase 5 and are unauthenticated by design (the
// browser is a single tenant, localhost-only). For non-/api paths the function
// passes through.
func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		got := bearer(r.Header.Get("Authorization"))
		if len(got) == 0 {
			http.Error(w, "unauthorized: missing bearer token", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare(got, s.token) != 1 {
			http.Error(w, "unauthorized: bad token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// logRequest emits one line per request: method, path, status, elapsed. It is
// the minimum operator's view, and the only structured-ish output the
// management plane produces.
func (s *Server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.Printf("mgmt: %s %s -> %d", r.Method, r.URL.Path, rec.status)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(s int) {
	r.status = s
	r.ResponseWriter.WriteHeader(s)
}

// bearer parses "Bearer <token>" headers. The lowercased comparison is per RFC
// 7235; an empty Authorization header returns nil.
func bearer(h string) []byte {
	const pfx = "bearer "
	if len(h) <= len(pfx) || !strings.EqualFold(h[:len(pfx)], pfx) {
		return nil
	}
	return []byte(strings.TrimSpace(h[len(pfx):]))
}

// --- Endpoints ---

// pathName pulls the {name} segment out of the route and checks it against the
// listener-name grammar before it is ever joined into a filesystem path. Only
// DeleteListenerFile validated, so the GET and PATCH handlers built a filename
// out of whatever the router happened to match. Go's ServeMux makes that hard to
// abuse -- a {name} wildcard spans one segment and the request path is cleaned
// before routing -- but "hard to abuse" is not the bar for a string that becomes
// a filename, and the check is one line.
//
// Returns "" and writes the response when the name is not one the supervisor
// could ever have written; the caller returns on an empty result.
func (s *Server) pathName(w http.ResponseWriter, r *http.Request) string {
	name := r.PathValue("name")
	if !supervisor.ValidName(name) {
		http.Error(w, "no such listener", http.StatusNotFound)
		return ""
	}
	return name
}

// handleHealth answers a basic liveness probe.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	start := s.startedAt.Load()
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "uptime": nowUnix() - start})
}

// ProtocolsResp is the body of GET /api/protocols.
type ProtocolsResp struct {
	Protocols []ProtocolDesc `json:"protocols"`
}

// ProtocolDesc is one protocol's surface the panel can render.
type ProtocolDesc struct {
	Name    string           `json:"name"`
	Options []client.OptSpec `json:"options,omitempty"`
	Known   bool             `json:"known"` // always true for client.ServerProtocols() entries
}

func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	names := client.ServerProtocols()
	out := ProtocolsResp{Protocols: make([]ProtocolDesc, 0, len(names))}
	for _, name := range names {
		opts, _ := client.ServerOptsFor(name)
		out.Protocols = append(out.Protocols, ProtocolDesc{Name: name, Options: opts, Known: true})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListListeners(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	statuses := s.mgr.All()
	// Add the on-disk configs for listeners that are not yet built (disabled).
	// The status' State="disabled" or "stopped" carries the info; full config
	// is fetched per-name via GET /api/listeners/{name}.
	writeJSON(w, http.StatusOK, map[string]any{"listeners": statuses})
}

// listenerResponse is one listener's full description: its visible status plus
// its on-disk config with secrets redacted. The panel combines the two views.
type listenerResponse struct {
	supervisor.Status
	Config supervisor.ListenerConfig `json:"config"`
}

func (s *Server) handleGetListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	status := s.mgr.Status(name)
	if status.State == "unknown" {
		http.Error(w, "no such listener", http.StatusNotFound)
		return
	}
	cfg, err := supervisor.ParseListenerFile(filepath.Join(s.dir, name+".json"))
	if err != nil {
		// Status said it exists; if the file is gone, treat as 404 instead of
		// surfacing a file-read error to the API caller.
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "no such listener", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.Options = redactOptions(cfg.Protocol, cfg.Options, true)
	writeJSON(w, http.StatusOK, listenerResponse{Status: status, Config: cfg})
}

func (s *Server) handleCreateListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Start from the same defaults a hand-written config file gets, so a create
	// that stays silent about "enabled" produces a running listener rather than
	// one that is stored, listed, and never started.
	cfg := supervisor.NewListenerConfig()
	if err := decodeJSON(r, &cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := cfg.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !supervisor.KnownProtocol(cfg.Protocol) {
		http.Error(w, "unknown protocol", http.StatusBadRequest)
		return
	}
	// POST creates. Without this check it also silently overwrote, so a repeated
	// create -- a double-submitted form, a re-run script -- replaced a live
	// listener's config, keys and all, and reported 201. Editing goes through
	// PATCH, which preserves what it is not told to change.
	if _, err := os.Stat(filepath.Join(s.dir, cfg.Name+".json")); err == nil {
		http.Error(w, "a listener with that name already exists; PATCH it to edit",
			http.StatusConflict)
		return
	} else if !errors.Is(err, fs.ErrNotExist) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := supervisor.WriteListenerFile(s.dir, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.mgr.Apply(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, s.mgr.Status(cfg.Name))
}

func (s *Server) handlePatchListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	existing, err := supervisor.ParseListenerFile(filepath.Join(s.dir, name+".json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "no such listener", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var in listenerPatch
	if err := decodeJSON(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// A rename would have to move the file and retire the old listener. The
	// previous version did neither: it wrote <newname>.json, left <oldname>.json
	// in place, and rebuilt the old name -- so one edit produced two listeners.
	// Refuse it and say what to do instead.
	if in.Name != nil && *in.Name != name {
		http.Error(w, "renaming a listener is not supported: create the new one and delete the old",
			http.StatusBadRequest)
		return
	}
	merged := in.applyTo(existing)
	if err := merged.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !supervisor.KnownProtocol(merged.Protocol) {
		http.Error(w, "unknown protocol", http.StatusBadRequest)
		return
	}
	if err := supervisor.WriteListenerFile(s.dir, merged); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Rebuild this listener, not Apply-all: an Apply that fails because
	// another unrelated listener fails should not block this PATCH's effect.
	if err := s.mgr.Rebuild(name); err != nil {
		// The new config file is on disk; the rebuild error is reported but
		// the operator can retry via POST .../restart. HTTP 202 conveys
		// "accepted, partially applied".
		writeJSON(w, http.StatusAccepted,
			map[string]any{"status": "saved", "build_error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status(name))
}

func (s *Server) handleDeleteListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	// Stop reports "no listener named X" if the running set does not have it;
	// we proceed with the file removal so Delete is idempotent for a listener
	// that crashed but whose file is still present.
	_ = s.mgr.Stop(name)
	if err := supervisor.DeleteListenerFile(s.dir, name); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "no such listener", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

func (s *Server) handleRestartListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	if err := s.mgr.Rebuild(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status(name))
}

// handlePeerList returns the peer list for a running listener whose protocol
// implements client.PeerDescriber. Protocols that do not implement it return
// an empty array; the panel renders nothing rather than showing a misleading
// "no peers" which could be read as "no clients".
func (s *Server) handlePeerList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	srv := s.mgr.Server(name)
	if srv == nil {
		http.Error(w, "no such listener", http.StatusNotFound)
		return
	}
	var peers []client.PeerInfo
	if pd, ok := srv.(client.PeerDescriber); ok {
		peers = pd.Peers()
	}
	if peers == nil {
		peers = []client.PeerInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"peers": peers})
}

// --- Helpers ---

// listenerPatch is a presence-aware view of a PATCH body.
//
// A plain supervisor.ListenerConfig cannot serve as one: encoding/json leaves an
// absent field at its zero value, so `"enabled": false` and an omitted "enabled"
// decode identically. The merge then has no way to tell "leave it alone" from
// "turn it off", and the previous version resolved that with
//
//	merged.Enabled = in.Enabled || existing.Enabled
//
// which made every boolean one-way: unchecking "enabled" or "-setup-nat" in the
// panel silently did nothing, and there was no way to disable a listener through
// the API at all. Pointers distinguish the two cases, which is the whole reason
// they are here.
type listenerPatch struct {
	Name     *string            `json:"name,omitempty"`
	Protocol *string            `json:"protocol,omitempty"`
	Options  *map[string]string `json:"options,omitempty"`
	SetupNAT *bool              `json:"setup_nat,omitempty"`
	WAN      *string            `json:"wan,omitempty"`
	Enabled  *bool              `json:"enabled,omitempty"`
}

// applyTo merges the fields the request actually carried onto existing, leaving
// every field it did not mention alone.
func (p listenerPatch) applyTo(existing supervisor.ListenerConfig) supervisor.ListenerConfig {
	out := existing
	if p.Name != nil {
		out.Name = *p.Name
	}
	if p.Protocol != nil {
		out.Protocol = *p.Protocol
	}
	if p.Options != nil {
		out.Options = mergeOptions(existing.Options, *p.Options)
	}
	if p.SetupNAT != nil {
		out.SetupNAT = *p.SetupNAT
	}
	if p.WAN != nil {
		out.WAN = *p.WAN
	}
	if p.Enabled != nil {
		out.Enabled = *p.Enabled
	}
	return out
}

// mergeOptions combines existing with the patch. A key the patch does not
// mention is left alone, which is what makes a hand-written curl PATCH carrying
// one option safe. Two values are special:
//
//	"<redacted>"  keep the stored value. The API never reveals a real secret, so
//	              a GET-then-PATCH round trip must not clobber the key with the
//	              placeholder it was shown.
//	""            delete the key. This is how the panel clears a field, since it
//	              submits every option the protocol declares on every save and
//	              needs a way to say "unset". Overloading empty is safe because
//	              the server parse functions already read a missing key and an
//	              empty one identically.
func mergeOptions(existing, patch map[string]string) map[string]string {
	out := make(map[string]string, len(existing)+len(patch))
	for k, v := range existing {
		out[k] = v
	}
	for k, v := range patch {
		switch v {
		case redacted:
		case "":
			delete(out, k)
		default:
			out[k] = v
		}
	}
	return out
}

// redactOptions replaces values of the secret keys a protocol declares with the
// "<redacted>" sentinel. It does not modify an empty options map. Protocols
// without an ServerOpts declaration are left untouched -- the API cannot tell
// which of their keys are secret, and they are out of established coverage.
func redactOptions(protocol string, opts map[string]string, _ bool) map[string]string {
	if opts == nil {
		return nil
	}
	specs, ok := client.ServerOptsFor(protocol)
	if !ok {
		return opts
	}
	for _, spec := range specs {
		if !spec.Secret {
			continue
		}
		if v, has := opts[spec.Key]; has && v != "" {
			opts[spec.Key] = redacted
		}
	}
	return opts
}

// decodeJSON reads a request body sized for the small config documents the API
// accepts, into a target pointer. A nil body or a body over 1 MiB is rejected.
func decodeJSON(r *http.Request, v any) error {
	const maxBody = 1 << 20 // 1 MiB; a listener config is much smaller
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("reading body: %w", err)
	}
	if len(body) == 0 {
		return fmt.Errorf("empty body")
	}
	if len(body) > maxBody {
		return fmt.Errorf("body exceeds 1 MiB")
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decoding JSON: %w", err)
	}
	return nil
}

// writeJSON serializes v with pretty indentation so a curl response is readable
// without help. Pretty output costs bytes, never correctness. HTML escaping is
// disabled so the "<redacted>" sentinel survives a Serialize/Deserialize/Patch
// round trip verbatim: the JSON default would escape "<" to "\u003c", which is
// safe but visually obscures the sentinel an operator reads in a curl.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// nowUnix is a slim wrapper kept for testability.
func nowUnix() int64 {
	return time.Now().Unix()
}
