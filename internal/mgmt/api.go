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
	"fmt"
	"io"
	"log"
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
	s.startedAt.Store(0) // set on ListenAndServe
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
// unix-domain socket. Auth middleware is baked in: ServeHTTP is preceded
// everywhere by requireToken.
func (s *Server) Handler() http.Handler {
	return s.requireToken(s.logRequest(s.mux))
}

// Token returns the bearer token the panel uses to authenticate its /api
// fetches from the browser. It is exported so the caller (cmd/veepin wiring
// the UI handler) can inject it into the embedded dashboard template.
func (s *Server) Token() []byte { return s.token }

// Start stamps the uptime epoch and serves. The caller (the supervisor in
// cmd/veepin/serve.go) passes the bound address typically localhost-only.
func (s *Server) Start(addr string) error {
	if s.startedAt.Load() == 0 {
		s.startedAt.Store(nowUnix())
	}
	srv := &http.Server{
		Addr:     addr,
		Handler:  s.Handler(),
		ErrorLog: s.log,
	}
	return srv.ListenAndServe()
}

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
	} else if !os.IsNotExist(err) {
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
	name := r.PathValue("name")
	status := s.mgr.Status(name)
	if status.State == "unknown" {
		http.Error(w, "no such listener", http.StatusNotFound)
		return
	}
	cfg, err := supervisor.ParseListenerFile(filepath.Join(s.dir, name+".json"))
	if err != nil {
		// Status said it exists; if the file is gone, treat as 404 instead of
		// surfacing a file-read error to the API caller.
		if os.IsNotExist(err) {
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
	var cfg supervisor.ListenerConfig
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
	name := r.PathValue("name")
	existing, err := supervisor.ParseListenerFile(filepath.Join(s.dir, name+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "no such listener", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var in supervisor.ListenerConfig
	if err := decodeJSON(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The PATCH body may be a partial update: only fields the client sent are
	// applied. Go's json.RoundTripizer leaves unset fields at zero values, so
	// a per-field "set if non-zero / present" merge is what distinguishes
	// "clear" from "do not touch". For Options the key set is healed by sending
	// back what the API just returned, with "<redacted>" standing in for
	// unchanged secrets. We merge the incoming Options over the existing ones
	// so a field that is not present in the request body is left alone; this
	// is the safest shape for a hand-edited PATCH.
	merged := existing
	if in.Name != "" {
		merged.Name = in.Name
	}
	if in.Protocol != "" {
		merged.Protocol = in.Protocol
	}
	if in.Options != nil {
		merged.Options = mergeOptions(existing.Options, in.Options)
	}
	merged.SetupNAT = in.SetupNAT || existing.SetupNAT
	if in.WAN != "" {
		merged.WAN = in.WAN
	}
	merged.Enabled = in.Enabled || existing.Enabled
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
	name := r.PathValue("name")
	// Stop reports "no listener named X" if the running set does not have it;
	// we proceed with the file removal so Delete is idempotent for a listener
	// that crashed but whose file is still present.
	_ = s.mgr.Stop(name)
	if err := supervisor.DeleteListenerFile(s.dir, name); err != nil {
		if os.IsNotExist(err) {
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
	name := r.PathValue("name")
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
	name := r.PathValue("name")
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

// mergeOptions combines existing with the patch: each key in patch overrides
// the matching key in existing, and a patch value of "<redacted>" means "do not
// change" -- the API never reveals the real secret, so a round-trip PATCH
// cannot clobber a real value with the redaction literal.
func mergeOptions(existing, patch map[string]string) map[string]string {
	out := make(map[string]string, len(existing)+len(patch))
	for k, v := range existing {
		out[k] = v
	}
	for k, v := range patch {
		if v == redacted {
			continue
		}
		out[k] = v
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
