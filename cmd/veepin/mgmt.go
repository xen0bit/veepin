package main

// runMgmt is the CLI's client of the supervisor's management API. It is a
// thin curl-equivalent: the subcommand names match the verbs the API exposes,
// and it reads VEEPIN_MGMT_URL (default http://127.0.0.1:8443) and
// VEEPIN_MGMT_TOKEN (required) to point at a running supervisor instance. The
// whole surface here does no JSON envelope management beyond what the API
// already requires: arguments that are URLs, names, or file paths.
//
// Subcommands map 1:1 to /api endpoints so an operator's `veepin mgmt ls` and
// the panel's `GET /api/listeners` are visibly the same operation, keeping the
// CLI the bottom of the management stack rather than a parallel interface.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xen0bit/veepin/client"
)

// mgmtHTTPTimeout bounds every request the management CLI makes. The API's
// mutation endpoints can block on a rebuild that waits out the supervisor's
// 5-second close grace, so a wedged listener should cost the operator a clear
// timeout error, not a CLI that hangs until they kill it.
const mgmtHTTPTimeout = 30 * time.Second

// runMgmt dispatches to a subcommand. With no subcommand it prints usage.
func runMgmt(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(`usage: veepin mgmt <subcommand>
subcommands:
  ls                          list running listeners [-json] [-q]
  status <name>               status of one listener [-json]
  protocols                   protocols the supervisor can run [-json]
  add                         create a listener from a JSON config on stdin [-json]
  edit <name>                 PATCH <name> from a partial JSON config on stdin [-json]
  restart <name>              rebuild <name> from its on-disk config [-json]
  rm <name>                   stop and delete <name> [-y] [-json]
  audit                       recent management-plane activity [-json]
  client-config <name>        generate a client profile for a listener [-endpoint host[:port]] [-set k=v] [-o dir] [-json]
environment:
  VEEPIN_MGMT_URL            base URL (default http://127.0.0.1:8443)
  VEEPIN_MGMT_TOKEN          bearer token (default: read /etc/veepin/mgmt/token)
  VEEPIN_MGMT_TOKEN_FILE     a different token file to read when TOKEN is unset`)
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "ls":
		return mgmtList(rest)
	case "status":
		return mgmtStatus(rest)
	case "protocols":
		return mgmtProtocols(rest)
	case "add":
		return mgmtAdd(rest)
	case "edit":
		return mgmtEdit(rest)
	case "restart":
		return mgmtRestart(rest)
	case "rm":
		return mgmtRm(rest)
	case "audit":
		return mgmtAudit(rest)
	case "client-config":
		return mgmtClientConfig(rest)
	default:
		return fmt.Errorf("mgmt: unknown subcommand %q", sub)
	}
}

// mgmtClient wraps token/binding env and sends one request to the API. The body
// is decoded as JSON when the response is 2xx, otherwise the raw body is
// printed and the error returned.
type mgmtClient struct {
	base  string
	token string
	http  *http.Client
}

func newMgmtClient() (*mgmtClient, error) {
	base := os.Getenv("VEEPIN_MGMT_URL")
	if base == "" {
		base = "http://127.0.0.1:8443"
	}
	tok := os.Getenv("VEEPIN_MGMT_TOKEN")
	if tok == "" {
		// The supervisor mints <config>/mgmt/token on first run; falling back
		// to it means `sudo veepin mgmt ls` works without the operator exporting
		// anything (and a non-root user gets a clean error below instead of a
		// permission-denied reading the file). VEEPIN_MGMT_TOKEN_FILE names a
		// different token file.
		path := os.Getenv("VEEPIN_MGMT_TOKEN_FILE")
		if path == "" {
			path = "/etc/veepin/mgmt/token"
		}
		if body, err := os.ReadFile(path); err == nil {
			tok = strings.TrimSpace(string(body))
		}
	}
	if tok == "" {
		return nil, fmt.Errorf("mgmt: VEEPIN_MGMT_TOKEN is required (export it, or run as a user " +
			"who can read /etc/veepin/mgmt/token)")
	}
	return &mgmtClient{
		base:  strings.TrimRight(base, "/"),
		token: tok,
		http:  &http.Client{Timeout: mgmtHTTPTimeout},
	}, nil
}

// do sends a request and returns the parsed body alongside the HTTP status. On
// a non-2xx response, the raw body becomes the error.
func (c *mgmtClient) do(method, path string, body io.Reader) (any, error) {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var v any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &v)
	}
	return v, nil
}

// buildErrorOf digs the API's "accepted, partially applied" marker out of a
// decoded response body. PATCH /api/listeners/{name} answers 202 with a
// build_error field when the config was saved but the cold rebuild failed; the
// caller must surface it as the failure it is, not swallow it as a 2xx success.
func buildErrorOf(v any) string {
	if m, ok := v.(map[string]any); ok {
		if be, ok := m["build_error"].(string); ok && be != "" {
			return be
		}
	}
	return ""
}

// prettyEncode renders v as indented JSON and returns it. On a marshal failure
// it falls back to %v rather than returning an error: this is the terminal
// output path, and showing the operator a Go-syntax dump of the response beats
// showing them nothing.
//
// HTML escaping is off. encoding/json escapes <, > and & by default so its
// output is safe to embed in a <script> block, which is exactly what this is
// not: the destination is a terminal, and the escaping turns the <redacted>
// sentinel -- the one string an operator most needs to recognise on sight --
// into <redacted>.
func prettyEncode(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Sprintf("%v", v)
	}
	// Encode appends a newline; the callers add their own.
	return strings.TrimRight(buf.String(), "\n")
}

// mgmtPrint renders v the way the subcommand asked: pretty JSON by default (a
// curl-able, human-readable response), or a compact single line with -json for
// scripting. Both are JSON; -json only drops the indentation.
func mgmtPrint(jsonOut bool, v any) {
	if jsonOut {
		if b, err := json.Marshal(v); err == nil {
			fmt.Println(string(b))
			return
		}
	}
	fmt.Println(prettyEncode(v))
}

// mgmtFlags parses a subcommand's flags and returns the shared -json flag. Every
// subcommand takes it so an operator can script any response without text
// processing the pretty form.
func mgmtFlags(fs *flag.FlagSet, args []string) (jsonOut bool, err error) {
	fs.BoolVar(&jsonOut, "json", false, "emit compact JSON (for scripting)")
	if err := fs.Parse(args); err != nil {
		return false, err
	}
	return jsonOut, nil
}

// splitPositional pulls the first non-flag argument out of args and returns it
// with the rest, so flags can precede or follow a subcommand's positional name
// (Go's flag package stops at the first positional, which made `-json` after a
// name silently unparsed).
func splitPositional(args []string) (string, []string) {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			rest := make([]string, 0, len(args)-1)
			rest = append(rest, args[:i]...)
			rest = append(rest, args[i+1:]...)
			return a, rest
		}
	}
	return "", args
}

// confirmDelete gates a destructive subcommand (mgmt rm, profile rm) on an
// interactive yes. A pipe or redirection means a script, and a script that got
// this far has already decided -- prompting would hang it -- so non-terminal
// stdin proceeds without asking. At a terminal, only an explicit yes answers
// the prompt. force (the -y flag) skips the question everywhere.
func confirmDelete(what string, force bool) bool {
	if force {
		return true
	}
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return true
	}
	fmt.Fprintf(os.Stderr, "%s? [y/N] ", what)
	var ans string
	if _, err := fmt.Fscanln(os.Stdin, &ans); err != nil {
		return false
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes"
}

func mgmtList(args []string) error {
	fs := flag.NewFlagSet("mgmt ls", flag.ContinueOnError)
	quiet := fs.Bool("q", false, "print only listener names")
	jsonOut, err := mgmtFlags(fs, args)
	if err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: veepin mgmt ls [-json] [-q]")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("GET", "/api/listeners", nil)
	if err != nil {
		return err
	}
	if *quiet {
		return printNames(v)
	}
	mgmtPrint(jsonOut, v)
	return nil
}

// printNames emits just the "name" field of each element in a {"listeners": [...]}
// envelope — the scripting form of `ls`.
func printNames(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("mgmt: unexpected response shape")
	}
	list, ok := m["listeners"].([]any)
	if !ok {
		return fmt.Errorf("mgmt: response has no listeners array")
	}
	for _, e := range list {
		if em, ok := e.(map[string]any); ok {
			if n, ok := em["name"].(string); ok {
				fmt.Println(n)
			}
		}
	}
	return nil
}

func mgmtStatus(args []string) error {
	name, rest := splitPositional(args)
	fs := flag.NewFlagSet("mgmt status", flag.ContinueOnError)
	jsonOut, err := mgmtFlags(fs, rest)
	if err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("usage: veepin mgmt status <name> [-json]")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("GET", "/api/listeners/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	mgmtPrint(jsonOut, v)
	return nil
}

func mgmtProtocols(args []string) error {
	fs := flag.NewFlagSet("mgmt protocols", flag.ContinueOnError)
	jsonOut, err := mgmtFlags(fs, args)
	if err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: veepin mgmt protocols [-json]")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("GET", "/api/protocols", nil)
	if err != nil {
		return err
	}
	mgmtPrint(jsonOut, v)
	return nil
}

func mgmtAdd(args []string) error {
	fs := flag.NewFlagSet("mgmt add", flag.ContinueOnError)
	jsonOut, err := mgmtFlags(fs, args)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("mgmt add: read a listener JSON on stdin (got EOF)")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("POST", "/api/listeners", bytes.NewReader(body))
	if err != nil {
		return err
	}
	mgmtPrint(jsonOut, v)
	return nil
}

func mgmtEdit(args []string) error {
	name, rest := splitPositional(args)
	fs := flag.NewFlagSet("mgmt edit", flag.ContinueOnError)
	jsonOut, err := mgmtFlags(fs, rest)
	if err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("usage: veepin mgmt edit <name> (config JSON on stdin) [-json]")
	}
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("mgmt edit: read a listener JSON on stdin (got EOF)")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("PATCH", "/api/listeners/"+url.PathEscape(name), bytes.NewReader(body))
	if err != nil {
		return err
	}
	// The API answers 202 with build_error when the config was saved but the
	// rebuild failed. The listener is down and the operator has to act; the
	// response still prints (so a -json script sees the envelope) but the CLI
	// must not report a success it cannot stand behind.
	if be := buildErrorOf(v); be != "" {
		mgmtPrint(jsonOut, v)
		return fmt.Errorf("mgmt edit %s: config saved, but the rebuild failed: %s (retry with `veepin mgmt restart %s`)",
			name, be, name)
	}
	mgmtPrint(jsonOut, v)
	return nil
}

func mgmtRestart(args []string) error {
	name, rest := splitPositional(args)
	fs := flag.NewFlagSet("mgmt restart", flag.ContinueOnError)
	jsonOut, err := mgmtFlags(fs, rest)
	if err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("usage: veepin mgmt restart <name> [-json]")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("POST", "/api/listeners/"+url.PathEscape(name)+"/restart", nil)
	if err != nil {
		return err
	}
	mgmtPrint(jsonOut, v)
	return nil
}

func mgmtRm(args []string) error {
	name, rest := splitPositional(args)
	// -y is read positionally rather than registered with the flag set: Go's
	// flag package stops at the first positional, so a -y AFTER the name would
	// otherwise be silently unparsed, and a -y BEFORE it would be rejected as
	// undefined by mgmtFlags. Pull it out of the remainder before parsing.
	yes := false
	filtered := make([]string, 0, len(rest))
	for _, a := range rest {
		// -yes too: see profile.go's confirmDelete caller.
		if a == "-y" || a == "--y" || a == "-yes" || a == "--yes" {
			yes = true
			continue
		}
		filtered = append(filtered, a)
	}
	fs := flag.NewFlagSet("mgmt rm", flag.ContinueOnError)
	jsonOut, err := mgmtFlags(fs, filtered)
	if err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("usage: veepin mgmt rm <name> [-y] [-json]")
	}
	if !confirmDelete("delete listener "+name, yes) {
		return fmt.Errorf("mgmt rm %s: cancelled", name)
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("DELETE", "/api/listeners/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	mgmtPrint(jsonOut, v)
	return nil
}

func mgmtAudit(args []string) error {
	fs := flag.NewFlagSet("mgmt audit", flag.ContinueOnError)
	jsonOut, err := mgmtFlags(fs, args)
	if err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: veepin mgmt audit [-json]")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("GET", "/api/audit", nil)
	if err != nil {
		return err
	}
	mgmtPrint(jsonOut, v)
	return nil
}

// mgmtClientConfig generates a client connection profile for a listener: the
// same POST the panel's "client config" button fires. With -o <dir> it writes
// profile.json and any companion files into the directory; otherwise it prints
// the response.
func mgmtClientConfig(args []string) error {
	name, rest := splitPositional(args)
	fs := flag.NewFlagSet("mgmt client-config", flag.ContinueOnError)
	outDir := fs.String("o", "", "directory to write profile.json and companion files into (default: print)")
	endpoint := fs.String("endpoint", "", "server address clients dial, host[:port] (required for most protocols)")
	var sets setList
	fs.Var(&sets, "set", "override a client option, key=value (repeatable)")
	showSecrets := fs.Bool("secrets", false, "print secret values instead of <redacted> (stdout only; -o always writes them)")
	jsonOut, err := mgmtFlags(fs, rest)
	if err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("usage: veepin mgmt client-config <name> [-endpoint host[:port]] [-set k=v] [-o dir] [-json]")
	}
	// No protocol name: only the server knows what this listener runs, and it
	// validates the override keys against that protocol's client OptSpecs. An
	// empty protocol skips the local key check and keeps the key=value one.
	overrides, err := applyOverrides("mgmt client-config", "", nil, sets)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"endpoint": *endpoint, "overrides": overrides})
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("POST", "/api/listeners/"+url.PathEscape(name)+"/client-config", bytes.NewReader(body))
	if err != nil {
		return err
	}
	if *outDir != "" {
		return writeClientConfigBundle(*outDir, v)
	}
	// Without -o the profile goes to stdout, and it carries the client's real
	// private key and every secret the listener supplied -- a generated profile
	// is complete by construction. `veepin profile show` redacts by default and
	// takes -secrets to opt in; this printed everything and took nothing, which
	// is the opposite default for strictly more sensitive output. It lands in
	// scrollback and, piped, in whatever consumed it.
	if !*showSecrets {
		v = redactClientConfigResponse(v)
	}
	mgmtPrint(jsonOut, v)
	return nil
}

// redactClientConfigResponse replaces the secret option values in a
// client-config response with the same sentinel the API uses on reads.
//
// Best-effort over an any-shaped decode: a response whose shape it does not
// recognise is returned unchanged rather than half-redacted, because a caller
// who asked for the profile and got a mangled one is worse off than one who
// got what they asked for. The complete profile is always available with -o
// (mode 0600) or -secrets.
func redactClientConfigResponse(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	prof, ok := m["profile"].(map[string]any)
	if !ok {
		return v
	}
	protocol, _ := prof["protocol"].(string)
	specs, ok := client.ClientOptsFor(protocol)
	if !ok {
		return v
	}
	opts, ok := prof["options"].(map[string]any)
	if !ok {
		return v
	}
	for _, sp := range specs {
		if !sp.Secret {
			continue
		}
		if cur, present := opts[sp.Key]; present && cur != "" {
			opts[sp.Key] = client.Redacted
		}
	}
	// The companion files are key material too -- a bundled client.key is the
	// private half in full.
	if files, ok := m["files"].([]any); ok {
		for _, f := range files {
			fm, ok := f.(map[string]any)
			if !ok {
				continue
			}
			fm["content"] = client.Redacted
		}
	}
	m["note"] = "secrets redacted; re-run with -o <dir> to write the real profile, or -secrets to print it"
	return m
}

// writeClientConfigBundle writes the generated profile.json and its companion
// files into dir. Companion names come from the server as base names, and are
// re-based defensively here before they become paths.
//
// The directory is filled all-or-nothing: every file is staged into a sibling
// temp directory and moved in by rename, and a failure anywhere after the first
// write takes the already-installed files back out. Writing profile.json first
// and then the companions in place -- the earlier shape -- left a half-bundle
// (profile without CA) whenever a companion write failed, which an operator
// then handed to `veepin connect` and got a profile that pointed at nothing.
func writeClientConfigBundle(dir string, v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("mgmt: unexpected response shape")
	}
	prof, ok := m["profile"].(map[string]any)
	if !ok {
		return fmt.Errorf("mgmt: response has no profile")
	}
	// Collect everything into memory before touching the directory, so no
	// marshalling or shape failure can leave files behind either.
	type bundleFile struct{ name, content string }
	var files []bundleFile
	if list, ok := m["files"].([]any); ok {
		for _, f := range list {
			fm, ok := f.(map[string]any)
			if !ok {
				continue
			}
			fname, _ := fm["name"].(string)
			content, _ := fm["content"].(string)
			if fname == "" {
				continue
			}
			files = append(files, bundleFile{name: filepath.Base(fname), content: content})
		}
	}
	profBody, err := json.MarshalIndent(prof, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(filepath.Dir(dir), ".client-config-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	// installed records what to undo, and how. A name we created is removed on
	// rollback; a name we REPLACED is put back.
	//
	// Removing either was wrong: re-running `client-config -o ./bundle` over an
	// existing bundle overwrote the operator's previous ca.crt, and a failure on
	// the next companion then deleted it -- so the "all-or-nothing" promise
	// restored a state that had never existed, with their file gone.
	type undo struct {
		name   string
		backup string // "" when the name did not exist before
	}
	var installed []undo
	rollback := func() {
		for i := len(installed) - 1; i >= 0; i-- {
			u := installed[i]
			target := filepath.Join(dir, u.name)
			if u.backup == "" {
				_ = os.Remove(target)
				continue
			}
			_ = os.Rename(u.backup, target)
		}
	}
	install := func(name string, body []byte) error {
		staged := filepath.Join(staging, name)
		if err := os.WriteFile(staged, body, 0o600); err != nil {
			return err
		}
		target := filepath.Join(dir, name)
		u := undo{name: name}
		if fi, err := os.Stat(target); err == nil {
			// Only a regular file is ours to replace. A directory (or a socket,
			// or a device) under one of our names is the operator having
			// something else there entirely, and moving it aside to drop a PEM
			// in its place is not a decision this command should make.
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("mgmt client-config: %s exists and is not a regular file", target)
			}
			// Move the existing file aside into the staging dir, which is on the
			// same filesystem as dir (os.MkdirTemp under filepath.Dir(dir)), so
			// the rename is atomic and cannot half-copy.
			u.backup = filepath.Join(staging, ".backup-"+name)
			if err := os.Rename(target, u.backup); err != nil {
				return err
			}
		}
		if err := os.Rename(staged, target); err != nil {
			return err
		}
		installed = append(installed, u)
		return nil
	}
	if err := install("profile.json", profBody); err != nil {
		rollback()
		return err
	}
	for _, f := range files {
		if err := install(f.name, []byte(f.content)); err != nil {
			rollback()
			return fmt.Errorf("mgmt: writing %s: %w", f.name, err)
		}
	}
	fmt.Printf("wrote %s (and any companion files)\n", filepath.Join(dir, "profile.json"))
	return nil
}
