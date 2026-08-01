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
)

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
  rm <name>                   stop and delete <name> [-json]
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
	return &mgmtClient{base: strings.TrimRight(base, "/"), token: tok}, nil
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
	resp, err := http.DefaultClient.Do(req)
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

// prettyEncode pretty-prints v to the writer.
func prettyEncode(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
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
	fs := flag.NewFlagSet("mgmt rm", flag.ContinueOnError)
	jsonOut, err := mgmtFlags(fs, rest)
	if err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("usage: veepin mgmt rm <name> [-json]")
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
	jsonOut, err := mgmtFlags(fs, rest)
	if err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("usage: veepin mgmt client-config <name> [-endpoint host[:port]] [-set k=v] [-o dir] [-json]")
	}
	overrides, err := applyOverrides(nil, sets)
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
	mgmtPrint(jsonOut, v)
	return nil
}

// writeClientConfigBundle writes the generated profile.json and its companion
// files into dir. Companion names come from the server as base names, and are
// re-based defensively here before they become paths.
func writeClientConfigBundle(dir string, v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("mgmt: unexpected response shape")
	}
	prof, ok := m["profile"].(map[string]any)
	if !ok {
		return fmt.Errorf("mgmt: response has no profile")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(prof, "", "  ")
	if err != nil {
		return err
	}
	profilePath := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(profilePath, body, 0o600); err != nil {
		return err
	}
	if files, ok := m["files"].([]any); ok {
		for _, f := range files {
			fm, ok := f.(map[string]any)
			if !ok {
				continue
			}
			fname, _ := fm["name"].(string)
			content, _ := fm["content"].(string)
			if fname == "" {
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, filepath.Base(fname)), []byte(content), 0o600); err != nil {
				return err
			}
		}
	}
	fmt.Printf("wrote %s (and any companion files)\n", profilePath)
	return nil
}
