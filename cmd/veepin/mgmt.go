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
	"strings"
)

// runMgmt dispatches to a subcommand. With no subcommand it prints usage.
func runMgmt(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(`usage: veepin mgmt <subcommand>
subcommands:
  ls                          list running listeners
  status <name>               status of one listener
  protocols                   protocols the supervisor can run
  add                         create a listener from a JSON config on stdin
  edit <name>                 PATCH <name> from a partial JSON config on stdin
  restart <name>              rebuild <name> from its on-disk config
  rm <name>                   stop and delete <name>
environment:
  VEEPIN_MGMT_URL    base URL (default http://127.0.0.1:8443)
  VEEPIN_MGMT_TOKEN  bearer token (required)`)
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
		return nil, fmt.Errorf("mgmt: VEEPIN_MGMT_TOKEN is required")
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

func mgmtList(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: veepin mgmt ls (takes no arguments)")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("GET", "/api/listeners", nil)
	if err != nil {
		return err
	}
	fmt.Println(prettyEncode(v))
	return nil
}

func mgmtStatus(args []string) error {
	fs := flag.NewFlagSet("mgmt status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: veepin mgmt status <name>")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("GET", "/api/listeners/"+url.PathEscape(fs.Arg(0)), nil)
	if err != nil {
		return err
	}
	fmt.Println(prettyEncode(v))
	return nil
}

func mgmtProtocols(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: veepin mgmt protocols (takes no arguments)")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("GET", "/api/protocols", nil)
	if err != nil {
		return err
	}
	fmt.Println(prettyEncode(v))
	return nil
}

func mgmtAdd(args []string) error {
	fs := flag.NewFlagSet("mgmt add", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
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
	fmt.Println(prettyEncode(v))
	return nil
}

func mgmtEdit(args []string) error {
	fs := flag.NewFlagSet("mgmt edit", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: veepin mgmt edit <name> (config JSON on stdin)")
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
	v, err := c.do("PATCH", "/api/listeners/"+url.PathEscape(fs.Arg(0)), bytes.NewReader(body))
	if err != nil {
		return err
	}
	fmt.Println(prettyEncode(v))
	return nil
}

func mgmtRestart(args []string) error {
	fs := flag.NewFlagSet("mgmt restart", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: veepin mgmt restart <name>")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("POST", "/api/listeners/"+url.PathEscape(fs.Arg(0))+"/restart", nil)
	if err != nil {
		return err
	}
	fmt.Println(prettyEncode(v))
	return nil
}

func mgmtRm(args []string) error {
	fs := flag.NewFlagSet("mgmt rm", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: veepin mgmt rm <name>")
	}
	c, err := newMgmtClient()
	if err != nil {
		return err
	}
	v, err := c.do("DELETE", "/api/listeners/"+url.PathEscape(fs.Arg(0)), nil)
	if err != nil {
		return err
	}
	fmt.Println(prettyEncode(v))
	return nil
}
