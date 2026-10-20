// Package ui is the supervisor's server-rendered web panel. It is plain
// html/template and inlined vanilla JavaScript over an embed.FS; no npm, no
// bundle step, no third-party dependency. The browser talks to the same
// /api/* endpoints the CLI does, authenticating each fetch with the bearer
// token.
//
// The pages carry no token. They are served without authentication, and a
// loopback TCP port answers every user on the host, not only the one who owns
// the token file -- so a page that embedded the token handed root's
// credential to any local account that asked for it. The operator brings the
// token to the browser instead: in the URL fragment (#token=..., which a
// browser never sends to the server), or pasted into the prompt the panel
// shows when it has none. panel.js keeps it in sessionStorage for the tab.
// See doc/security.md.
package ui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/xen0bit/veepin/internal/vlog"
)

//go:embed templates/*
var templatesFS embed.FS

// Handler is the http.Handler that serves the panel pages.
type Handler struct {
	tmpl *template.Template
	log  *vlog.Logger
}

// NewHandler parses the embedded templates once. Returns an error if the embedded templates fail to parse, which a build
// embeds once and which should therefore never happen.
//
// logger is the supervisor's logger -- the same one feeding mgmt.LogRing, so a
// render failure shows up in the panel's own /api/logs tail. It was an
// fmt.Printf to stdout, which meant the panel's one failure mode was the one
// thing the panel could not show you. A nil logger discards.
func NewHandler(logger *vlog.Logger) (*Handler, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("ui: parsing embedded templates: %w", err)
	}
	if logger == nil {
		logger = vlog.Discard()
	}
	return &Handler{tmpl: tmpl, log: logger}, nil
}

// pageData is the render context. It holds nothing secret, and must not: the
// pages are served to anyone who can reach the port.
type pageData struct {
	InitialJS string
}

// ServeHTTP routes the dashboard, the add/edit form pages (for listeners and
// profiles), and the shared panel.js asset. /api/* is owned by api.go; this
// handler only sees requests that did not match the api. Form paths:
//
//	/listeners/new, /listeners/{name}    listener add / edit
//	/profiles/new, /profiles/{name}      profile add / edit
//
// Anything else falls through to a plain 404 so the management API's own 404
// for /api/missing is unaffected.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch p := r.URL.Path; {
	case p == "/" || p == "":
		h.render(w, "dashboard.html")
	case p == "/assets/panel.js":
		h.serveAsset(w, r, "templates/panel.js", "text/javascript; charset=utf-8")
	case p == "/listeners/new":
		h.render(w, "form.html", pageData{InitialJS: "new"})
	case p == "/profiles/new":
		h.render(w, "form.html", pageData{InitialJS: "new-profile"})
	case strings.HasPrefix(p, "/listeners/"):
		name := p[len("/listeners/"):]
		if name == "" || strings.Contains(name, "/") {
			http.NotFound(w, r)
			return
		}
		h.render(w, "form.html", pageData{InitialJS: "edit:" + name})
	case strings.HasPrefix(p, "/profiles/"):
		name := p[len("/profiles/"):]
		if name == "" || strings.Contains(name, "/") {
			http.NotFound(w, r)
			return
		}
		h.render(w, "form.html", pageData{InitialJS: "edit-profile:" + name})
	default:
		http.NotFound(w, r)
	}
}

// serveAsset writes one file from the embedded tree with the given content type.
// nosniff because the declared type is the correct one and a browser that
// second-guesses it on a page holding the bearer token in its script state is
// not a trade worth making.
func (h *Handler) serveAsset(w http.ResponseWriter, r *http.Request, name, ctype string) {
	body, err := templatesFS.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}

// render executes a template into the response.
//
// It renders into a buffer first, so a failure can still become a 500 with a
// body. Executing straight into the ResponseWriter meant a template that failed
// halfway had already sent 200 and a truncated page, and the code that noticed
// could do nothing about it -- the comment there promised "write a 500 in the
// body" above a line that wrote nothing to the body at all.
func (h *Handler) render(w http.ResponseWriter, name string, data ...pageData) {
	var ctx pageData
	if len(data) > 0 {
		ctx = data[0]
	}

	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, name, ctx); err != nil {
		h.log.Warnf("ui: template %s failed: %v", name, err)
		http.Error(w, "panel template failed to render; see the supervisor log",
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}
