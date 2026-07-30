// Package ui is the supervisor's server-rendered web panel. It is plain
// html/template and inlined vanilla JavaScript over an embed.FS; no npm, no
// bundle step, no third-party dependency. The browser talks to the same
// /api/* endpoints the CLI does, authenticating each fetch with the bearer
// token this package embeds into the dashboard as a JS global.
//
// The panel is served at the root of the management HTTP server; /api/* is
// reserved for the data plane. The panel itself is reachable without a token
// because the management server binds to localhost by default -- the bearer
// token is then the per-request boundary, sent from the browser on each fetch
// against /api/*. Operators who bind to a routable interface are expected to
// stand up mTLS or SSH-tunnel in front of the panel: that posture is the
// subject of doc/security.md.
package ui

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Handler is the http.Handler that serves the panel pages.
type Handler struct {
	token string
	tmpl  *template.Template
}

// NewHandler parses the embedded templates once and stores the bearer token
// for injection into the dashboard; the browser uses it for its /api fetches.
// Returns an error if the embedded templates fail to parse, which a build
// embeds once and which should therefore never happen.
func NewHandler(token string) (*Handler, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("ui: parsing embedded templates: %w", err)
	}
	return &Handler{token: token, tmpl: tmpl}, nil
}

// pageData is the dashboard render context. The Token field is the only
// secret; everything else is decorative.
type pageData struct {
	Token     string
	InitialJS string
}

// ServeHTTP routes the dashboard and per-listener form pages. The router is
// minimal by design, since /api/* is owned by api.go; this handler only sees
// requests that did not match the api (the manager's outer mux runs /api/*
// first). Three paths: "/" renders the dashboard; "/listeners/new" the add
// form; "/listeners/{name}" the edit form. Anything else falls through to a
// plain 404 so the management API's own 404 for /api/missing is unaffected.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch p := r.URL.Path; {
	case p == "/" || p == "":
		h.render(w, "dashboard.html")
	case p == "/listeners/new":
		h.render(w, "form.html", pageData{Token: h.token, InitialJS: "new"})
	case strings.HasPrefix(p, "/listeners/"):
		name := p[len("/listeners/"):]
		if name == "" || strings.Contains(name, "/") {
			http.NotFound(w, r)
			return
		}
		h.render(w, "form.html", pageData{Token: h.token, InitialJS: "edit:" + name})
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) render(w http.ResponseWriter, name string, data ...pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var ctx pageData
	if len(data) > 0 {
		ctx = data[0]
	}
	// The dashboard template reads only .Token; the form template reads
	// .Token and .InitialJS. A zero InitialJS defaults to "" which the form
	// JS treats as "edit with no name" -- but its only call with no InitialJS
	// is the dashboard path, which uses a different template, so the empty
	// value never reaches the form.
	ctx.Token = h.token
	if err := h.tmpl.ExecuteTemplate(w, name, ctx); err != nil {
		// ExecuteTemplate writes directly to w; once we have started sending
		// bytes, write a 500 in the body. Log via fmt since this package has
		// no logger field and the panel never speaks to an operator beyond the
		// browser.
		fmt.Printf("ui: template %s failed: %v\n", name, err)
	}
}
