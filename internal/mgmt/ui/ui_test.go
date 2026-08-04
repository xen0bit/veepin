package ui

// Tests for the embedded panel: the templates parse, the handler routes the
// dashboard and two form paths, and the token is injected into the rendered
// page so the browser can authenticate its fetches.

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestNewHandlerParsesTemplates(t *testing.T) {
	h, err := NewHandler("test-token")
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if h == nil || h.tmpl == nil {
		t.Fatalf("nil handler or templates")
	}
}

func TestDashboardRendersToken(t *testing.T) {
	h, _ := NewHandler("test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "test-token") {
		t.Errorf("dashboard page does not include the token: %s", body[:min(len(body), 200)])
	}
	if !strings.Contains(body, "veepin supervisor") {
		t.Errorf("dashboard page does not include its title")
	}
}

func TestNewListenerFormRenders(t *testing.T) {
	h, _ := NewHandler("test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/listeners/new", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "new listener") {
		t.Errorf("form page does not include its 'new listener'heading")
	}
}

func TestEditListenerFormRendersName(t *testing.T) {
	h, _ := NewHandler("test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/listeners/site-a", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "site-a") {
		t.Errorf("form page does not include the listener name site-a")
	}
}

// TestDashboardEscapesEveryFieldItRenders: the dashboard builds its rows by
// concatenating API values into innerHTML, and one of those values -- `error` --
// is arbitrary text from a protocol's failure path, which routinely quotes the
// option values that caused it. The page holds the bearer token in its DOM, so
// markup landing in a row is a token-exfiltration path.
//
// The check is on the source rather than on rendered output because the rows are
// built client-side; what a Go test can pin is that every field goes through
// esc() and none is concatenated raw. esc lives in the shared panel.js.
func TestDashboardEscapesEveryFieldItRenders(t *testing.T) {
	panel, err := templatesFS.ReadFile("templates/panel.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(panel), "function esc(") {
		t.Fatal("panel.js has no esc() helper")
	}
	body, err := templatesFS.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, field := range []string{"l.error", "l.protocol", "l.tun", "l.gateway", "l.network", "l.name"} {
		// Presence first. A field the template stopped rendering passes the
		// escaping check below vacuously, which is how the error column was
		// dropped from the fleet table while this test still claimed to guard
		// it -- and a listener in state "error" then showed its error nowhere.
		if !strings.Contains(src, field) {
			t.Errorf("dashboard.html no longer renders %s; this test was guarding a field that is gone", field)
			continue
		}
		// Every mention of a field must be lexically inside an esc(...) or
		// encodeURIComponent(...) call.
		//
		// This used to reject three literal spellings -- "+ l.error +",
		// "+ l.error)" and "(l.error||" -- which is a blacklist, and a
		// blacklist of three entries against an infinite set. Writing
		// '</td><td>'+l.error+'</td>' with no spaces passed. So did a template
		// literal, and so did reading the field into a local first. The test's
		// own comment says it guards a token-exfiltration path.
		for _, at := range indexesOf(src, field) {
			// Only interpolation into a string matters. Using the value as an
			// object key (expanded[l.name]) or passing it to a function
			// (loadDetail(l.name)) puts nothing into markup.
			if !interpolatedIntoAString(src, at, len(field)) {
				continue
			}
			if !wrappedInCall(src, at, "esc", "encodeURIComponent") {
				t.Errorf("dashboard.html interpolates %s without escaping it, at:\n\t%s",
					field, lineAround(src, at))
			}
		}
	}
}

// indexesOf returns every offset at which needle occurs as a whole identifier
// reference -- not as a prefix of a longer one, so "l.name" does not match
// inside "l.namespace".
func indexesOf(src, needle string) []int {
	var out []int
	for i := 0; ; {
		j := strings.Index(src[i:], needle)
		if j < 0 {
			return out
		}
		at := i + j
		end := at + len(needle)
		if end >= len(src) || !isIdentRune(src[end]) {
			out = append(out, at)
		}
		i = end
	}
}

// interpolatedIntoAString reports whether the occurrence at `at` is being
// concatenated with, or substituted into, a string: `'x' + f`, `f + 'x'`, or
// `${f}`. Those are the ways a value reaches innerHTML; a subscript or a call
// argument is not one of them.
func interpolatedIntoAString(src string, at, width int) bool {
	before := at - 1
	for before >= 0 && (src[before] == ' ' || src[before] == '\t') {
		before--
	}
	if before >= 0 && src[before] == '+' {
		return true
	}
	if before >= 1 && src[before] == '{' && src[before-1] == '$' {
		return true
	}
	after := at + width
	for after < len(src) && (src[after] == ' ' || src[after] == '\t') {
		after++
	}
	return after < len(src) && src[after] == '+'
}

func isIdentRune(b byte) bool {
	return b == '_' || b == '$' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// wrappedInCall reports whether the byte at `at` sits inside the argument list
// of a call to one of the named functions.
//
// It walks backwards balancing parentheses: each unmatched '(' encountered is an
// enclosing call, and the identifier immediately before it is that call's name.
// Crude next to a JS parser, and enough to tell esc(x) from a bare
// concatenation, which is the whole question.
func wrappedInCall(src string, at int, names ...string) bool {
	depth := 0
	for i := at - 1; i >= 0; i-- {
		switch src[i] {
		case ')':
			depth++
		case '(':
			if depth > 0 {
				depth--
				continue
			}
			// Unmatched: read the identifier that precedes it.
			end := i
			for end > 0 && src[end-1] == ' ' {
				end--
			}
			start := end
			for start > 0 && isIdentRune(src[start-1]) {
				start--
			}
			if slices.Contains(names, src[start:end]) {
				return true
			}
			// An enclosing call that is not one of ours: keep walking out, so
			// esc(String(l.error)) still counts as escaped.
		case '\n':
			// A newline with no unmatched '(' open means the statement began
			// on this line and nothing wraps the field.
			if depth == 0 {
				return false
			}
		}
	}
	return false
}

// lineAround returns the source line containing offset, for an error message
// that points at the code rather than describing it.
func lineAround(src string, at int) string {
	start := strings.LastIndexByte(src[:at], '\n') + 1
	end := strings.IndexByte(src[at:], '\n')
	if end < 0 {
		end = len(src)
	} else {
		end += at
	}
	return strings.TrimSpace(src[start:end])
}

// TestFormEscapesTheProtocolOptionsItBuilds extends the same discipline to
// form.html, which was building its <option> list by raw concatenation. The
// values come from the registry so it was not reachable, but "escape
// everything" is only a rule if there is nothing to remember an exception for.
func TestFormEscapesTheProtocolOptionsItBuilds(t *testing.T) {
	body, err := templatesFS.ReadFile("templates/form.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, bare := range []string{"+ p.name +", "+ p.name)", "+ body.name +"} {
		if strings.Contains(src, bare) {
			t.Errorf("form.html concatenates a value unescaped (found %q)", bare)
		}
	}
}

// TestFormRoutesAListenerNamedProfileAsAListener: listener names match
// ^[a-z0-9][a-z0-9-]{0,31}$, so "profiles" and "vpn-profile" are legal. A
// substring test for "profile" on the whole hint pointed the entire form --
// load, save, delete -- at /api/profiles for those names.
func TestFormRoutesAListenerNamedProfileAsAListener(t *testing.T) {
	h, _ := NewHandler("test-token")
	for _, name := range []string{"profiles", "vpn-profile", "profile-a"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/listeners/"+name, nil))
		if rec.Code != 200 {
			t.Fatalf("GET /listeners/%s = %d, want 200", name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"edit:`+name+`"`) {
			t.Errorf("GET /listeners/%s does not carry the listener edit hint", name)
		}
	}
	// The hint grammar the page matches on, pinned here so a change to either
	// side has to change both.
	body, _ := templatesFS.ReadFile("templates/form.html")
	if strings.Contains(string(body), `INITIAL.indexOf("profile")`) {
		t.Error("form.html decides its kind by substring again; match the hint grammar instead")
	}
}

// TestProfileRoutesCarryTheProfileEditHint pins the profile add/edit routes that the
// dashboard's profile table links to.
func TestProfileRoutesCarryTheProfileEditHint(t *testing.T) {
	h, _ := NewHandler("test-token")
	for _, path := range []string{"/profiles/new", "/profiles/home"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
		}
		want := "new-profile"
		if path == "/profiles/home" {
			want = "edit-profile"
		}
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("GET %s does not carry its initial kind", path)
		}
	}
}

// TestFormHidesRestartAndDeleteOnNewPages: restart and delete act on an
// existing entity, so on the "new" pages both buttons would fire at a name that
// has not been saved yet and 404. configureBody must hide them there; the
// listener/profiles split alone is not enough (the listener "new" page used to
// show both buttons).
func TestFormHidesRestartAndDeleteOnNewPages(t *testing.T) {
	body, err := templatesFS.ReadFile("templates/form.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if !strings.Contains(src, `document.getElementById("apply").style.display = (isProfile() || isNew) ? "none" : "";`) {
		t.Errorf("form.html does not hide the restart button on new pages")
	}
	if !strings.Contains(src, `document.getElementById("delete").style.display = isNew ? "none" : "";`) {
		t.Errorf("form.html does not hide the delete button on new pages")
	}
}

// TestDashboardRestartConfirms: a restart drops every connected client (the
// listener cold-rebuilds), so the dashboard must confirm before firing it, the
// way delete already does.
func TestDashboardRestartConfirms(t *testing.T) {
	body, err := templatesFS.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `confirm("restart listener `) {
		t.Errorf("dashboard.html restart does not confirm")
	}
}

// TestPanelJSIsServedAsJavaScriptAndNotSniffable pins the shared-asset route both templates load.
func TestPanelJSIsServedAsJavaScriptAndNotSniffable(t *testing.T) {
	h, _ := NewHandler("test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/panel.js", nil))
	if rec.Code != 200 {
		t.Fatalf("GET /assets/panel.js = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("Content-Type = %q, want text/javascript", ct)
	}
	if !strings.Contains(rec.Body.String(), "function esc(") {
		t.Errorf("/assets/panel.js does not carry the esc helper")
	}
}

// TestDashboardRendersHealthHeader: the dashboard shows supervisor health and
// uptime fetched from /api/health, so a dead management plane is visible in the
// page rather than silently freezing the listener table.
func TestDashboardRendersHealthHeader(t *testing.T) {
	h, _ := NewHandler("test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="health"`) {
		t.Errorf("dashboard has no health header element")
	}
}

// TestDashboardRepollsEveryPanelIncludingHealth: health was fetched once at page
// load while the three tables each had an interval, so the uptime froze and a
// management plane that had died looked healthy in the one element added to show
// exactly that.
func TestDashboardRepollsEveryPanelIncludingHealth(t *testing.T) {
	body, err := templatesFS.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, fn := range []string{"refresh", "refreshProfiles", "refreshAudit", "refreshHealth", "refreshLog"} {
		if !strings.Contains(src, "setInterval("+fn+",") {
			t.Errorf("%s is never re-polled: the panel it fills goes stale after page load", fn)
		}
	}
}

// TestDashboardRendersALogBlock: the dashboard must offer the supervisor's log
// tail and refresh it on the poll cycle, so "why is this listener in error
// state" is answerable from the browser rather than from the supervisor's
// stdout. The log lines are arbitrary text, so the rendering must escape them.
func TestDashboardRendersALogBlock(t *testing.T) {
	body, err := templatesFS.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if !strings.Contains(src, `id="log"`) {
		t.Errorf("dashboard.html has no log block")
	}
	if !strings.Contains(src, "/api/logs?n=200") {
		t.Errorf("dashboard.html does not fetch the log tail")
	}
	if !strings.Contains(src, "esc(l.line)") {
		t.Errorf("log rendering does not escape the line (arbitrary log text must not inject markup)")
	}
}

// TestFormSurfacesErrorsInABanner: every API failure must land in a visible
// banner. The check is on the source because the behaviour is client-side; it
// pins the two mechanisms that would otherwise silently swallow a rejection:
// an error banner element on the page, and a save handler that surfaces a 202
// (which carries a saved-but-rebuild-failed outcome) instead of redirecting.
func TestFormSurfacesErrorsInABanner(t *testing.T) {
	body, err := templatesFS.ReadFile("templates/form.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if !strings.Contains(src, `id="banner"`) {
		t.Errorf("form.html has no error banner element")
	}
	if !strings.Contains(src, "showBanner(") {
		t.Errorf("form.html does not use the shared showBanner helper")
	}
	// The save handler's redirect is a setTimeout (delayed, and only after any
	// generated key material has been shown); an immediate "if (status < 300)
	// window.location" belongs to the delete handler only. The 202 branch must
	// exist and must return before any redirect.
	if !strings.Contains(src, "status === 202 && body && body.build_error") {
		t.Errorf("form.html does not surface the 202 'saved but rebuild failed' outcome")
	}
}

// TestApiHelperParsesPlainTextBodies: the API answers some errors with plain
// text (http.Error) and some with JSON. The shared fetch helper must read the
// body as text and fall back to JSON, or a rejected request rejects the promise
// and the page shows nothing.
func TestApiHelperParsesPlainTextBodies(t *testing.T) {
	body, err := templatesFS.ReadFile("templates/panel.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if !strings.Contains(src, "r.text()") {
		t.Errorf("panel.js: api() does not read the body as text, so a plain-text error rejects the promise")
	}
	if !strings.Contains(src, "try { body = JSON.parse(t); } catch") {
		t.Errorf("panel.js: api() does not fall back from JSON, so a JSON body renders as a quoted string")
	}
}

// TestDashboardOffersClientConfigGeneration pins the panel's client-config
// affordance: the row action exists, and it escapes every value it renders.
func TestDashboardOffersClientConfigGeneration(t *testing.T) {
	body, err := templatesFS.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if !strings.Contains(src, `data-clientcfg`) {
		t.Errorf("dashboard has no client-config action")
	}
	if !strings.Contains(src, "/client-config") {
		t.Errorf("dashboard does not POST to the client-config endpoint")
	}
}

// TestDashboardClientConfigDialogCarriesOverrides: the client-config dialog
// must collect option overrides, not just the endpoint. Protocols whose client
// identity is not derivable from the listener (nebula's per-host cert/key,
// ikev2's identity) are ungeneratable from the browser otherwise. The prompt
// API cannot carry a map, which is why the dialog replaced it.
func TestDashboardClientConfigDialogCarriesOverrides(t *testing.T) {
	body, err := templatesFS.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if !strings.Contains(src, "cc-overrides") {
		t.Errorf("dashboard has no overrides textarea in the client-config dialog")
	}
	if !strings.Contains(src, "parseOverrides(") {
		t.Errorf("dashboard does not parse override lines")
	}
	if strings.Contains(src, `window.prompt("Server address`) {
		t.Errorf("client-config still uses window.prompt, which cannot carry overrides")
	}
}

// TestDashboardOffersPeerRemoval: a WireGuard-family listener's peer rows must
// offer removal — the escape hatch for a stranded peer nobody holds the key
// for. The button only renders for the WireGuard family; other protocols get
// no dead button.
func TestDashboardOffersPeerRemoval(t *testing.T) {
	body, err := templatesFS.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if !strings.Contains(src, `data-peer-del`) {
		t.Errorf("dashboard has no peer-removal action")
	}
	if !strings.Contains(src, `"/peers?key=" + encodeURIComponent(key)`) {
		t.Errorf("peer removal does not send the public key as a query value")
	}
	if !strings.Contains(src, `wg = protocol === "wireguard" || protocol === "amneziawg"`) {
		t.Errorf("peer removal is not gated on the WireGuard family")
	}
}

// TestUnknownPathReturns404 checks that paths the panel does not own are not
// silently swallowed.
func TestUnknownPathReturns404(t *testing.T) {
	h, _ := NewHandler("test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// TestDetailLoadIsCalledWithTheName: refresh() drives loadDetail through
// Array.prototype.forEach, which passes the ELEMENT to the callback, so a bare
// `forEach(loadDetail)` hands loadDetail a listener OBJECT whose
// encodeURIComponent is the literal "[object Object]" — which matches no
// data-detail cell and leaves every expanded row stuck on "loading…". The
// callback must pick out the listener's name. The browser suite caught this;
// this guard keeps the source shape from regressing it.
func TestDetailLoadIsCalledWithTheName(t *testing.T) {
	body, err := templatesFS.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), ".forEach(loadDetail)") {
		t.Error("dashboard.html calls loadDetail with the listener object; " +
			"encodeURIComponent(obj) matches no data-detail cell and the detail view never renders")
	}
}
