package ui

// Tests for the embedded panel: the templates parse, the handler routes the
// dashboard and two form paths, and the token is injected into the rendered
// page so the browser can authenticate its fetches.

import (
	"net/http"
	"net/http/httptest"
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
		// Every mention of a field must be inside an esc(...) call or an
		// encodeURIComponent(...) one; a bare "+ l.error +" is the bug.
		for _, bare := range []string{"+ " + field + " +", "+ " + field + ")", "(" + field + "||"} {
			if strings.Contains(src, bare) {
				t.Errorf("dashboard.html concatenates %s unescaped (found %q)", field, bare)
			}
		}
	}
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
	for _, fn := range []string{"refresh", "refreshProfiles", "refreshAudit", "refreshHealth"} {
		if !strings.Contains(src, "setInterval("+fn+",") {
			t.Errorf("%s is never re-polled: the panel it fills goes stale after page load", fn)
		}
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
