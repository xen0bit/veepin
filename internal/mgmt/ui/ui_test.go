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
