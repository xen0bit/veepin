package livingreadme

import (
	"strings"
	"testing"
)

func TestReplaceRegion(t *testing.T) {
	doc := []byte("intro\n" +
		startMarker("interop") + "\n" +
		"OLD CONTENT\n" +
		endMarker("interop") + "\n" +
		"outro\n")

	out, err := ReplaceRegion(doc, "interop", "NEW\nTABLE")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "NEW\nTABLE") {
		t.Errorf("new body missing:\n%s", s)
	}
	if strings.Contains(s, "OLD CONTENT") {
		t.Errorf("old body survived:\n%s", s)
	}
	// The prose outside the markers is untouched.
	if !strings.HasPrefix(s, "intro\n") || !strings.HasSuffix(s, "outro\n") {
		t.Errorf("surrounding prose changed:\n%s", s)
	}
	// The markers survive.
	if !strings.Contains(s, startMarker("interop")) || !strings.Contains(s, endMarker("interop")) {
		t.Errorf("markers lost:\n%s", s)
	}
}

func TestReplaceRegionIdempotent(t *testing.T) {
	doc := []byte(startMarker("benchmark") + "\nx\n" + endMarker("benchmark") + "\n")
	once, err := ReplaceRegion(doc, "benchmark", "BODY")
	if err != nil {
		t.Fatal(err)
	}
	twice, err := ReplaceRegion(once, "benchmark", "BODY")
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Errorf("not idempotent:\nonce:  %q\ntwice: %q", once, twice)
	}
}

func TestReplaceRegionBodyFraming(t *testing.T) {
	doc := []byte(startMarker("interop") + "\n" + endMarker("interop") + "\n")
	// A body with or without surrounding newlines must produce the same result.
	a, _ := ReplaceRegion(doc, "interop", "T")
	b, _ := ReplaceRegion(doc, "interop", "\n\nT\n\n")
	if string(a) != string(b) {
		t.Errorf("body framing not normalised:\n%q\n%q", a, b)
	}
	want := startMarker("interop") + "\nT\n" + endMarker("interop") + "\n"
	if string(a) != want {
		t.Errorf("got %q, want %q", a, want)
	}
}

func TestReplaceRegionErrors(t *testing.T) {
	cases := map[string][]byte{
		"missing start": []byte(endMarker("interop") + "\n"),
		"missing end":   []byte(startMarker("interop") + "\n"),
		"out of order":  []byte(endMarker("interop") + "\n" + startMarker("interop") + "\n"),
		"dup start":     []byte(startMarker("interop") + startMarker("interop") + endMarker("interop")),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReplaceRegion(doc, "interop", "x"); err == nil {
				t.Errorf("expected an error for %q", name)
			}
		})
	}
}

func TestHasRegion(t *testing.T) {
	doc := []byte(startMarker("benchmark") + "\n" + endMarker("benchmark"))
	if !HasRegion(doc, "benchmark") {
		t.Error("benchmark region should be present")
	}
	if HasRegion(doc, "interop") {
		t.Error("interop region should be absent")
	}
}
