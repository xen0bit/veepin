package livingreadme

import (
	"strings"
	"testing"
)

func TestParseTestResults(t *testing.T) {
	// A representative slice of `go test -json` output: a pass, a fail, a skip,
	// a subtest (ignored), and non-JSON noise.
	in := strings.Join([]string{
		`{"Action":"run","Test":"TestInteropSelf"}`,
		`{"Action":"pass","Test":"TestInteropSelf"}`,
		`{"Action":"run","Test":"TestInteropWireguardSelf"}`,
		`{"Action":"fail","Test":"TestInteropWireguardSelf"}`,
		`{"Action":"skip","Test":"TestInteropOpenVPNSelf"}`,
		`{"Action":"pass","Test":"TestInteropOpenVPNSelf/subcase"}`,
		`not json at all`,
		`{"Action":"pass","Package":"pkg"}`,
	}, "\n")

	got := ParseTestResults(in)
	if !got["TestInteropSelf"] {
		t.Error("TestInteropSelf should be pass")
	}
	if got["TestInteropWireguardSelf"] {
		t.Error("TestInteropWireguardSelf should be fail")
	}
	if got["TestInteropOpenVPNSelf"] {
		t.Error("skipped test should not be pass")
	}
	if _, ok := got["TestInteropOpenVPNSelf/subcase"]; ok {
		t.Error("subtests must be ignored")
	}
}

func TestRenderCell(t *testing.T) {
	results := TestResults{"A": true, "B": true, "C": false}

	cases := []struct {
		name string
		cell interopCell
		want string
	}{
		{"all pass with label", interopCell{Tests: []string{"A", "B"}, Label: "strongSwan"}, "✓ strongSwan"},
		{"one fails", interopCell{Tests: []string{"A", "C"}, Label: "strongSwan"}, "✗ strongSwan"},
		{"missing test fails", interopCell{Tests: []string{"A", "Z"}}, "✗"},
		{"self pass no label", interopCell{Tests: []string{"A"}}, "✓"},
		{"untested verbatim label", interopCell{Label: "—†"}, "—†"},
		{"untested no label", interopCell{}, "—"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderCell(tc.cell, results); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRenderInterop(t *testing.T) {
	// Everything passes.
	results := TestResults{}
	for _, row := range interopMatrix {
		for _, c := range []interopCell{row.Client, row.Server, row.Self} {
			for _, name := range c.Tests {
				results[name] = true
			}
		}
	}
	out := RenderInterop(results, Meta{})

	if !strings.Contains(out, "| Protocol") {
		t.Error("missing header row")
	}
	// No ✗ anywhere when all pass.
	if strings.Contains(out, "✗") {
		t.Errorf("unexpected failure mark with all-passing results:\n%s", out)
	}
	// Every protocol appears.
	for _, row := range interopMatrix {
		if !strings.Contains(out, row.Protocol) {
			t.Errorf("protocol %q missing from matrix", row.Protocol)
		}
	}
	// Fortinet's untested client cell survives verbatim.
	if !strings.Contains(out, "—†") {
		t.Error("Fortinet untested client cell lost")
	}

	// One failure flips exactly that cell.
	results["TestInteropSelf"] = false
	out = RenderInterop(results, Meta{})
	if !strings.Contains(out, "✗") {
		t.Error("expected a failure mark after flipping a result")
	}
}

func TestInteropMatrixTestsExist(t *testing.T) {
	// Guard against typos in the manifest: no duplicate test names across cells,
	// which would silently couple unrelated cells.
	seen := map[string]string{}
	for _, row := range interopMatrix {
		for _, c := range []interopCell{row.Client, row.Server, row.Self} {
			for _, name := range c.Tests {
				if where, dup := seen[name]; dup {
					t.Errorf("test %q listed in both %q and %q", name, where, row.Protocol)
				}
				seen[name] = row.Protocol
			}
		}
	}
}
