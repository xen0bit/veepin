package livingreadme

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// TestInteropShards checks the derived split covers the manifest exactly. The
// shards are what CI runs, so a test missing from every shard never runs at all,
// and a test that never runs is indistinguishable from one that passes.
func TestInteropShards(t *testing.T) {
	shards := InteropShards()
	if len(shards) == 0 {
		t.Fatal("no shards derived from the manifest")
	}

	names := map[string]bool{}
	for _, s := range shards {
		if s.Name == "" {
			t.Errorf("shard with an empty name: %+v", s)
		}
		if names[s.Name] {
			t.Errorf("duplicate shard name %q; artifacts would collide", s.Name)
		}
		names[s.Name] = true
		for _, r := range s.Name {
			safe := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
			if !safe {
				t.Errorf("shard name %q contains %q, which is not safe for a job or "+
					"artifact identifier", s.Name, r)
			}
		}
	}

	// Every manifest test must be selected by exactly one shard's regexp.
	for _, row := range interopMatrix {
		for _, c := range []interopCell{row.Client, row.Server, row.Self} {
			for _, name := range c.Tests {
				matched := 0
				for _, s := range shards {
					re, err := regexp.Compile(s.Run)
					if err != nil {
						t.Fatalf("shard %q has an invalid -run regexp %q: %v", s.Name, s.Run, err)
					}
					if re.MatchString(name) {
						matched++
					}
				}
				if matched != 1 {
					t.Errorf("test %q is selected by %d shards, want exactly 1", name, matched)
				}
			}
		}
	}
}

// A skip is not a failure, and the table cannot tell them apart.
//
// renderCell maps both to "✗", which reads as "veepin does not interoperate"
// — so a run that could not start a peer would publish the opposite of what
// happened. SkippedMatrixTests is what lets the generator refuse instead, and
// this pins the three distinctions it has to draw: skip is reported, fail and
// pass are not, and a test outside the manifest is nobody's business.
func TestSkippedMatrixTestsSeparatesSkipsFromFailures(t *testing.T) {
	in := strings.Join([]string{
		`{"Action":"skip","Test":"TestInteropVeepinClientKernelL2TPv3Server"}`,
		`{"Action":"fail","Test":"TestInteropL2TPv3Self"}`,
		`{"Action":"pass","Test":"TestInteropWireguardSelf"}`,
		`{"Action":"skip","Test":"TestSomethingNotInTheMatrix"}`,
		`{"Action":"skip","Test":"TestInteropWireguardSelf/subcase"}`,
	}, "\n")

	got := SkippedMatrixTests(in)
	want := []string{"TestInteropVeepinClientKernelL2TPv3Server"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A test whose final action is a pass did not skip, whatever happened inside
// it. Subtests skip routinely -- a cell that probes for a capability and then
// tests what it found -- and reporting the parent as skipped would refuse a run
// that tested everything it claims to.
func TestSkippedMatrixTestsTakesTheFinalAction(t *testing.T) {
	in := strings.Join([]string{
		`{"Action":"skip","Test":"TestInteropWireguardSelf"}`,
		`{"Action":"pass","Test":"TestInteropWireguardSelf"}`,
	}, "\n")

	if got := SkippedMatrixTests(in); len(got) != 0 {
		t.Errorf("a test that ended in a pass was reported as skipped: %v", got)
	}
}

// A row's Modules must survive into its shard, because that is the only thing
// the workflow reads.
//
// This is the same failure the shard derivation exists to prevent, one field
// along: a host requirement declared in the manifest and dropped on the way out
// means the workflow's modprobe step no-ops, the peer never starts, the cells
// t.Skip, and a skip is reported as not-passed. Every one of those steps is
// quiet, which is why the check is here and not left to somebody noticing a ✗.
func TestShardsCarryTheModulesTheirRowDeclares(t *testing.T) {
	byName := map[string][]string{}
	for _, s := range InteropShards() {
		// Never nil, because a nil slice marshals to null and the workflow reads
		// this through GitHub's join(), whose behaviour on null is not something
		// to discover from a failing run.
		if s.Modules == nil {
			t.Errorf("shard %q has nil Modules; it would serialise as null, not []", s.Name)
		}
		byName[s.Name] = s.Modules
	}
	declared := 0
	for _, row := range interopMatrix {
		if len(row.Modules) == 0 {
			continue
		}
		declared++
		got, ok := byName[shardName(row.Protocol)]
		if !ok {
			t.Errorf("%s declares modules %v but yields no shard", row.Protocol, row.Modules)
			continue
		}
		if !slices.Equal(got, row.Modules) {
			t.Errorf("%s: shard carries %v, row declares %v", row.Protocol, got, row.Modules)
		}
	}
	// If nothing declares any, the field is dead and so is the workflow step
	// that reads it -- which is worth knowing, because the step is silent when
	// the list is empty and would stay silent after a row lost its modules.
	if declared == 0 {
		t.Error("no row declares Modules; the workflow's module step now does nothing on every shard")
	}
}

// TestInteropMatrixMatchesTheTestFunctions is the other half of the contract the
// manifest has always claimed but never checked: that it and
// tests/interop/*_test.go name the same set of tests.
//
// It matters more now that CI shards by the manifest. A test function absent
// from it is not merely missing from the README table — it is in no shard, so it
// never runs, and nothing says so.
func TestInteropMatrixMatchesTheTestFunctions(t *testing.T) {
	const dir = "../../tests/interop"

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	declared := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s/%s: %v", dir, name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "TestInterop") {
				continue
			}
			declared[fn.Name.Name] = true
		}
	}
	if len(declared) == 0 {
		t.Fatalf("found no TestInterop* functions in %s; this check covers nothing", dir)
	}

	listed := map[string]bool{}
	for _, row := range interopMatrix {
		for _, c := range []interopCell{row.Client, row.Server, row.Self} {
			for _, name := range c.Tests {
				listed[name] = true
			}
		}
	}

	for name := range listed {
		if !declared[name] {
			t.Errorf("the manifest lists %q, which no longer exists in %s: it reads as a "+
				"permanent failure in the README matrix", name, dir)
		}
	}
	for name := range declared {
		if !listed[name] {
			t.Errorf("%s declares %q but the manifest does not list it, so CI puts it in no "+
				"shard and it never runs", dir, name)
		}
	}
}

// TestNoRowCarriesADashInTheSelfColumn turns a comment into a check.
//
// interop.go said, from the moment the SoftEther row was written, that "a
// veepin↔veepin test is always possible, so a dash there is never earned" — and
// the SoftEther row carried one anyway, for as long as the sentence sat above
// it. A comment describing an invariant is not an invariant.
//
// The client and server columns legitimately carry a dash: "—†" where no
// open-source peer exists to test against (FortiOS), "—‡" where the cell has not
// been built. Neither reason can apply to Self. Both ends are veepin, so the
// peer always exists — which means a dash there is never about availability. It
// is either an afternoon nobody spent, or, as it turned out for SoftEther, a
// data path nobody had written. Both are worth failing a build over; neither is
// worth a dash that reads like a matrix result.
func TestNoRowCarriesADashInTheSelfColumn(t *testing.T) {
	for _, row := range interopMatrix {
		if len(row.Self.Tests) > 0 {
			continue
		}
		t.Errorf("%s names no test in its Self column (label %q). Both ends are veepin, "+
			"so a peer always exists and the cell is always possible; a dash here reads "+
			"as a matrix result while meaning nobody built it.",
			row.Protocol, row.Self.Label)
	}
}
