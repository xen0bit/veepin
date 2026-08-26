package livingreadme

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseThroughputJSON(t *testing.T) {
	// Wrap two markers the way go test -json does: as Output events with go
	// test's "    file.go:NN: " framing.
	mk := func(payload string) string {
		b, _ := json.Marshal(struct {
			Action string
			Output string
		}{"output", payload})
		return string(b)
	}
	in := strings.Join([]string{
		mk("    interop_test.go:120: " + IperfLine("TestInteropSelf", 1.94e9) + "\n"),
		mk("    interop_test.go:120: " + IperfLine("TestInteropWireguardSelf", 8.5e8) + "\n"),
		mk("some unrelated line\n"),
		`{"Action":"pass","Test":"TestInteropSelf"}`,
	}, "\n")

	tp := ParseThroughput(in)
	if got := tp["TestInteropSelf"].BitsPerSec; got != 1.94e9 {
		t.Errorf("TestInteropSelf = %v, want 1.94e9", got)
	}
	if got := tp["TestInteropWireguardSelf"].BitsPerSec; got != 8.5e8 {
		t.Errorf("TestInteropWireguardSelf = %v, want 8.5e8", got)
	}
}

func TestParseThroughputRaw(t *testing.T) {
	// A raw (non-JSON) stream should also yield markers.
	in := "noise\n" + IperfLine("TestInteropSelf", 1000) + "\nmore noise\n"
	tp := ParseThroughput(in)
	if tp["TestInteropSelf"].BitsPerSec != 1000 {
		t.Errorf("raw parse failed: %v", tp)
	}
}

func TestParseThroughputKeepsMax(t *testing.T) {
	in := IperfLine("T", 0) + "\n" + IperfLine("T", 500) + "\n" + IperfLine("T", 200) + "\n"
	tp := ParseThroughput(in)
	if tp["T"].BitsPerSec != 500 {
		t.Errorf("expected max 500, got %v", tp["T"])
	}
}

func TestFormatBits(t *testing.T) {
	cases := map[float64]string{
		1.94e9: "1.94 Gbit/s",
		2.5e9:  "2.5 Gbit/s",
		8.5e8:  "850 Mbit/s",
		12.3e6: "12.3 Mbit/s",
		9.6e5:  "960 kbit/s",
		500:    "500 bit/s",
	}
	for in, want := range cases {
		if got := formatBits(in); got != want {
			t.Errorf("formatBits(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderInteropBench(t *testing.T) {
	tp := Throughput{
		"TestInteropSelf":                         {BitsPerSec: 1.9e9},
		"TestInteropVeepinClientStrongswanServer": {BitsPerSec: 1.2e9},
	}
	out := RenderInteropBench(tp, Meta{})

	if !strings.Contains(out, "1.9 Gbit/s") {
		t.Errorf("self throughput missing:\n%s", out)
	}
	if !strings.Contains(out, "1.2 Gbit/s") {
		t.Errorf("client throughput missing:\n%s", out)
	}
	// A cell with no measurement is an em dash; Fortinet's untested client too.
	if !strings.Contains(out, "—") {
		t.Errorf("expected em dashes for unmeasured cells:\n%s", out)
	}
	// Every protocol row is present.
	for _, row := range interopMatrix {
		if !strings.Contains(out, row.Protocol) {
			t.Errorf("protocol %q missing", row.Protocol)
		}
	}
}

// TestParseThroughputFailedMarker covers the distinction the table exists to
// make. The failed marker has the successful one as a prefix, so a parser that
// checked the wrong one first would read a failure as a malformed success and
// drop it — leaving the cell indistinguishable from one never measured.
func TestParseThroughputFailedMarker(t *testing.T) {
	in := "noise\n" + IperfFailedLine("TestInteropVeepinClientSSHServer") + "\n"
	tp := ParseThroughput(in)

	m, ok := tp["TestInteropVeepinClientSSHServer"]
	if !ok {
		t.Fatalf("failed marker not recorded: %v", tp)
	}
	if !m.Failed {
		t.Errorf("Failed = false, want true (%+v)", m)
	}
	if m.BitsPerSec != 0 {
		t.Errorf("BitsPerSec = %v, want 0", m.BitsPerSec)
	}
}

// TestParseThroughputSuccessBeatsFailure: a cell that failed once and then
// measured is a working cell. Order must not decide it.
func TestParseThroughputSuccessBeatsFailure(t *testing.T) {
	for _, in := range []string{
		IperfFailedLine("T") + "\n" + IperfLine("T", 700) + "\n",
		IperfLine("T", 700) + "\n" + IperfFailedLine("T") + "\n",
	} {
		tp := ParseThroughput(in)
		if tp["T"].Failed || tp["T"].BitsPerSec != 700 {
			t.Errorf("input %q gave %+v, want a 700 measurement", in, tp["T"])
		}
	}
}

// TestBenchCellStates pins the three-way distinction directly, since it is the
// whole point of the change: an absent measurement and a broken one are
// different facts about a cell.
func TestBenchCellStates(t *testing.T) {
	measured := interopCell{Tests: []string{"measured"}}
	broke := interopCell{Tests: []string{"broke"}}
	never := interopCell{Tests: []string{"never"}}
	noTest := interopCell{}

	tp := Throughput{
		"measured": {BitsPerSec: 5e8},
		"broke":    {Failed: true},
	}

	if got := benchCell(measured, tp); got != "500 Mbit/s" {
		t.Errorf("measured cell = %q, want 500 Mbit/s", got)
	}
	if got := benchCell(broke, tp); got != "✗" {
		t.Errorf("attempted-and-failed cell = %q, want ✗ — a broken measurement "+
			"must not read as a deliberate omission", got)
	}
	if got := benchCell(never, tp); got != "—" {
		t.Errorf("never-measured cell = %q, want —", got)
	}
	if got := benchCell(noTest, tp); got != "—" {
		t.Errorf("cell with no test = %q, want —", got)
	}
}

// TestBenchCellScansTheWholeCell pins the three states against a cell whose
// measured test is not its first.
//
// The old benchCell read Tests[0] and nothing else, so a cell like this rendered
// an em dash — "iperf3 does not apply here" — while holding a real measurement.
// It is not a hypothetical: every pq- cell was appended after its row's existing
// tests, which is precisely this shape, and their throughput went unpublished
// for exactly that reason.
func TestBenchCellScansTheWholeCell(t *testing.T) {
	cases := []struct {
		name string
		cell interopCell
		tp   Throughput
		want string
	}{
		{
			"a measurement behind an unmeasured test still renders",
			interopCell{Tests: []string{"A", "B"}},
			Throughput{"B": {BitsPerSec: 1e9}},
			"1 Gbit/s",
		},
		{
			"the first measured test wins, not the largest",
			interopCell{Tests: []string{"A", "B"}},
			Throughput{"A": {BitsPerSec: 1e6}, "B": {BitsPerSec: 1e9}},
			"1 Mbit/s",
		},
		{
			"a failed measurement behind an unmeasured test is a cross",
			interopCell{Tests: []string{"A", "B"}},
			Throughput{"B": {Failed: true}},
			"✗",
		},
		{
			"a success anywhere beats a failure before it",
			interopCell{Tests: []string{"A", "B"}},
			Throughput{"A": {Failed: true}, "B": {BitsPerSec: 5e8}},
			"500 Mbit/s",
		},
		{
			"nothing measured at all is an em dash",
			interopCell{Tests: []string{"A", "B"}},
			Throughput{},
			"—",
		},
		{
			"a cell with no tests is an em dash",
			interopCell{Label: "—†"},
			Throughput{"A": {BitsPerSec: 1e9}},
			"—",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := benchCell(tc.cell, tc.tp); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEveryMatrixCellNamesItsBenchTestFirst holds the convention benchCell's
// ordering relies on: within a cell, the test that measures comes before any
// that do not.
//
// benchCell no longer BREAKS when that is violated — it scans past the gap — but
// it does then publish a variant's number where the plain cell's belongs, and a
// shaped variant's throughput is deliberately far lower than its unshaped
// sibling's. Presenting that as the cell's rate would be wrong in a way nobody
// would notice, so the ordering stays a rule and this is what enforces it.
func TestEveryMatrixCellNamesItsBenchTestFirst(t *testing.T) {
	benched := benchedInteropTests(t)
	for _, row := range interopMatrix {
		for _, c := range []interopCell{row.Client, row.Server, row.Self} {
			if len(c.Tests) < 2 {
				continue
			}
			if benched[c.Tests[0]] {
				continue
			}
			for _, later := range c.Tests[1:] {
				if benched[later] {
					t.Errorf("%s: %q measures throughput but %q is listed first, so the "+
						"table would publish a later cell's rate as this one's. Put the "+
						"measuring test first.", row.Protocol, later, c.Tests[0])
				}
			}
		}
	}
}

// benchedInteropTests reports which TestInterop* functions end up measuring
// throughput, following calls through the harness's own helpers.
//
// The indirection is real and has to be followed: some cells call
// runInteropBench directly, some go through runOpenVPNInterop, and the pq- ones
// through runInteropPQSelf. A check that grepped for runInteropBench in a test's
// own body would call two thirds of the measured cells unmeasured and then
// enforce an ordering rule against the wrong set.
func benchedInteropTests(t *testing.T) map[string]bool {
	t.Helper()
	const dir = "../../tests/interop"

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	calls := map[string]map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s/%s: %v", dir, entry.Name(), err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			out := map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok {
					out[id.Name] = true
				}
				return true
			})
			calls[fn.Name.Name] = out
		}
	}

	// The two leaves that actually log a throughput marker.
	measures := map[string]bool{"runInteropBench": true, "measureThroughput": true}
	// Closure: a helper that calls a measuring function measures. Iterating to a
	// fixed point rather than recursing keeps it obviously terminating.
	for changed := true; changed; {
		changed = false
		for name, callees := range calls {
			if measures[name] {
				continue
			}
			for callee := range callees {
				if measures[callee] {
					measures[name] = true
					changed = true
					break
				}
			}
		}
	}

	benched := map[string]bool{}
	for name := range calls {
		if strings.HasPrefix(name, "TestInterop") && measures[name] {
			benched[name] = true
		}
	}
	if len(benched) == 0 {
		t.Fatal("no TestInterop* function was found to measure throughput; this check covers nothing")
	}
	return benched
}
