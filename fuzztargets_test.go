package veepin

// Keeps the fuzz job's target list and the tree in step.
//
// .github/workflows/ci.yml names every fuzz target by hand, and its own comment
// states the principle: "a target nothing runs is not a test". Nothing enforced
// it. The job's existing guard compares the number of targets it *ran* against a
// hardcoded expected count, which catches the heredoc truncation it was written
// for and catches adding a line to the list — but not the case that matters: a
// Fuzz function added to a package and never added to the list. The count still
// matches, the job is still green, and that parser is never fuzzed.
//
// That is worth guarding here rather than anywhere else because these parsers
// read bytes an unauthenticated peer controls, so a panic in one is a remote
// crash — and because fuzzing has already found real bugs in them (the Fortinet
// GFtype cookie's missing NUL terminator, which gave one cookie two encodings).
//
// The test lives in the root package because it is about the repository rather
// than about any one package's behaviour, and it reads both sides from source so
// it cannot itself drift.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const fuzzWorkflow = ".github/workflows/ci.yml"

// fuzzTarget is one package/function pair, in the form the workflow lists.
type fuzzTarget struct {
	Pkg  string // "./internal/masque"
	Name string // "FuzzReadCapsule"
}

// declaredFuzzTargets walks the tree for exported Fuzz functions that take a
// *testing.F, which is what `go test -fuzz` will run.
func declaredFuzzTargets(t *testing.T) []fuzzTarget {
	t.Helper()

	var targets []fuzzTarget
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Vendored, generated and VCS trees hold no targets of ours.
			switch d.Name() {
			case ".git", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // a file that does not parse is the compiler's problem, not this test's
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
				continue
			}
			if !takesTestingF(fn) {
				continue
			}
			targets = append(targets, fuzzTarget{
				Pkg:  "./" + filepath.ToSlash(filepath.Dir(path)),
				Name: fn.Name.Name,
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	return targets
}

// takesTestingF reports whether fn has the single *testing.F parameter that
// makes it a fuzz target rather than an ordinary helper whose name starts with
// "Fuzz".
func takesTestingF(fn *ast.FuncDecl) bool {
	params := fn.Type.Params
	if params == nil || len(params.List) != 1 {
		return false
	}
	star, ok := params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "F" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing"
}

var (
	fuzzListLine   = regexp.MustCompile(`^\s*(\./\S+)\s+(Fuzz\w+)\s*$`)
	fuzzExpectedRe = regexp.MustCompile(`(?m)^\s*expected=(\d+)\s*$`)
)

// listedFuzzTargets reads the workflow's TARGETS heredoc, plus the expected
// count it asserts.
func listedFuzzTargets(t *testing.T) ([]fuzzTarget, int) {
	t.Helper()

	body, err := os.ReadFile(fuzzWorkflow)
	if err != nil {
		t.Fatalf("reading %s: %v", fuzzWorkflow, err)
	}
	text := string(body)

	start := strings.Index(text, "3<<'TARGETS'")
	if start < 0 {
		t.Fatalf("%s: no TARGETS heredoc found; this guard no longer knows where the "+
			"fuzz list lives and is silently checking nothing", fuzzWorkflow)
	}
	rest := text[start:]
	end := strings.Index(rest, "\n          TARGETS")
	if end < 0 {
		t.Fatalf("%s: TARGETS heredoc is not terminated as expected", fuzzWorkflow)
	}

	var listed []fuzzTarget
	for _, line := range strings.Split(rest[:end], "\n") {
		if m := fuzzListLine.FindStringSubmatch(line); m != nil {
			listed = append(listed, fuzzTarget{Pkg: m[1], Name: m[2]})
		}
	}

	expected := -1
	if m := fuzzExpectedRe.FindStringSubmatch(text); m != nil {
		expected, _ = strconv.Atoi(m[1])
	}
	return listed, expected
}

func fuzzKey(f fuzzTarget) string { return f.Pkg + " " + f.Name }

// TestFuzzTargetsAreAllListed is the guard proper.
func TestFuzzTargetsAreAllListed(t *testing.T) {
	declared := declaredFuzzTargets(t)
	listed, expected := listedFuzzTargets(t)

	if len(declared) == 0 {
		t.Fatal("found no fuzz targets in the tree; this guard covers nothing")
	}
	if len(listed) == 0 {
		t.Fatalf("found no targets in %s's list; this guard covers nothing", fuzzWorkflow)
	}

	inList := make(map[string]bool, len(listed))
	for _, f := range listed {
		if inList[fuzzKey(f)] {
			t.Errorf("%s lists %s twice", fuzzWorkflow, fuzzKey(f))
		}
		inList[fuzzKey(f)] = true
	}
	inTree := make(map[string]bool, len(declared))
	for _, f := range declared {
		inTree[fuzzKey(f)] = true
	}

	var missing, stale []string
	for _, f := range declared {
		if !inList[fuzzKey(f)] {
			missing = append(missing, fuzzKey(f))
		}
	}
	for _, f := range listed {
		if !inTree[fuzzKey(f)] {
			stale = append(stale, fuzzKey(f))
		}
	}
	slices.Sort(missing)
	slices.Sort(stale)

	for _, k := range missing {
		t.Errorf("fuzz target %s exists but is not in %s, so nothing ever fuzzes it — "+
			"add the line to the TARGETS list and bump expected=", k, fuzzWorkflow)
	}
	for _, k := range stale {
		t.Errorf("%s lists fuzz target %s, which no longer exists — the job will fail "+
			"trying to run it", fuzzWorkflow, k)
	}

	// The job asserts it ran this many, which is how it catches the heredoc
	// being truncated. That number has to track the list.
	if expected < 0 {
		t.Errorf("%s: no `expected=N` assertion found; the job would no longer notice "+
			"a truncated target list", fuzzWorkflow)
	} else if expected != len(listed) {
		t.Errorf("%s asserts expected=%d but lists %d targets; the job fails on every run",
			fuzzWorkflow, expected, len(listed))
	}
}
