package main

// The harness must know every protocol the production binary knows, and the
// only thing that makes it so is the block of blank imports at the top of
// main.go. Forgetting one is silent in exactly the way AGENTS.md warns about for
// docs_test.go: the panel's protocol dropdown is one entry shorter, no form
// renders for the missing protocol, and every test passes because no test names
// it.
//
// The subtlety is where the *other* side of the comparison comes from. Asking
// client.Protocols() is circular and looks like it works: this file is in the
// harness's own package, so a protocol whose import is missing is not linked
// into the test binary either, does not register, and is absent from both sides
// at once. Removing an import to check the guard bites produces a pass.
//
// So the truth is taken from the source tree instead: a facade is a top-level
// package that calls client.Register or client.RegisterServer, which is the
// definition AGENTS.md gives and the one thing a new protocol cannot skip.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/xen0bit/veepin/"

// moduleRoot is where this test's working directory sits relative to the repo.
const moduleRoot = "../../.."

// TestHarnessImportsEveryProtocolFacade: the facade packages main.go imports and
// the facade packages in the tree are the same set. A facade missing here serves
// a panel that has never heard of that protocol; a name here that is no longer a
// facade is an import that outlived its package.
func TestHarnessImportsEveryProtocolFacade(t *testing.T) {
	imported := harnessFacadeImports(t)
	facades := facadePackages(t)

	// If the scan finds nothing the comparison below is vacuously true, which is
	// the failure this whole file exists to avoid having.
	if len(facades) < 10 {
		t.Fatalf("found only %d facade packages under %s; the scan is broken, not the tree",
			len(facades), moduleRoot)
	}

	for _, p := range facades {
		if !slices.Contains(imported, p) {
			t.Errorf("main.go does not import %q, so the harness serves a panel that has never heard of it\n"+
				"add:\t_ \"%s%s\"", p, modulePath, p)
		}
	}
	for _, p := range imported {
		if !slices.Contains(facades, p) {
			t.Errorf("main.go imports %q, which registers no protocol", p)
		}
	}
}

// harnessFacadeImports returns every main.go import under the module root that
// is a single path element -- the facades. internal/... and client are plumbing.
func harnessFacadeImports(t *testing.T) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing main.go: %v", err)
	}
	var out []string
	for _, spec := range f.Imports {
		p := importPath(t, spec)
		if !strings.HasPrefix(p, modulePath) {
			continue
		}
		rest := strings.TrimPrefix(p, modulePath)
		if strings.Contains(rest, "/") || rest == "client" {
			continue
		}
		out = append(out, rest)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// facadePackages returns the name of every top-level directory holding a package
// that calls client.Register or client.RegisterServer. Matching on the call is
// what keeps this honest: a directory is a facade because it registers, not
// because it is spelled like a protocol.
func facadePackages(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(moduleRoot)
	if err != nil {
		t.Fatalf("reading the module root: %v", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "internal" || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if registersAProtocol(t, filepath.Join(moduleRoot, e.Name())) {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out
}

func registersAProtocol(t *testing.T, dir string) bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("globbing %s: %v", dir, err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		if strings.Contains(string(body), "client.Register(") ||
			strings.Contains(string(body), "client.RegisterServer(") {
			return true
		}
	}
	return false
}

func importPath(t *testing.T, spec *ast.ImportSpec) string {
	t.Helper()
	p, err := strconv.Unquote(spec.Path.Value)
	if err != nil {
		t.Fatalf("import path %s is not a quoted string: %v", spec.Path.Value, err)
	}
	return p
}
