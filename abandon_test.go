package veepin

// A listener that will not close must still give its descriptors back.
//
// The supervisor bounds how long it waits for a listener's Close (stopGrace, 5s)
// because an unbounded wait freezes every other listener's status behind one
// wedged protocol. Past the bound the listener is abandoned -- and abandoning it
// used to mean its packet pump goroutine and TUN fd stayed held for the life of
// the process, so a fleet restarting a genuinely wedged listener on a timer
// accumulated one of each per attempt.
//
// client.AbandonableServer is what closes that, and it is found by type
// assertion at exactly one call site (internal/supervisor's stopListenerLocked).
// A facade that does not implement it is not a compile error and not a test
// failure anywhere else: it is a listener that leaks, silently, only in
// production, only after a Close has already gone wrong. Hence a guard.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
)

// serverIsAnotherFacades names protocols whose registered server is not a type
// of their own, with the facade that owns it. Their parse function returns
// somebody else's *Server, so the assertion belongs there and would be a
// duplicate here.
var serverIsAnotherFacades = map[string]string{
	"amneziawg": "wireguard",
}

// TestEveryRegisteredServerCanBeAbandoned requires every facade that registers a
// server to assert client.AbandonableServer on its own type.
//
// It looks for the assertion rather than the method, and that is the point: the
// assertion is a compile-time check of the whole interface, so finding it proves
// the method exists *with the right signature*. Scanning for `func (s *Server)
// Abandon()` would pass just as happily on an Abandon that took an argument, or
// returned an error, or hung off the wrong type -- none of which the supervisor
// would ever call.
func TestEveryRegisteredServerCanBeAbandoned(t *testing.T) {
	for _, proto := range client.Protocols() {
		if _, ok := client.ServerOptsFor(proto); !ok {
			continue // client-only protocol; nothing registers a server
		}
		if owner, delegated := serverIsAnotherFacades[proto]; delegated {
			if !assertsAbandonable(t, owner) {
				t.Errorf("%s: its server is %s's, which does not assert "+
					"client.AbandonableServer", proto, owner)
			}
			continue
		}
		if !assertsAbandonable(t, proto) {
			t.Errorf("%s: no `var _ client.AbandonableServer = (*Server)(nil)` in the facade. "+
				"A listener the supervisor gives up waiting for keeps its packet pump "+
				"goroutine and its TUN fd until the process exits, and a fleet that "+
				"restarts it accumulates one of each per attempt. Add Abandon (close the "+
				"TUN, take no lock, wait for nothing) and assert it", proto)
		}
	}
}

// TestTheDelegatedServerListIsStillTrue keeps the exemption honest: an entry for
// a protocol that has since grown a server type of its own would suppress the
// check for a facade nobody is looking at.
func TestTheDelegatedServerListIsStillTrue(t *testing.T) {
	for proto, owner := range serverIsAnotherFacades {
		if _, ok := client.ServerOptsFor(proto); !ok {
			t.Errorf("%s is listed as delegating its server to %s, but registers no server "+
				"at all — the entry is stale", proto, owner)
		}
		if assertsAbandonable(t, proto) {
			t.Errorf("%s is listed as delegating its server to %s, but its own package now "+
				"asserts client.AbandonableServer — drop the entry", proto, owner)
		}
	}
}

// assertsAbandonable reports whether package dir contains the compile-time
// assertion. Files are parsed one at a time, as autherr_test.go and docs_test.go
// do: parser.ParseDir is deprecated and its replacement is a dependency this
// module does not take.
func assertsAbandonable(t *testing.T, dir string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Errorf("%s: %v", dir, err)
		return false
	}
	fset := token.NewFileSet()
	found := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Errorf("%s: %v", filepath.Join(dir, name), err)
			return false
		}
		ast.Inspect(file, func(n ast.Node) bool {
			decl, ok := n.(*ast.ValueSpec)
			if !ok || len(decl.Names) != 1 || decl.Names[0].Name != "_" {
				return true
			}
			sel, ok := decl.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if ok && pkg.Name == "client" && sel.Sel.Name == "AbandonableServer" {
				found = true
			}
			return true
		})
	}
	return found
}
