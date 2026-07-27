package main

// Guards against the CLI and the protocol facades drifting apart.
//
// Each protocol binds its flags in connectFlags/serveFlags and then copies them
// into the option map the facade parses. Those are two separate lists written by
// hand, so a flag can be bound, documented in -h, accepted on the command line —
// and then silently dropped on the floor because nothing ever copies it into the
// map. Nothing fails; the server simply ignores what the operator asked for.
//
// That is the worst shape a bug can take here. `-shape` deciding to do nothing
// leaves an operator believing downstream traffic is padded when it is not, and
// there is no output anywhere that would say otherwise.
//
// The check below needs no per-protocol knowledge, so it cannot itself fall out
// of date: enumerate whatever flags a protocol binds, and require each one to
// change the option map when it changes.

import (
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
)

// TestServeFlagsCoverRegisteredServerProtocols is the serve-side mirror of
// TestConnectFlagsCoverRegisteredProtocols: a protocol you can serve but cannot
// pass flags to is unreachable from the command line.
func TestServeFlagsCoverRegisteredServerProtocols(t *testing.T) {
	for _, name := range client.ServerProtocols() {
		if _, err := serveFlags(name, newTestFlagSet()); err != nil {
			t.Errorf("serve has no flags for registered server protocol %q: %v", name, err)
		}
	}
}

// flagSentinel is a value no flag defaults to, used to perturb string flags.
const flagSentinel = "veepin-flag-reaches-options"

// perturbed returns a value for f that differs from the one it currently holds,
// spelled in the flag's own type so Set accepts it. The second result is false
// for a flag type this test does not know how to vary, which is reported rather
// than skipped — an unknown type here means the check has quietly stopped
// covering that flag.
func perturbed(f *flag.Flag) (string, bool) {
	getter, ok := f.Value.(flag.Getter)
	if !ok {
		return "", false
	}
	switch v := getter.Get().(type) {
	case bool:
		return strconv.FormatBool(!v), true
	case int:
		return strconv.Itoa(v + 1), true
	case string:
		if v == flagSentinel {
			return flagSentinel + "-2", true
		}
		return flagSentinel, true
	}
	return "", false
}

// assertFlagsReachOptions requires every flag a protocol binds to influence the
// option map it produces. Each flag is varied on its own flag set, so a failure
// names the one flag that is dead rather than the whole protocol.
func assertFlagsReachOptions(
	t *testing.T,
	command string,
	protocols []string,
	bind func(string, *flag.FlagSet) (func() map[string]string, error),
) {
	t.Helper()

	for _, protocol := range protocols {
		probe := newTestFlagSet()
		if _, err := bind(protocol, probe); err != nil {
			t.Errorf("%s %s: binding flags: %v", command, protocol, err)
			continue
		}
		var names []string
		probe.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
		if len(names) == 0 {
			t.Errorf("%s %s: binds no flags at all", command, protocol)
			continue
		}

		for _, name := range names {
			fs := newTestFlagSet()
			options, err := bind(protocol, fs)
			if err != nil {
				t.Fatalf("%s %s: binding flags: %v", command, protocol, err)
			}
			before := options()

			value, ok := perturbed(fs.Lookup(name))
			if !ok {
				t.Errorf("%s %s: -%s has a type this test cannot vary; teach perturbed() about it",
					command, protocol, name)
				continue
			}
			if err := fs.Set(name, value); err != nil {
				t.Errorf("%s %s: setting -%s=%s: %v", command, protocol, name, value, err)
				continue
			}

			if after := options(); maps.Equal(before, after) {
				t.Errorf("%s %s: -%s changes no key in the option map, so the facade "+
					"never sees it — the flag is accepted and silently ignored",
					command, protocol, name)
			}
		}
	}
}

// TestEveryServeFlagReachesTheOptionMap is the guard proper for the server side.
func TestEveryServeFlagReachesTheOptionMap(t *testing.T) {
	assertFlagsReachOptions(t, "serve", client.ServerProtocols(), serveFlags)
}

// TestEveryConnectFlagReachesTheOptionMap is the same guard for the client side,
// where a dropped flag is just as quiet.
func TestEveryConnectFlagReachesTheOptionMap(t *testing.T) {
	assertFlagsReachOptions(t, "connect", client.Protocols(), connectFlags)
}

// optionVocabulary is every option key a protocol's facade package declares: the
// Opt* string constants that are its documented surface. It is read from the
// source rather than from the package's exported values because Go constants
// cannot be enumerated at run time, and asking each facade to publish a list for
// the benefit of a test would grow ten public APIs to check one thing.
//
// Client and server constants are deliberately pooled. They cannot be told apart
// by name — ikev2.OptServerID is a *client* key ("server-id"), not a server one —
// and the distinction does not matter for what this catches: an option map keyed
// by a string the facade never mentions at all.
func optionVocabulary(t *testing.T, protocol string) map[string]bool {
	t.Helper()

	dir := filepath.Join("..", "..", protocol)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the %s facade package at %s: %v", protocol, dir, err)
	}

	fset := token.NewFileSet()
	vocabulary := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s/%s: %v", dir, name, err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range value.Names {
					if !strings.HasPrefix(ident.Name, "Opt") || i >= len(value.Values) {
						continue
					}
					lit, ok := value.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					if key, err := strconv.Unquote(lit.Value); err == nil {
						vocabulary[key] = true
					}
				}
			}
		}
	}
	return vocabulary
}

// assertEmittedKeysAreDeclared requires every key the CLI puts in the option map
// to be one the facade declares. This is the half the compiler cannot see: a key
// spelled wrong, or copied from a protocol that happens to name things
// differently, still compiles and still type-checks — the facade just never
// looks it up, and the setting is dropped in silence.
//
// Every flag is set away from its default first, so keys the CLI writes only
// conditionally (`if *shape != 0`) are present to be checked.
func assertEmittedKeysAreDeclared(
	t *testing.T,
	command string,
	protocols []string,
	bind func(string, *flag.FlagSet) (func() map[string]string, error),
) {
	t.Helper()

	for _, protocol := range protocols {
		fs := newTestFlagSet()
		options, err := bind(protocol, fs)
		if err != nil {
			t.Errorf("%s %s: binding flags: %v", command, protocol, err)
			continue
		}
		fs.VisitAll(func(f *flag.Flag) {
			if value, ok := perturbed(f); ok {
				_ = fs.Set(f.Name, value)
			}
		})

		vocabulary := optionVocabulary(t, protocol)
		if len(vocabulary) == 0 {
			t.Errorf("%s %s: found no Opt* constants in the facade package; "+
				"this check silently covers nothing for %s", command, protocol, protocol)
			continue
		}

		var undeclared []string
		for key := range options() {
			if !vocabulary[key] {
				undeclared = append(undeclared, key)
			}
		}
		sort.Strings(undeclared)
		for _, key := range undeclared {
			t.Errorf("%s %s: emits option key %q, which the %s package declares no Opt* "+
				"constant for — the facade cannot be reading it",
				command, protocol, key, protocol)
		}
	}
}

// TestServeEmittedKeysAreDeclared and its connect twin are the checks that catch
// a misspelled or foreign option key, which compiles cleanly and then does
// nothing.
func TestServeEmittedKeysAreDeclared(t *testing.T) {
	assertEmittedKeysAreDeclared(t, "serve", client.ServerProtocols(), serveFlags)
}

func TestConnectEmittedKeysAreDeclared(t *testing.T) {
	assertEmittedKeysAreDeclared(t, "connect", client.Protocols(), connectFlags)
}
