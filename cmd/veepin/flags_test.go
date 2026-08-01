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
	case uint:
		// AmneziaWG's H1-H4 are 32-bit message-type words, so their flags are
		// uint rather than int.
		return strconv.FormatUint(uint64(v)+1, 10), true
	case uint64:
		return strconv.FormatUint(v+1, 10), true
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

// TestServerOptSpecsMatchTheKeysTheProtocolReads is the same guard one layer
// further out, for the metadata the management panel renders forms from.
//
// client.RegisterServerOpts is a third hand-written list of option keys, after
// the facade's Opt* constants and serveFlags' option map. Nothing tied it to the
// other two. A spec keyed by a string the protocol never reads renders a form
// field an operator fills in and the server ignores — the same silent-drop shape
// the tests above exist for, arriving by a different route. A key the protocol
// does read but the metadata omits is worse in a quieter way: the panel offers
// no field for it, so the option is unreachable from the panel and, if it is a
// secret, GET /api/listeners/{name} does not know to redact it.
//
// serveFlags' emitted key set is the reference, because that is by construction
// what `veepin serve <protocol>` can set and therefore what the protocol reads.
func TestServerOptSpecsMatchTheKeysTheProtocolReads(t *testing.T) {
	for _, protocol := range client.ServerProtocols() {
		specs, ok := client.ServerOptsFor(protocol)
		if !ok {
			t.Errorf("%s: registered as a server but declared no OptSpec metadata", protocol)
			continue
		}

		fs := newTestFlagSet()
		options, err := serveFlags(protocol, fs)
		if err != nil {
			t.Errorf("%s: binding serve flags: %v", protocol, err)
			continue
		}
		fs.VisitAll(func(f *flag.Flag) {
			if value, ok := perturbed(f); ok {
				_ = fs.Set(f.Name, value)
			}
		})
		emitted := options()

		declared := make(map[string]bool, len(specs))
		for _, s := range specs {
			declared[s.Key] = true
			if _, reads := emitted[s.Key]; !reads {
				t.Errorf("%s: OptSpec declares key %q, which `veepin serve %s` never emits — "+
					"the panel renders a field the protocol does not read",
					protocol, s.Key, protocol)
			}
		}

		var missing []string
		for key := range emitted {
			if !declared[key] {
				missing = append(missing, key)
			}
		}
		sort.Strings(missing)
		for _, key := range missing {
			t.Errorf("%s: option %q has no OptSpec — it cannot be set from the panel, and if "+
				"it is a secret the management API does not know to redact it", protocol, key)
		}
	}
}

// TestClientOptSpecsMatchTheKeysTheProtocolReads is the client-side mirror of
// TestServerOptSpecsMatchTheKeysTheProtocolReads: the metadata the profile
// forms and `veepin profile add` render Dial options from must agree with what
// connectFlags actually emits (which is, by construction, what the protocol
// reads). A spec keyed by a string the parse never sees renders a field the
// operator fills in and the dial ignores.
func TestClientOptSpecsMatchTheKeysTheProtocolReads(t *testing.T) {
	for _, protocol := range client.Protocols() {
		specs, ok := client.ClientOptsFor(protocol)
		if !ok {
			t.Errorf("%s: registered as a client but declared no client OptSpec metadata", protocol)
			continue
		}

		fs := newTestFlagSet()
		options, err := connectFlags(protocol, fs)
		if err != nil {
			t.Errorf("%s: binding connect flags: %v", protocol, err)
			continue
		}
		fs.VisitAll(func(f *flag.Flag) {
			if value, ok := perturbed(f); ok {
				_ = fs.Set(f.Name, value)
			}
		})
		emitted := options()

		declared := make(map[string]bool, len(specs))
		for _, s := range specs {
			declared[s.Key] = true
			if _, reads := emitted[s.Key]; !reads {
				t.Errorf("%s: client OptSpec declares key %q, which `veepin connect %s` never emits",
					protocol, s.Key, protocol)
			}
		}

		var missing []string
		for key := range emitted {
			if !declared[key] {
				missing = append(missing, key)
			}
		}
		sort.Strings(missing)
		for _, key := range missing {
			t.Errorf("%s: option %q has no client OptSpec — it cannot be set from a profile form", protocol, key)
		}
	}
}

// plausibleValue is a value the given spec's kind will parse. The Required
// guard has to hand each protocol a map it would otherwise accept, or every
// parse fails for the wrong reason and the test proves nothing.
func plausibleValue(sp client.OptSpec) string {
	if sp.Default != "" && sp.Kind != client.OptFilePath {
		return sp.Default
	}
	switch sp.Kind {
	case client.OptInt:
		return "1"
	case client.OptBool:
		return "false"
	case client.OptCIDR:
		return "10.0.0.2/32"
	case client.OptCommaList:
		return "10.0.0.0/8"
	case client.OptFilePath:
		return "/nonexistent/veepin-test"
	default:
		return "veepin-test"
	}
}

// requiredOptions builds the full option map a protocol's spec describes, so
// each key can be removed from it one at a time.
//
// "config" is left out deliberately. openvpn, wireguard and amneziawg accept a
// whole profile file through it, and every other option becomes optional the
// moment one is named — so including it would make the parse tolerate every
// absence and this guard would prove nothing.
func requiredOptions(specs []client.OptSpec) map[string]string {
	out := make(map[string]string, len(specs))
	for _, sp := range specs {
		if sp.Key == "config" {
			continue
		}
		out[sp.Key] = plausibleValue(sp)
	}
	return out
}

// missingKeyError reports whether err reads as "this option was not supplied"
// rather than "this option's value is wrong". The parse functions phrase it as
// "<key> is required" / "<key> and <key> are required", which is the whole
// vocabulary this needs to recognise.
func missingKeyError(err error, key string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "required") && strings.Contains(msg, key)
}

// TestRequiredClientOptsAreTheOnesTheParseRejects catches options the parse
// hard-rejects the absence of while the OptSpec calls them optional. Nothing
// checked this: TestClientOptSpecsMatchTheKeysTheProtocolReads compares key sets
// only, so Required, Secret and Kind sat outside every guard — and three
// protocols under-claimed their password, letting the panel save a profile that
// could not dial and the management plane generate one.
//
// Only "is required"-shaped failures count. A parse that rejects a placeholder
// value for being unparseable is saying something else entirely, and reading
// that as a required-option error would make this test agree with anything.
//
// The converse -- Required set where the parse tolerates absence -- is
// deliberately NOT checked, because it is not a defect. Required is a claim
// about the form ("insist on this"), and a parse can legitimately accept a
// missing value because a profile file supplied it, because another option
// substitutes for it, or because the check happens at dial rather than at
// parse. Asserting it mechanically would mean weakening the flag on protocols
// where it is telling operators something true.
func TestRequiredClientOptsAreTheOnesTheParseRejects(t *testing.T) {
	for _, protocol := range client.Protocols() {
		specs, ok := client.ClientOptsFor(protocol)
		if !ok {
			continue // covered by TestClientOptSpecsMatchTheKeysTheProtocolReads
		}
		full := requiredOptions(specs)
		for _, sp := range specs {
			if sp.Required || sp.Key == "config" {
				continue
			}
			without := maps.Clone(full)
			delete(without, sp.Key)
			if err := client.ValidateOptions(protocol, without); missingKeyError(err, sp.Key) {
				t.Errorf("%s: the parse rejects a config without %q (%v) but the OptSpec does not mark it "+
					"Required — the panel will happily save a profile that cannot dial", protocol, sp.Key, err)
			}
		}
	}
}
