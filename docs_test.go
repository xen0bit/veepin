package veepin

// Keeps the front-page documentation counting the protocols the registry
// actually has.
//
// This has now drifted twice. doc/consolidation-plan.md item 5 was "doc.go
// describes two of nine protocols"; that was fixed to eight, and then MASQUE and
// Fortinet shipped and nobody came back — so the module's own package
// documentation understated what it does, and the README said "nine production
// protocols" while listing ten of them and elsewhere saying "all ten". A count
// in prose has no compiler and no reader who recounts it.
//
// The protocol packages are imported here for their registration side effect
// only. It is a test-only import, so the library keeps its own dependency graph;
// cmd/veepin already imports the same set for the same reason.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"

	_ "github.com/xen0bit/veepin/amneziawg"
	_ "github.com/xen0bit/veepin/anyconnect"
	_ "github.com/xen0bit/veepin/cisco"
	_ "github.com/xen0bit/veepin/fortinet"
	_ "github.com/xen0bit/veepin/gp"
	_ "github.com/xen0bit/veepin/ikev2"
	_ "github.com/xen0bit/veepin/l2tp"
	_ "github.com/xen0bit/veepin/l2tpv3"
	_ "github.com/xen0bit/veepin/masque"
	_ "github.com/xen0bit/veepin/nebula"
	_ "github.com/xen0bit/veepin/openvpn"
	_ "github.com/xen0bit/veepin/pulse"
	_ "github.com/xen0bit/veepin/softether"
	_ "github.com/xen0bit/veepin/ssh"
	_ "github.com/xen0bit/veepin/sstp"
	_ "github.com/xen0bit/veepin/toy"
	_ "github.com/xen0bit/veepin/wireguard"
)

// toyProtocol is registered but is not a real protocol: it provides no security
// and is excluded from the "production protocols" the docs count.
const toyProtocol = "toy"

// productionProtocols is every registered protocol except the teaching example.
func productionProtocols() []string {
	var out []string
	for _, name := range client.Protocols() {
		if name != toyProtocol {
			out = append(out, name)
		}
	}
	return out
}

// TestPackageDocNamesEveryProtocol requires doc.go to mention each registered
// protocol package by name. Checking names rather than a count is what makes it
// useful: adding a protocol and forgetting the docs fails here, naming the one
// that is missing.
func TestPackageDocNamesEveryProtocol(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "doc.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing doc.go: %v", err)
	}
	if file.Doc == nil {
		t.Fatal("doc.go has no package comment")
	}
	doc := file.Doc.Text()

	for _, name := range client.Protocols() {
		if !strings.Contains(doc, name) {
			t.Errorf("doc.go's package comment never mentions the %q package, which is "+
				"registered — the module's own documentation understates what it does",
				name)
		}
	}
}

// numberWords and ordinalWords cover the range a protocol count will plausibly
// occupy. Prose spells numbers out, so the checks have to as well — and the two
// counts are spelled differently: a cardinal for how many there are, an ordinal
// for where TOY sits among them.
var numberWords = map[int]string{
	8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve",
	13: "thirteen", 14: "fourteen", 15: "fifteen", 16: "sixteen",
	17: "seventeen", 18: "eighteen", 19: "nineteen",
}

var ordinalWords = map[int]string{
	8: "eighth", 9: "ninth", 10: "tenth", 11: "eleventh", 12: "twelfth",
	13: "thirteenth", 14: "fourteenth", 15: "fifteenth", 16: "sixteenth",
	17: "seventeenth", 18: "eighteenth", 19: "nineteenth", 20: "twentieth",
}

// countPhrase matches every spelled-out count the README attaches to a phrase,
// so a stale one can be found wherever it sits. Checking with strings.Contains
// would only prove *some* occurrence is right — and the phrase appears more than
// once, which is precisely how the page came to say "nine" in one place and
// "ten" in another.
func countPhrase(phrase string) *regexp.Regexp {
	return regexp.MustCompile(`(\w+) ` + regexp.QuoteMeta(phrase))
}

// assertEveryCount requires each occurrence of "<word> <phrase>" to use want.
func assertEveryCount(t *testing.T, readme, phrase, want, why string) {
	t.Helper()

	matches := countPhrase(phrase).FindAllStringSubmatch(readme, -1)
	if len(matches) == 0 {
		t.Errorf("README.md never says %q %s; %s", want, phrase, why)
		return
	}
	for _, m := range matches {
		if m[1] != want {
			t.Errorf("README.md says %q, want %q %s — %s", m[0], want, phrase, why)
		}
	}
}

// TestREADMECountsProtocolsCorrectly pins the prose counts on the front page
// against the registry: the production protocols, and TOY's ordinal among all
// registered ones. Every occurrence has to agree, not just one.
func TestREADMECountsProtocolsCorrectly(t *testing.T) {
	body, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	readme := string(body)

	production := len(productionProtocols())
	word, ok := numberWords[production]
	if !ok {
		t.Fatalf("no spelled-out word for %d protocols; extend numberWords", production)
	}
	assertEveryCount(t, readme, "production protocols", word,
		fmt.Sprintf("there are %d: %v", production, productionProtocols()))

	// TOY is registered too, so its ordinal is one past the production count.
	toyWord, ok := ordinalWords[production+1]
	if !ok {
		t.Fatalf("no spelled-out ordinal for %d; extend ordinalWords", production+1)
	}
	assertEveryCount(t, readme, "registered protocol", toyWord,
		"TOY is registered alongside the production protocols")

	assertBareProtocolCounts(t, readme, production)
}

// bareProtocolCount matches a spelled-out number immediately before the word
// "protocols", wherever it sits and whatever follows.
//
// This is the wider anchor. assertEveryCount above keys on the exact phrases
// "production protocols" and "registered protocol", so three counts in the
// prose were invisible to it and all three had gone stale: "the other nine
// protocols" (fifteen), "one of the ten real protocols" (sixteen), and "seven
// of the nine protocols" (twelve of sixteen). The failure was not that the
// numbers were wrong when written. It was that nothing was watching them.
var bareProtocolCount = regexp.MustCompile(`(\w+) (?:real |production |registered )?protocols`)

// spelledOutNumbers is every word bareProtocolCount should treat as a count.
// Anything else before "protocols" is ordinary English ("transport protocols",
// "SSL-based protocols") and is not this guard's business -- which is why the
// check keys on this set rather than on a list of words to ignore. An
// ignore-list would have to grow with the prose; this one grows only if someone
// writes a bigger number.
var spelledOutNumbers = map[string]bool{
	"one": true, "two": true, "three": true, "four": true, "five": true,
	"six": true, "seven": true, "eight": true, "nine": true, "ten": true,
	"eleven": true, "twelve": true, "thirteen": true, "fourteen": true,
	"fifteen": true, "sixteen": true, "seventeen": true, "eighteen": true,
	"nineteen": true, "twenty": true,
}

// subsetProtocolCounts are the spelled-out counts that legitimately differ from
// the registry's, because they count a subset. Each entry names the subset, so
// that an exemption is a claim someone has to write down and can be checked by
// reading -- rather than a number that was quietly allowed through.
//
// Every one of these was stale when this guard was written, which is the point:
// the numbers were right when typed and nothing was watching them afterwards.
var subsetProtocolCounts = map[string]string{
	"fifteen": "the protocols that reach no further than x/crypto (all but MASQUE)",
	"twelve":  "the protocols that register a shaping option",
}

// assertBareProtocolCounts requires a spelled-out number before "protocols" to
// be either the registry count or a subset subsetProtocolCounts names.
func assertBareProtocolCounts(t *testing.T, readme string, production int) {
	t.Helper()
	want := numberWords[production]
	for _, m := range bareProtocolCount.FindAllStringSubmatch(readme, -1) {
		word := strings.ToLower(m[1])
		if !spelledOutNumbers[word] || word == want {
			continue
		}
		if subset, ok := subsetProtocolCounts[word]; ok {
			t.Logf("%q counts %s, not the registry", m[0], subset)
			continue
		}
		t.Errorf("README.md says %q, and %q is neither the registry count (%q) nor a "+
			"subset subsetProtocolCounts names. Either the number is stale, or add it "+
			"there saying what subset it counts.", m[0], word, want)
	}
}

// TestEveryOptConstIsDescribedByAnOptSpec closes the hole the flag-driven
// guards cannot see. TestClientOptSpecsMatchTheKeysTheProtocolReads compares a
// facade's spec table against what connectFlags emits, and its doc comment
// calls that "by construction, what the protocol reads" -- but an option the
// parse reads for which no flag exists is absent from BOTH sides, so the two
// agree and the key is invisible.
//
// That is not hypothetical: wireguard.OptListenPort is read on the client path
// by Config.applyOverrides and had no flag and no client OptSpec, so a profile
// could carry it, the dial would honour it, and the panel could neither show
// nor set it.
//
// The check is on the source rather than the registry because the registry
// stores strings: OptListenPort and OptServerListenPort are both "listen-port",
// so a by-value check would find the server's entry and call it covered. What
// has to hold is that every Opt* CONSTANT a facade declares is named as a Key
// in one of that facade's two OptSpec tables.
func TestEveryOptConstIsDescribedByAnOptSpec(t *testing.T) {
	for _, proto := range client.Protocols() {
		declared, used, err := optConstsAndSpecKeys(proto)
		if err != nil {
			t.Errorf("%s: %v", proto, err)
			continue
		}
		var missing []string
		for name := range declared {
			if !used[name] {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		for _, name := range missing {
			t.Errorf("%s: the facade declares %s but no OptSpec table names it as a Key — "+
				"the parse may read it while the panel, the profile form and -set cannot reach it",
				proto, name)
		}
	}
}

// optConstsAndSpecKeys parses one facade package and returns the names of every
// Opt* constant it declares and the names of every identifier it uses as an
// OptSpec Key.
func optConstsAndSpecKeys(proto string) (declared, used map[string]bool, err error) {
	entries, err := os.ReadDir(proto)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", proto, err)
	}
	// Files are parsed one at a time rather than with parser.ParseDir, which is
	// deprecated, and the alternative it points at (x/tools/go/packages) is a
	// dependency this module does not take.
	fset := token.NewFileSet()
	declared, used = map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(proto, name), nil, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing %s/%s: %w", proto, name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.ValueSpec:
				for _, id := range v.Names {
					if strings.HasPrefix(id.Name, "Opt") && id.Name != "Opt" {
						declared[id.Name] = true
					}
				}
			case *ast.KeyValueExpr:
				// The `Key: OptFoo` field of a client.OptSpec literal.
				k, ok := v.Key.(*ast.Ident)
				if !ok || k.Name != "Key" {
					return true
				}
				if id, ok := v.Value.(*ast.Ident); ok {
					used[id.Name] = true
				}
			case *ast.CallExpr:
				// A shared-spec helper: client.TUNOpt(OptTUN),
				// client.ShapeOpt(OptShape, "upstream"). Its first argument is
				// the key, so it covers the const exactly as a literal Key
				// field does. Matching on the "...Opt" suffix rather than a
				// fixed list means a helper added later is covered without
				// anyone remembering to come back here -- and forgetting would
				// take this guard's whole coverage of that option away
				// silently, which is the failure it exists to prevent.
				sel, ok := v.Fun.(*ast.SelectorExpr)
				if !ok || !strings.HasSuffix(sel.Sel.Name, "Opt") || len(v.Args) == 0 {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "client" {
					return true
				}
				if id, ok := v.Args[0].(*ast.Ident); ok {
					used[id.Name] = true
				}
			}
			return true
		})
	}
	return declared, used, nil
}
