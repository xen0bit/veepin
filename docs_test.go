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
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"

	_ "github.com/xen0bit/veepin/anyconnect"
	_ "github.com/xen0bit/veepin/cisco"
	_ "github.com/xen0bit/veepin/fortinet"
	_ "github.com/xen0bit/veepin/gp"
	_ "github.com/xen0bit/veepin/ikev2"
	_ "github.com/xen0bit/veepin/l2tp"
	_ "github.com/xen0bit/veepin/masque"
	_ "github.com/xen0bit/veepin/nebula"
	_ "github.com/xen0bit/veepin/openvpn"
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
	13: "thirteen", 14: "fourteen", 15: "fifteen",
}

var ordinalWords = map[int]string{
	8: "eighth", 9: "ninth", 10: "tenth", 11: "eleventh", 12: "twelfth",
	13: "thirteenth", 14: "fourteenth", 15: "fifteenth",
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
}
