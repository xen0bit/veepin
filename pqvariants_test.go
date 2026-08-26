package veepin

// The guards for the pq- variant scheme.
//
// A variant makes two claims that nothing else in the tree checks. The first is
// that it is the SAME protocol -- same options, same flags, same everything an
// operator types -- so that `pq-sstp` is not a second surface to learn or to
// keep in sync. The second is that it REFUSES what its base accepts, which is
// the entire reason the name exists.
//
// Both claims are the kind that stay true right up until someone adds a
// variant-specific option "just for this one", or wires a facade's
// PostQuantumOnly field to nothing. Neither mistake breaks a build.

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/keygen"
	"github.com/xen0bit/veepin/internal/pqpolicy"

	_ "github.com/xen0bit/veepin/anyconnect/pq"
	_ "github.com/xen0bit/veepin/fortinet/pq"
	_ "github.com/xen0bit/veepin/gp/pq"
	_ "github.com/xen0bit/veepin/ikev2/pq"
	_ "github.com/xen0bit/veepin/masque/pq"
	_ "github.com/xen0bit/veepin/openvpn/pq"
	_ "github.com/xen0bit/veepin/pulse/pq"
	_ "github.com/xen0bit/veepin/softether/pq"
	_ "github.com/xen0bit/veepin/ssh/pq"
	_ "github.com/xen0bit/veepin/sstp/pq"
)

// TestEveryVariantIsNamedForItsBase pins the naming convention, because the
// scheme's whole usability rests on a reader being able to guess the name.
func TestEveryVariantIsNamedForItsBase(t *testing.T) {
	for _, v := range client.AllVariants() {
		base := client.BaseOf(v)
		if base == "" {
			t.Errorf("variant %q has no base", v)
			continue
		}
		if want := "pq-" + base; v != want {
			t.Errorf("variant %q varies %q; the convention is %q", v, base, want)
		}
		if slices.Contains(client.Protocols(), v) {
			t.Errorf("variant %q is also a registered protocol, which would make it "+
				"count towards the README's protocol total", v)
		}
	}
}

// TestVariantsAreNotCountedAsProtocols is the guard behind the README staying
// at "sixteen". productionProtocols() is Protocols() minus toy, so a variant
// that leaked into Protocols() would silently inflate every spelled-out count
// on the front page -- and TestREADMECountsProtocolsCorrectly would then demand
// the prose be changed to match, which is exactly the wrong fix.
func TestVariantsAreNotCountedAsProtocols(t *testing.T) {
	if len(client.AllVariants()) == 0 {
		t.Fatal("no variants registered; the blank imports above are not doing their job")
	}
	for _, name := range client.Protocols() {
		if strings.HasPrefix(name, "pq-") {
			t.Errorf("%q is in Protocols(), so it counts as a production protocol. "+
				"A pq- name is a floor under an existing protocol, not a new one.", name)
		}
	}
}

// TestEveryVariantResolvesItsBaseOptSpecs is the one that keeps a variant from
// becoming a second surface. The specs must be IDENTICAL, not merely present:
// an extra row would render an extra form field in the panel and an extra flag
// on the command line, both of which the base would not have.
func TestEveryVariantResolvesItsBaseOptSpecs(t *testing.T) {
	for _, v := range client.AllVariants() {
		base := client.BaseOf(v)

		vs, vok := client.ClientOptsFor(v)
		bs, bok := client.ClientOptsFor(base)
		if vok != bok || !slices.Equal(vs, bs) {
			t.Errorf("%s: client OptSpecs differ from %s (%d vs %d). A variant declares no "+
				"table of its own; ClientOptsFor must fall back to the base.", v, base, len(vs), len(bs))
		}

		vs, vok = client.ServerOptsFor(v)
		bs, bok = client.ServerOptsFor(base)
		if vok != bok || !slices.Equal(vs, bs) {
			t.Errorf("%s: server OptSpecs differ from %s (%d vs %d).", v, base, len(vs), len(bs))
		}
	}
}

// TestEveryVariantForcesThePostQuantumMarker drives each variant's registered
// parse the way the CLI would and requires the marker to reach the options the
// base sees. Without this a variant could register, resolve, generate flags and
// dial -- and enforce nothing at all.
func TestEveryVariantForcesThePostQuantumMarker(t *testing.T) {
	// The check runs against a base we control, so it can observe exactly what
	// it was handed. Driving the real facades instead would prove less: their
	// parse functions reject missing required options long before the marker
	// could be inspected.
	var seen map[string]string
	client.Register("pqguard", func(opts map[string]string) (client.Dialer, error) {
		seen = opts
		return nil, errNotADialer
	})
	client.RegisterVariant("pq-pqguard", "pqguard", func(opts map[string]string) (client.Dialer, error) {
		o, err := pqpolicy.Force("pq-pqguard", opts, nil)
		if err != nil {
			return nil, err
		}
		return client.ParseWithBase("pqguard", o)
	})

	if err := client.ValidateOptions("pq-pqguard", map[string]string{"user": "alice"}); err == nil {
		t.Fatal("the stand-in base should have refused")
	}
	if !pqpolicy.Requested(seen) {
		t.Errorf("the variant did not set %s in the options the base received: %v",
			pqpolicy.OptKey, seen)
	}
	if seen["user"] != "alice" {
		t.Errorf("the variant did not pass the operator's own options through: %v", seen)
	}
}

// errNotADialer is what the stand-in base returns; it never dials.
var errNotADialer = errStr("pqguard: this base exists only to observe its options")

type errStr string

func (e errStr) Error() string { return string(e) }

// TestPQVariantsCoverEveryCapableProtocol is the completeness check, and it is
// written as an explicit expectation rather than derived from the registry --
// deriving it from the registry would make it tautological.
//
// The protocols NOT here cannot carry the contract, and each absence is a
// structural fact rather than a backlog item:
//
//	wireguard, amneziawg  Noise_IKpsk2 fixes X25519 and negotiates nothing;
//	                      Rosenpass needs round-3 Kyber and Classic McEliece,
//	                      neither of which is reachable (doc/rosenpass-plan.md).
//	nebula                plain Noise_IX, and its PSK machinery is inert.
//	cisco, l2tp           IKEv1, which has no additional-key-exchange mechanism.
//	l2tpv3                no cryptography at all, by design.
//	toy                   deliberately insecure teaching example.
//
// pqVariants is also what the guards further down iterate, in preference to
// client.AllVariants(). That is not tidiness either: the marker test above
// registers a stand-in variant ("pq-pqguard") into the process-wide registry and
// never unregisters it, because the registry has no way to. A guard reading the
// live registry therefore picks it up, goes looking for a pqguard/ package, and
// fails for a reason that has nothing to do with the code under test.
var pqVariants = []string{
	"pq-anyconnect", "pq-fortinet", "pq-gp", "pq-ikev2", "pq-masque",
	"pq-openvpn", "pq-pulse", "pq-softether", "pq-ssh", "pq-sstp",
}

func TestPQVariantsCoverEveryCapableProtocol(t *testing.T) {
	got := client.AllVariants()
	for _, w := range pqVariants {
		if !slices.Contains(got, w) {
			t.Errorf("%s is not registered", w)
		}
	}

	// And the ones that must NOT exist, so that adding pq-wireguard requires
	// deleting a line here and arguing with the comment above it.
	for _, impossible := range []string{
		"pq-wireguard", "pq-amneziawg", "pq-nebula", "pq-cisco",
		"pq-l2tp", "pq-l2tpv3", "pq-toy",
	} {
		if slices.Contains(got, impossible) {
			t.Errorf("%s is registered, but that protocol cannot carry a post-quantum "+
				"contract. See the comment above this test.", impossible)
		}
	}
}

// The two guards doc/pq-variants-plan.md §9 listed as owed and nobody wrote.
//
// Between them they answer the question the variant scheme rests on: does the
// name actually change what the facade does? Everything above this point checks
// the plumbing -- that the marker is set, that the specs resolve, that the name
// is not counted as a protocol -- and all of it would keep passing against ten
// facades that read the marker and ignored it.

// pqCredentialGenerators maps a variant to the keygen type that mints a
// credential its server role will accept, derived from the option keys the
// server declares rather than listed by hand.
//
// A variant absent from the result is named in pqNoCredentialCheck below, with
// the reason. That is the same shape autherr_test.go's noCredentialJudged uses,
// and for the same reason: the interesting facts are the exceptions, and an
// exception should have to be written down.
func pqCredentialGenerator(variant string) (genType string, ok bool) {
	specs, ok := client.ServerOptsFor(variant)
	if !ok {
		return "", false
	}
	// REQUIRED, not merely declared. ikev2 offers cert and key as an optional
	// alternative to a PSK and requires neither, so keying on their presence
	// would put it in this loop and then fail it for a reason that is not about
	// post-quantum at all.
	var hasCA, hasCert, hasKey bool
	for _, sp := range specs {
		if !sp.Required {
			continue
		}
		switch sp.Key {
		case "ca":
			hasCA = true
		case "cert":
			hasCert = true
		case "key":
			hasKey = true
		}
	}
	if !hasCert || !hasKey {
		return "", false
	}
	// OpenVPN is the mutual-TLS one and declares a "ca" option; the SSL-VPN
	// family does not. genChain writes a different file set for each.
	if hasCA {
		return "x509-chain", true
	}
	return "tls", true
}

// pqNoCredentialCheck names the variants whose server does NOT run
// pqpolicy.CheckCredential, and why. Both reasons are structural.
var pqNoCredentialCheck = map[string]string{
	"pq-ikev2": "IKEv2 is not TLS: the AUTH payload carries the signature, and the " +
		"refusal lives in the IKE engine as RequirePostQuantumAuth rather than in a " +
		"credential check at construction. internal/ikev2/ike/pqauth_test.go covers it, " +
		"and a real strongSwan initiator does in TestInteropPQIKEv2ServerRefusesAClassicalPeer.",
	"pq-ssh": "SSH has no post-quantum signature algorithm anywhere, so there is no " +
		"post-quantum credential to demand. This is the single named exception in " +
		"pqpolicy.SSHKeyExchangeOnly; see TestSSHIsTheOnlyPQAuthException.",
}

// pqExtraServerOpts are options a variant's server needs beyond its credential
// before the parse will reach the credential check at all.
//
// Every one of them is a user database. The SSL-VPN family authenticates its
// users by password inside the tunnel and validates that before it looks at the
// certificate, so without these the parse returns "user and pass are required"
// and the guard would be asserting that a missing password is a classical
// credential -- which is how a test agrees with anything.
var pqExtraServerOpts = map[string]map[string]string{
	"pq-anyconnect": {"user": "alice", "pass": "s3cret"},
	"pq-fortinet":   {"user": "alice", "pass": "s3cret"},
	"pq-gp":         {"user": "alice", "pass": "s3cret"},
	"pq-pulse":      {"user": "alice", "pass": "s3cret"},
	"pq-softether":  {"user": "alice", "pass": "s3cret"},
	"pq-sstp":       {"user": "alice", "pass": "s3cret"},
}

// TestPQServerRefusesAClassicalCredential is the behavioural half: point a pq-
// server at an ECDSA certificate and it must refuse, at construction, before
// the TUN is opened and before anything binds.
//
// The precondition is what stops this being vacuous, and it is not the obvious
// one. The same option map with an ML-DSA credential does NOT succeed here --
// it gets as far as dataplane.OpenTUN and fails for want of CAP_NET_ADMIN,
// which is correct and is exactly the signal wanted: it proves the credential
// was accepted and the parse got PAST the check. Asserting a successful
// construction instead would make the test require root and skip in CI, which
// is the failure mode where a guard quietly covers nothing.
func TestPQServerRefusesAClassicalCredential(t *testing.T) {
	checked := 0
	for _, variant := range pqVariants {
		genType, ok := pqCredentialGenerator(variant)
		if !ok {
			if _, named := pqNoCredentialCheck[variant]; !named {
				t.Errorf("%s declares no cert/key server option and is not named in "+
					"pqNoCredentialCheck; if its server judges no credential, say so there "+
					"with the reason", variant)
			}
			continue
		}
		if reason, named := pqNoCredentialCheck[variant]; named {
			t.Errorf("%s is named in pqNoCredentialCheck (%q) but requires cert and key "+
				"server options, so the exception no longer describes it", variant, reason)
			continue
		}

		t.Run(variant, func(t *testing.T) {
			classical := pqServerOpts(t, variant, genType, false)
			err := newServerIgnoringTUN(variant, classical)
			if !errors.Is(err, pqpolicy.ErrClassicalCredential) {
				t.Fatalf("an ECDSA credential was not refused: got %v, want %v",
					err, pqpolicy.ErrClassicalCredential)
			}

			// The precondition: the same map with ML-DSA must get past the
			// credential check. Without this the test would pass against a
			// facade that refused every credential, post-quantum or not.
			postQuantum := pqServerOpts(t, variant, genType, true)
			if err := newServerIgnoringTUN(variant, postQuantum); errors.Is(err, pqpolicy.ErrClassicalCredential) {
				t.Fatalf("an ML-DSA-65 credential was ALSO refused as classical (%v); the "+
					"refusal above proves nothing about the algorithm", err)
			}
		})
		checked++
	}
	// Ten variants, two structural exceptions. If this ever reads zero the loop
	// has stopped covering anything and every assertion above is unreachable.
	if want := len(pqVariants) - len(pqNoCredentialCheck); checked != want {
		t.Errorf("checked %d variants, want %d", checked, want)
	}
}

// pqServerOpts builds a server option map for variant, with a freshly minted
// credential that is ML-DSA-65 when postQuantum and ECDSA P-256 otherwise.
func pqServerOpts(t *testing.T, variant, genType string, postQuantum bool) map[string]string {
	t.Helper()
	opts, err := keygen.Generate("listener", t.TempDir(),
		keygen.PostQuantumType(genType, postQuantum), "cert", nil)
	if err != nil {
		t.Fatalf("generating a %s credential: %v", genType, err)
	}
	maps.Copy(opts, pqExtraServerOpts[variant])
	return opts
}

// newServerIgnoringTUN calls the registry's server parse and closes whatever it
// got, so a run WITH CAP_NET_ADMIN does not leak a TUN per variant.
//
// The error is returned unexamined. Construction failing at the TUN is the
// expected outcome for the post-quantum case in an unprivileged process, and
// distinguishing that from any other late failure is not this guard's business:
// it asks one question, whether the error is ErrClassicalCredential.
func newServerIgnoringTUN(variant string, opts map[string]string) error {
	srv, err := client.NewServer(variant, opts)
	if srv != nil {
		if c, ok := srv.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}
	return err
}

// TestEveryPQVariantAppliesThePolicyInBothRoles is the source-level half, and it
// covers the failure the behavioural test above cannot reach: a facade that
// reads pqpolicy.Requested into a PostQuantumOnly field and then never consults
// it.
//
// There is no seam to test that through. Each facade builds its tls.Config
// internally and hands it straight to the handshake, so a role that quietly
// stopped hardening is indistinguishable from one that did -- until it meets a
// classical peer, in production. pqtls_test.go's
// TestNoTLSConfigPinsCurvePreferences answers the mirror-image question the same
// way, by reading the source, and for the same reason.
//
// It asks the question per ROLE, by walking the package's own call graph out
// from Dial and from NewServer, and that is the whole design rather than
// tidiness. Written against the package as a whole it passed while
// `veepin serve pq-openvpn` accepted a classical peer, an RSA certificate and
// TLS 1.2: openvpn/openvpn.go hardened the dialler, openvpn/server.go declared
// PostQuantumOnly and never read it, and one call in the package satisfied a
// check that asked whether the package called it at all. The client cell and
// the self cell both passed, because the client half was correct and the self
// cell drove it from both ends.
//
// Reachability rather than "is this string in server.go", because the file
// layout is not uniform: softether has no server.go at all -- both roles live in
// softether.go -- and openvpn's server builds its config in serverTLSConfig, two
// calls down. A filename rule would have excused the first and a same-function
// rule would have missed the second.
func TestEveryPQVariantAppliesThePolicyInBothRoles(t *testing.T) {
	for _, variant := range pqVariants {
		base := client.BaseOf(variant)
		if base == "" {
			continue // TestEveryVariantIsNamedForItsBase reports this
		}
		if reason, named := pqPolicyExemptFacades[base]; named {
			t.Logf("%s: not TLS, exempt from HardenTLS — %s", variant, reason)
			continue
		}
		reaches := pqCallsReachableFrom(t, base)
		if !reaches["Dial"]["pqpolicy.HardenTLS"] {
			t.Errorf("%s: the CLIENT role of %q never calls pqpolicy.HardenTLS. The variant "+
				"would set the marker, the facade would read it into PostQuantumOnly, and "+
				"the handshake would negotiate exactly what it negotiates today.", variant, base)
		}
		if !reaches["NewServer"]["pqpolicy.HardenTLS"] {
			t.Errorf("%s: the SERVER role of %q never calls pqpolicy.HardenTLS, so "+
				"`veepin serve %s` would accept a classical peer and TLS 1.2", variant, base, variant)
		}
		if !reaches["NewServer"]["pqpolicy.CheckCredential"] {
			t.Errorf("%s: the SERVER role of %q never calls pqpolicy.CheckCredential, so it "+
				"would start on an RSA certificate and refuse every client afterwards",
				variant, base)
		}
	}
}

// pqPolicyExemptFacades names the two bases that carry the contract without
// crypto/tls, so requiring HardenTLS of them would be requiring the wrong thing.
var pqPolicyExemptFacades = map[string]string{
	"ikev2": "IKEv2 negotiates its own key exchange and carries its signature in the " +
		"AUTH payload; the refusal is RequirePostQuantum/RequirePostQuantumAuth in " +
		"internal/ikev2/ike",
	"ssh": "SSH negotiates its own key exchange; the refusal is pinning " +
		"pqpolicy.SSHKeyExchanges onto the ssh.Config's KeyExchanges",
}

// pqCallsReachableFrom walks a facade package's internal call graph out from
// each of its two entry points and reports which pqpolicy calls each can reach.
//
// Package-local calls only, which is exactly the scope wanted: a facade delegates
// its TLS setup to its own unexported helper (openvpn's serverTLSConfig,
// masque's inline block) and nothing here needs to follow a call into another
// package. Selector calls are recorded by their full "pkg.Func" spelling so
// "pqpolicy.HardenTLS" is what the caller asks about.
func pqCallsReachableFrom(t *testing.T, pkg string) map[string]map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, pkg, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", pkg, err)
	}

	// funcName -> the set of things its body calls, by local name for a
	// package-local function and "pkg.Func" for a selector.
	calls := map[string]map[string]bool{}
	for _, astPkg := range pkgs {
		for _, file := range astPkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				// Methods and functions share a namespace here. That is
				// imprecise and harmless: a false edge can only make a call
				// look REACHABLE, and every assertion below is that something
				// is reachable, so imprecision cannot manufacture a pass for a
				// facade that calls nothing.
				out := calls[fn.Name.Name]
				if out == nil {
					out = map[string]bool{}
					calls[fn.Name.Name] = out
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch f := call.Fun.(type) {
					case *ast.Ident:
						out[f.Name] = true
					case *ast.SelectorExpr:
						if x, ok := f.X.(*ast.Ident); ok {
							out[x.Name+"."+f.Sel.Name] = true
						}
					}
					return true
				})
			}
		}
	}

	out := map[string]map[string]bool{}
	for _, entry := range []string{"Dial", "NewServer"} {
		if _, ok := calls[entry]; !ok {
			t.Fatalf("%s declares no %s; this check covers nothing for that role", pkg, entry)
		}
		out[entry] = reachable(calls, entry)
	}
	return out
}

// reachable returns everything callable from entry, transitively, within calls.
func reachable(calls map[string]map[string]bool, entry string) map[string]bool {
	seen := map[string]bool{}
	queue := []string{entry}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		for callee := range calls[name] {
			if seen[callee] {
				continue
			}
			seen[callee] = true
			if _, local := calls[callee]; local {
				queue = append(queue, callee)
			}
		}
	}
	return seen
}

// packageSource concatenates the non-test .go files of a facade package.
func packageSource(t *testing.T, pkg string) string {
	t.Helper()
	entries, err := os.ReadDir(pkg)
	if err != nil {
		t.Fatalf("reading %s: %v", pkg, err)
	}
	var b strings.Builder
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(pkg, name))
		if err != nil {
			t.Fatalf("reading %s/%s: %v", pkg, name, err)
		}
		b.Write(body)
	}
	if b.Len() == 0 {
		t.Fatalf("%s has no non-test Go source; this check covers nothing", pkg)
	}
	return b.String()
}

// TestEveryVariantAnnouncesItsContract requires every variant to call
// pqpolicy.Announce in both roles.
//
// The line is not decoration. It is what an operator reads to tell a pq- process
// from its base at runtime, and it is what the ten veepin<->veepin interop cells
// assert on -- and those cells need it badly, because both ends of a self cell
// apply the same policy from the same package. If the hardening silently stopped
// applying, both would drop to a classical handshake, agree with each other
// perfectly, and the ping would pass. See runInteropPQSelf.
func TestEveryVariantAnnouncesItsContract(t *testing.T) {
	for _, variant := range pqVariants {
		base := client.BaseOf(variant)
		if base == "" {
			continue
		}
		src := packageSource(t, filepath.Join(base, "pq"))
		if n := strings.Count(src, "pqpolicy.Announce("); n != 2 {
			t.Errorf("%s/pq calls pqpolicy.Announce %d times, want 2 (once in dial, once "+
				"in serve). Without it the variant is invisible in the process log and "+
				"its interop cell has nothing to assert on.", base, n)
		}
	}
}
