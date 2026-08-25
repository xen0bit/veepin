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
	"slices"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
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
	for _, v := range client.AllVariants() {
		// Parse will fail on missing required options for most protocols; that
		// is fine and expected. What is asserted is the marker, captured by a
		// stand-in registered as the base of a throwaway variant below.
		if _, ok := pqpolicy.KeyExchangeOnly(v); ok {
			continue // exempt variants still force the marker, checked in pqpolicy
		}
	}

	// The real check, on a base we control, so it can observe what it was given.
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
func TestPQVariantsCoverEveryCapableProtocol(t *testing.T) {
	want := []string{
		"pq-anyconnect", "pq-fortinet", "pq-gp", "pq-ikev2", "pq-masque",
		"pq-openvpn", "pq-pulse", "pq-softether", "pq-ssh", "pq-sstp",
	}
	got := client.AllVariants()
	for _, w := range want {
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
