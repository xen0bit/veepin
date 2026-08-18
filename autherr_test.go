package veepin

// A protocol that judges a credential must say so when it refuses one.
//
// client.ErrAuth is not decoration. Two callers branch on it and both do
// something harmful without it:
//
//   - `veepin connect -retry` treats an auth failure as permanent and stops.
//     Everything else it retries with backoff, forever by default. A protocol
//     that reports a wrong password as an ordinary error therefore replays that
//     password every sixty seconds against a server that counts failures --
//     ocserv, SoftEther, FortiOS and sshd all lock out or ban on exactly that.
//   - The NetworkManager plugin maps it to NM's LoginFailed, which is what makes
//     NM re-prompt. Without it a typo in the password is reported to the user as
//     a broken network, and the prompt that would let them fix it never appears.
//
// Neither failure is visible from inside the protocol package, which is why this
// guard is here and not there: thirteen of sixteen facades were missing the
// mapping when it was written, every one of them tested and green.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
)

// noCredentialJudged names the protocols whose Dial declares a Secret option and
// still cannot produce client.ErrAuth, with the reason. A Secret option is the
// marker this guard keys on -- it is the tree's own record of what counts as
// key material -- but holding key material and *judging a credential* are not
// the same thing, and these four are the difference.
//
// Adding a protocol here is a decision, not a formality. The question to answer
// is: can this protocol's Dial return because a peer refused what we presented?
// If it can, the entry does not belong here.
var noCredentialJudged = map[string]string{
	"l2tpv3": "no authentication at all -- the cookie is a check value the receiver " +
		"chooses, not a credential, and a wrong one is a framing error",
	"amneziawg": "the whole of its Dial is wireguard.Dial, which maps noise.ErrDecrypt " +
		"itself; the obfuscation layer changes what packets look like and not what " +
		"authenticates them",
	"nebula": "Dial starts a mesh host and returns; it completes no handshake, so a " +
		"certificate a peer rejects (inebula.ErrPeerRejected) surfaces later in the " +
		"host's log and can never be a Dial error",
	"openvpn": "maps client.ErrAuth directly rather than through WrapAuth, in two " +
		"places -- see openvpn.go's isTLSAuthError branch and session.go's " +
		"AUTH_FAILED. Listed so the scan below stays a scan and not a special case",
}

// TestEveryProtocolJudgingACredentialReportsErrAuth requires each facade that
// takes a secret to reference client.ErrAuth or client.WrapAuth somewhere in its
// package, or to be named above with the reason it cannot.
//
// It is a source scan, deliberately. Proving the mapping behaviourally needs a
// server that refuses a login, which is a per-protocol harness; what actually
// went wrong here was simpler and this catches it -- a facade that returns the
// engine's error untouched, so nothing anywhere mentions ErrAuth. The
// behavioural half lives beside each engine, where a rejecting peer already
// exists (internal/softether's e2e_test.go has four of them).
func TestEveryProtocolJudgingACredentialReportsErrAuth(t *testing.T) {
	for _, proto := range client.Protocols() {
		specs, ok := client.ClientOptsFor(proto)
		if !ok {
			continue
		}
		var secrets []string
		for _, s := range specs {
			if s.Secret {
				secrets = append(secrets, s.Key)
			}
		}
		if len(secrets) == 0 {
			if _, listed := noCredentialJudged[proto]; listed {
				t.Errorf("%s: listed as judging no credential, but it declares no secret "+
					"option either — the entry is unnecessary", proto)
			}
			continue
		}
		if _, exempt := noCredentialJudged[proto]; exempt {
			continue
		}
		refs, err := authRefs(proto)
		if err != nil {
			t.Errorf("%s: %v", proto, err)
			continue
		}
		if len(refs) == 0 {
			sort.Strings(secrets)
			t.Errorf("%s: takes secret option(s) %v and never mentions client.ErrAuth or "+
				"client.WrapAuth — a rejected credential would reach the caller as an "+
				"ordinary error, so -retry replays it until the account locks out and "+
				"NetworkManager reports a dead network instead of prompting. Map the "+
				"engine's own auth sentinel with client.WrapAuth, or name %s in "+
				"noCredentialJudged with the reason it judges no credential",
				proto, secrets, proto)
		}
	}
}

// TestNoCredentialJudgedNamesOnlyRegisteredProtocols keeps the exemption list
// from outliving what it exempts. An entry for a protocol that has since gained
// an auth path, or been renamed, is worse than no entry: it silently suppresses
// the check for a name nobody is looking at.
func TestNoCredentialJudgedNamesOnlyRegisteredProtocols(t *testing.T) {
	registered := map[string]bool{}
	for _, p := range client.Protocols() {
		registered[p] = true
	}
	for proto, reason := range noCredentialJudged {
		if !registered[proto] {
			t.Errorf("noCredentialJudged names %q, which is not a registered protocol", proto)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("noCredentialJudged[%q] has no reason; the reason is the point", proto)
		}
	}
}

// authRefs returns the client.ErrAuth / client.WrapAuth selector expressions one
// facade package uses. Files are parsed one at a time for the same reason
// docs_test.go does it: parser.ParseDir is deprecated and its replacement is a
// dependency this module does not take.
func authRefs(proto string) ([]string, error) {
	entries, err := os.ReadDir(proto)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var refs []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(proto, name), nil, 0)
		if err != nil {
			return nil, err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "client" {
				return true
			}
			if sel.Sel.Name == "ErrAuth" || sel.Sel.Name == "WrapAuth" {
				refs = append(refs, sel.Sel.Name)
			}
			return true
		})
	}
	return refs, nil
}
