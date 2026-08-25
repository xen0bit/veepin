// Package pq registers "pq-pulse": Ivanti Connect Secure with the post-quantum contract in
// force -- ML-KEM key exchange and ML-DSA authentication, with anything less
// refused rather than negotiated down.
//
// It contains no protocol code, and that is the design. The variant injects the
// options that put the base facade into post-quantum-only mode and hands the map
// to pulse's own registered parse function, so every default, every validation,
// every credential path and the whole construction sequence stay in exactly one
// place. A variant that reimplemented any of that would be a second copy of the
// base's surface, drifting from the first.
//
// The same reasoning is why this package declares no OptSpec table:
// client.ServerOptsFor falls back to the base, so `veepin serve pq-pulse`
// renders byte-for-byte the flag set of `veepin serve pulse`.
//
// See doc/pq-variants-plan.md; what pq- guarantees is in internal/pqpolicy.
package pq

import (
	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/pqpolicy"

	_ "github.com/xen0bit/veepin/pulse" // the base this varies
)

const (
	name = "pq-pulse"
	base = "pulse"
)

func init() {
	client.RegisterVariant(name, base, dial)
	client.RegisterServerVariant(name, base, serve)
}

// forced are the options this variant pins beyond the post-quantum marker
// itself. Ivanti pushes its ESP keys inside the TLS
// session, so the data path inherits the raised floor with no extra pinning.
var forced = map[string]string(nil)

func dial(opts map[string]string) (client.Dialer, error) {
	o, err := pqpolicy.Force(name, opts, forced)
	if err != nil {
		return nil, err
	}
	return client.ParseWithBase(base, o)
}

func serve(opts map[string]string) (client.Server, error) {
	o, err := pqpolicy.Force(name, opts, forced)
	if err != nil {
		return nil, err
	}
	return client.ParseServerWithBase(base, o)
}
