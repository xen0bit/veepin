// Package pq registers "pq-ssh": SSH with the post-quantum contract in
// force. It is the ONE variant that does not carry the full contract: SSH has a
// post-quantum key exchange and no post-quantum signature algorithm anywhere, so
// mlkem768x25519-sha256 is pinned and host keys stay classical.
//
// That exemption is recorded by name in internal/pqpolicy, cites OpenSSH's own
// statement of the gap, and is held at exactly one entry by a test -- so a
// second protocol claiming the same excuse has to argue for it.
//
// It contains no protocol code, and that is the design. The variant injects the
// options that put the base facade into post-quantum-only mode and hands the map
// to ssh's own registered parse function, so every default, every validation,
// every credential path and the whole construction sequence stay in exactly one
// place. A variant that reimplemented any of that would be a second copy of the
// base's surface, drifting from the first.
//
// The same reasoning is why this package declares no OptSpec table:
// client.ServerOptsFor falls back to the base, so `veepin serve pq-ssh`
// renders byte-for-byte the flag set of `veepin serve ssh`.
//
// See doc/pq-variants-plan.md; what pq- guarantees is in internal/pqpolicy.
package pq

import (
	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/pqpolicy"

	_ "github.com/xen0bit/veepin/ssh" // the base this varies
)

const (
	name = "pq-ssh"
	base = "ssh"
)

func init() {
	client.RegisterVariant(name, base, dial)
	client.RegisterServerVariant(name, base, serve)
}

// forced are the options this variant pins beyond the post-quantum marker
// itself. Empty: the marker alone pins the key exchange.
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
