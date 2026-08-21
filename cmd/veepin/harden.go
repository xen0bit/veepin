package main

import (
	"flag"

	"github.com/xen0bit/veepin/internal/harden"
)

// hardenFlags are the process-hardening switches, bound on `serve`.
//
// They are off by default and that is deliberate. Both trade something real --
// mlockall makes the resident set unswappable, PR_SET_DUMPABLE changes who owns
// /proc/self -- and a default that silently changes a host's memory behaviour is
// not a default a VPN server should pick for its operator. See
// internal/harden and doc/security.md.
type hardenFlags struct {
	lockMemory  bool
	noCoreDumps bool
}

func bindHardenFlags(fs *flag.FlagSet) *hardenFlags {
	h := &hardenFlags{}
	fs.BoolVar(&h.lockMemory, "lock-memory", false,
		"mlockall: keep every page resident so key material never reaches swap "+
			"(needs CAP_IPC_LOCK or RLIMIT_MEMLOCK headroom)")
	fs.BoolVar(&h.noCoreDumps, "no-core-dumps", false,
		"prctl(PR_SET_DUMPABLE, 0): no core file carries live session keys, and "+
			"a same-uid process cannot ptrace in")
	return h
}

func (h hardenFlags) options() harden.Options {
	return harden.Options{LockMemory: h.lockMemory, NoCoreDumps: h.noCoreDumps}
}
