package main

import "flag"

// netFlags are the host-networking flags that apply to every `connect`,
// whatever protocol is underneath: what to route, what to resolve, and what to
// do when the tunnel dies. They are protocol-independent by construction --
// they describe what the caller does with a client.Result, and a Result has the
// same shape for all seventeen protocols.
//
// One struct rather than a handful of *bool because both bare mode and profile
// mode bind the identical set, and the two copies had already drifted: profile
// mode's -full-tunnel help text differed from bare mode's for no reason anyone
// intended.
type netFlags struct {
	fullTunnel bool
	noRoute    bool
	noDNS      bool
	retry      bool
	retryMax   int
}

// bindNetFlags declares the host-networking flags on fs and returns the struct
// they will fill once fs.Parse runs.
func bindNetFlags(fs *flag.FlagSet) *netFlags {
	n := &netFlags{}
	fs.BoolVar(&n.fullTunnel, "full-tunnel", true,
		"route all traffic through the VPN (default route)")
	fs.BoolVar(&n.noRoute, "no-route", false,
		"do not modify routing, addresses or DNS (diagnostic)")
	fs.BoolVar(&n.noDNS, "no-dns", false,
		"leave the host's resolvers alone; by default the servers the tunnel "+
			"offers are installed for its lifetime, because a full tunnel that "+
			"keeps the old resolver leaks every query it was meant to hide")
	fs.BoolVar(&n.retry, "retry", true,
		"re-dial when the tunnel drops, with jittered backoff from 1s to 60s; "+
			"a rejected credential is never retried. -retry=false for scripts")
	fs.IntVar(&n.retryMax, "retry-max", 0,
		"give up after this many attempts (0 = keep trying), for CI and scripts "+
			"that need a bounded failure")
	return n
}
