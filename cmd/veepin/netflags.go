package main

import (
	"flag"
	"fmt"
	"net"
	"strings"
)

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
	killSwitch bool
	routes     cidrList
	excludes   cidrList
}

// cidrList is a repeatable CIDR flag. It parses on Set rather than at apply
// time, so a typo is a command-line error with the offending value named,
// rather than a route that quietly never appears.
type cidrList []*net.IPNet

func (c *cidrList) String() string {
	out := make([]string, 0, len(*c))
	for _, n := range *c {
		out = append(out, n.String())
	}
	return strings.Join(out, ",")
}

func (c *cidrList) Set(v string) error {
	// A bare address is accepted and read as a host route, because "-exclude
	// 192.0.2.10" is what an operator will type and refusing it over a missing
	// /32 helps nobody.
	if !strings.Contains(v, "/") {
		ip := net.ParseIP(v)
		if ip == nil {
			return fmt.Errorf("%q is neither a CIDR prefix nor an address", v)
		}
		bits := 128
		if ip4 := ip.To4(); ip4 != nil {
			ip, bits = ip4, 32
		}
		*c = append(*c, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		return nil
	}
	_, n, err := net.ParseCIDR(v)
	if err != nil {
		return err
	}
	*c = append(*c, n)
	return nil
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
	fs.Var(&n.routes, "route",
		"send this prefix through the tunnel (repeatable); implies -full-tunnel=false, "+
			"since naming what to route means not routing everything")
	fs.Var(&n.excludes, "exclude",
		"keep this prefix OFF the tunnel (repeatable), by routing it via the "+
			"physical gateway -- the same mechanism that keeps the tunnel's own "+
			"packets from recursing into it")
	// Off by default, deliberately. A kill switch that engages when the user did
	// not ask for one strands a machine they may only be able to reach over the
	// network they just blackholed.
	fs.BoolVar(&n.killSwitch, "kill-switch", false,
		"fail closed: if the tunnel drops, blackhole traffic instead of letting "+
			"it resume in plaintext, until the tunnel is back or veepin exits. "+
			"Needs a full tunnel and a server with one outer address")
	return n
}

// resolve applies the implications between flags, once, after parsing.
//
// -route implies -full-tunnel=false. Naming the prefixes to route and also
// routing everything is a contradiction, and the two orders of precedence are
// not equally useful: honouring the default full tunnel would make -route a
// silent no-op, which is the shape of bug this tree calls the worst kind.
//
// An explicit -full-tunnel alongside -route is a contradiction the operator
// typed, so it is reported rather than resolved.
func (n *netFlags) resolve(fs *flag.FlagSet) error {
	// -no-route and -kill-switch cannot both be honoured: the switch IS host
	// routing -- blackhole routes at a worse metric than the tunnel's own -- and
	// -no-route says to install none.
	//
	// Reported rather than resolved, because the way this read before was the
	// silent one. dialConnect arms the switch inside the same `if !noRoute` block
	// that installs the routes, so `-no-route -kill-switch` brought the tunnel up,
	// printed nothing, and failed OPEN -- with the operator having explicitly
	// asked to fail closed. Every other way of refusing this flag says so out
	// loud (see armKillSwitch); this one has to as well.
	if n.killSwitch && n.noRoute {
		return fmt.Errorf("connect: -kill-switch installs blackhole routes and -no-route " +
			"installs none; pick one (there is nothing to fail closed with routing left alone)")
	}
	if len(n.routes) == 0 {
		return nil
	}
	explicitFull := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "full-tunnel" {
			explicitFull = true
		}
	})
	if explicitFull && n.fullTunnel {
		return fmt.Errorf("connect: -route names what to send through the tunnel and " +
			"-full-tunnel=true sends everything; pick one")
	}
	n.fullTunnel = false
	return nil
}
