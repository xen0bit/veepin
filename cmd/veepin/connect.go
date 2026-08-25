package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"math/rand/v2"
	"os/signal"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/profile"
	"github.com/xen0bit/veepin/internal/vlog"
)

// runConnect brings up a tunnel and applies the negotiated configuration to the
// system. The first argument is either a protocol name (bare mode) or a saved
// profile name (profile mode, resolved from ~/.config/veepin/profiles/).
//
// In bare mode the dial is identical to the existing command: flags produce an
// options map, client.Dial runs the handshake, routing is applied.
// Profile mode loads the named profile file by name and dials with the protocol
// and options stored inside it; per-protocol flags are not bound (the profile
// IS the flag set), only the global host-networking flags apply.
func runConnect(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: veepin connect <protocol|profile> [flags]\nprotocols: %s",
			strings.Join(client.AllProtocols(), ", "))
	}
	name := args[0]

	// Profile resolution: if the name is not a known protocol, look it up in
	// ~/.config/veepin/profiles/. The registry is checked first so a profile
	// that happens to share a name with a protocol resolves to the protocol.
	if !knownProtocol(name) {
		// VEEPIN_PROFILE_DIR is honored here too, not just by the profile
		// subcommands: `VEEPIN_PROFILE_DIR=./out veepin profile add x ...` and
		// `VEEPIN_PROFILE_DIR=./out veepin connect x` must agree on where a
		// profile lives, or a generated bundle can be saved and then undialable.
		profDir, err := profileDir()
		if err != nil {
			return fmt.Errorf("connect: profile directory: %w", err)
		}
		cfg, err := profile.ParseFile(profile.Path(profDir, name))
		if err != nil {
			// Only a missing file means "no such profile". A profile that exists
			// but does not parse -- a hand-edited file with a typo, a key from a
			// newer version -- must say so: reporting it as unknown sends the
			// operator looking for a file that is sitting right there.
			if errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("connect: %q is neither a protocol nor a saved profile\nprotocols: %s",
					name, strings.Join(client.AllProtocols(), ", "))
			}
			return fmt.Errorf("connect: profile %q: %w", name, err)
		}
		return runConnectProfile(cfg, args[1:]...)
	}

	return runConnectBare(name, args[1:])
}

// knownProtocol reports whether name is in the client registry. It is the
// gate between bare mode (name = protocol) and profile mode (name = profile).
func knownProtocol(name string) bool {
	return slices.Contains(client.AllProtocols(), name)
}

// runConnectBare is the existing single-protocol dial path, kept identical
// so flags_test.go and every protocol's registered flag set are untouched.
func runConnectBare(protocol string, args []string) error {
	fs := flag.NewFlagSet("connect "+protocol, flag.ContinueOnError)
	netCfg := bindNetFlags(fs)
	logCfg := bindLogFlags(fs)

	options, err := connectFlags(protocol, fs)
	if err != nil {
		return err
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := netCfg.resolve(fs); err != nil {
		return err
	}

	logger, err := logCfg.logger()
	if err != nil {
		return err
	}
	return dialConnect(protocol, options(), *netCfg, logger)
}

// runConnectProfile loads the named profile and dials with its saved protocol
// and options. Per-protocol flags are not bound: the profile file IS the flag
// set; only the global host-networking flags (see netflags.go), and -set
// overrides, apply in args.
func runConnectProfile(cfg profile.Config, args ...string) error {
	fs := flag.NewFlagSet("connect "+cfg.Name, flag.ContinueOnError)
	netCfg := bindNetFlags(fs)
	logCfg := bindLogFlags(fs)
	var sets setList
	fs.Var(&sets, "set", "override a profile option for this dial, key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("connect: unexpected argument %q", fs.Arg(0))
	}
	if err := netCfg.resolve(fs); err != nil {
		return err
	}
	opts, err := applyOverrides("connect", cfg.Protocol, cfg.Options, sets)
	if err != nil {
		return err
	}
	logger, err := logCfg.logger()
	if err != nil {
		return err
	}
	return dialConnect(cfg.Protocol, opts, *netCfg, logger)
}

// applyOverrides merges repeatable -set key=value pairs onto opts, so a profile
// dial can override one option without editing the file. An entry that is not
// key=value is an error, not a silent no-op, and neither is a key the protocol
// does not declare.
//
// The key check matters more than it looks. A flag and its option key are not
// always spelled the same -- ikev2's flag is -server and its option key is
// "gateway" -- so
//
//	veepin connect home -set server=other.example.com
//
// was accepted, changed nothing, and dialled the old gateway. That is the
// silent-drop shape flags_test.go's own header calls the worst kind of bug
// here, and the spec table that answers it was already in the registry.
//
// cmd names the caller, since both `connect` and `mgmt client-config` reach
// this and the error used to say "connect:" for both.
func applyOverrides(cmd, protocol string, opts map[string]string, sets []string) (map[string]string, error) {
	specs, haveSpecs := client.ClientOptsFor(protocol)
	declared := make(map[string]bool, len(specs))
	for _, sp := range specs {
		declared[sp.Key] = true
	}
	out := maps.Clone(opts)
	if out == nil {
		out = map[string]string{}
	}
	for _, kv := range sets {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("%s: -set %q is not key=value", cmd, kv)
		}
		if haveSpecs && !declared[k] {
			keys := make([]string, 0, len(declared))
			for d := range declared {
				keys = append(keys, d)
			}
			sort.Strings(keys)
			return nil, fmt.Errorf("%s: -set %q: %s has no option %q (it takes: %s)",
				cmd, kv, protocol, k, strings.Join(keys, ", "))
		}
		out[k] = v
	}
	return out, nil
}

// setList is a repeatable -set flag: each occurrence appends one key=value.
type setList []string

func (s *setList) String() string { return strings.Join(*s, ", ") }

func (s *setList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// dialConnect is the shared dial+route+serve tail that bare mode and profile
// mode both call, wrapped in the reconnection loop.
//
// The loop is the whole of the difference from what this used to be. Previously
// a session that ended for any reason returned to the shell, which meant the
// cross-protocol liveness monitor -- whose entire job is to notice a dead peer
// and end the session -- converted every recoverable outage into a permanent
// one. Now the monitor's teardown is what triggers a re-dial, which is the
// caller its own doc comment describes and that did not exist.
//
// Three things decide whether this is any good, and each is enforced below:
// a rejected credential is never retried, the host's routing state comes all
// the way down between attempts, and a signal during a backoff exits now.
func dialConnect(protocol string, opts map[string]string, netCfg netFlags, logger *vlog.Logger) error {
	// One signal context for the whole command, not one per session: a Ctrl-C
	// during a sixty-second backoff has to exit immediately, and a per-attempt
	// context cannot see it.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Parse once, up front. A malformed option produces the same error on every
	// attempt, so retrying it is a loop that prints the same line forever
	// instead of telling the operator their config is wrong. Dial parses again
	// through the same function, so this costs a parse and changes no behaviour.
	if err := client.ValidateOptions(protocol, opts); err != nil {
		return err
	}

	// The kill switch outlives every session, because holding across the gap is
	// the whole point of it: a tunnel that dies during the backoff must not
	// silently resume sending in plaintext. Disengaged by a defer that runs on
	// every path including a panic, so the only way to leave a host closed is to
	// kill the process outright -- for which the engage log line prints the
	// recovery command.
	var killer *dataplane.KillSwitch
	defer func() {
		if killer != nil && killer.Engaged() {
			if err := killer.Disengage(); err != nil {
				logger.Printf("kill switch: %v — reopen by hand with: %s", err, killer.RecoveryCommand())
			} else {
				logger.Printf("kill switch disengaged")
			}
		}
	}()

	rnd := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0))
	consecutive := 0 // failures since the last session that stayed up
	for attempt := 1; ; attempt++ {
		upFor, err := oneSession(ctx, protocol, opts, netCfg, logger, &killer)
		switch {
		case err == nil:
			// An intended teardown: the operator's signal, or a session that
			// ended without incident.
			return nil
		case ctx.Err() != nil:
			// The signal arrived mid-dial or mid-session. Whatever else the
			// error says, the operator asked to stop.
			return nil
		case permanent(err):
			return err
		case !netCfg.retry:
			return err
		}

		// A session that carried traffic for a while was a working
		// configuration; the next failure is a new outage, not an escalating
		// one, and starts again from one second.
		if upFor >= retrySettled {
			consecutive = 0
		}
		consecutive++

		if netCfg.retryMax > 0 && attempt >= netCfg.retryMax {
			return fmt.Errorf("connect: giving up after %d attempts: %w", attempt, err)
		}
		delay := backoff(consecutive, rnd)
		logger.Printf("disconnected: %v — reconnecting in %s%s",
			err, delay.Round(100*time.Millisecond), attemptsLeft(attempt+1, netCfg.retryMax))
		if !sleepCtx(ctx, delay) {
			return nil // signalled during the backoff
		}
	}
}

// oneSession dials, applies the negotiated configuration, and blocks until the
// session ends. It returns how long the tunnel was up and why it ended: a nil
// error means the teardown was intended (the operator's signal, or a clean
// close) and the caller should not re-dial.
//
// Everything it installs is undone before it returns, by defers that run on
// every path including a panic. That is what makes the retry loop above safe:
// a re-dial starts from a host whose routing table, addresses and resolver
// configuration are as they were before the first attempt.
//
// The one exception is the kill switch, which is the point of it: killer is the
// caller's, deliberately outlives this function, and is filled in here because
// this is where the server's outer address becomes known.
func oneSession(
	ctx context.Context,
	protocol string,
	opts map[string]string,
	netCfg netFlags,
	logger *vlog.Logger,
	killer **dataplane.KillSwitch,
) (time.Duration, error) {
	fullTunnel, noRoute := netCfg.fullTunnel, netCfg.noRoute

	// 1. Handshake + data path. Dial installs no routes -- that is this
	// command's job, and the split is what lets NetworkManager reuse the same
	// dial.
	sess, res, err := client.Dial(ctx, protocol, opts)
	if err != nil {
		return 0, err
	}
	defer sess.Close()
	up := time.Now()
	logger.Printf("connected on %s, internal IP %s (v6 %s), netmask %s, DNS %v",
		res.TUNName, res.AssignedIP, res.AssignedIP6, res.Netmask, res.DNS)

	// Advisory only. A protocol may have a reason for something unusual, and
	// refusing to bring up a working tunnel over a heuristic would be worse than
	// the mistake being caught -- but a Result that cannot be right should say
	// so here rather than manifest as traffic that silently goes nowhere.
	if err := res.Validate(); err != nil {
		logger.Printf("warning: %v", err)
	}

	// 2. Routing (and DNS, which the router owns for the same reason it owns
	// the routes: identical lifetime, identical teardown).
	if !noRoute {
		router := dataplane.NewClientRouter(dataplane.ClientNetConfig{
			TUNName:     res.TUNName,
			AssignedIP:  res.AssignedIP,
			Netmask:     res.Netmask,
			AssignedIP6: res.AssignedIP6,
			Prefix6:     res.Prefix6,
			ServerIP:    res.Gateway,
			DNS:         res.DNS,
			NoDNS:       netCfg.noDNS,
			FullTunnel:  fullTunnel,
			Routes:      netCfg.routes,
			Excludes:    netCfg.excludes,
		})
		// Revert is deferred before the result of Apply is examined, not after.
		// Apply installs several pieces of host state in sequence and can fail
		// on any of them; the old shape registered the cleanup only on complete
		// success, so a failure halfway through left addresses, routes -- and
		// now a rewritten resolv.conf -- behind for good. Revert is guarded by
		// what it actually installed, so calling it after a failed or partial
		// Apply is exactly right.
		aerr := router.Apply()
		defer func() {
			if rerr := router.Revert(); rerr != nil {
				logger.Printf("route cleanup: %v", rerr)
			}
		}()
		if aerr != nil {
			logger.Printf("routing setup failed: %v (continuing with whatever came up)", aerr)
		} else {
			logger.Printf("routing configured (full-tunnel=%v)", fullTunnel)
		}
		if be := router.DNSBackend(); be != "" {
			logger.Printf("DNS %v installed via %s", res.DNS, be)
		} else if !netCfg.noDNS && len(res.DNS) == 0 {
			// Said out loud, because a full tunnel with no resolvers of its own
			// resolves through the host's -- which is the leak this warns about
			// rather than silently permits.
			logger.Printf("warning: the server offered no DNS servers; " +
				"name resolution still uses the host's resolvers")
		}

		// 2b. The kill switch, armed while the tunnel is HEALTHY rather than in
		// response to its death. The blackholes sit at a worse metric than the
		// tunnel's own routes, so they are inert now and take over the instant
		// the kernel drops the TUN's routes with the device -- which is a
		// handover with no window, where installing them on teardown would leave
		// however long that takes as plaintext.
		if netCfg.killSwitch {
			if err := armKillSwitch(killer, res, fullTunnel, logger); err != nil {
				return time.Since(up), err
			}
		}
	}

	logger.Printf("tunnel up. Press Ctrl-C to disconnect.")

	// 3. Wait for a signal or for the session to end on its own.
	//
	// Distinguishing the two is what tells the loop above whether to re-dial,
	// and it is the same distinction the log line already drew: a tunnel that
	// dies on its own -- a dropped carrier, a peer teardown, a protocol error --
	// is otherwise indistinguishable from a clean Ctrl-C, which makes a failure
	// in the field or in CI nearly impossible to diagnose from the logs.
	err = sess.Wait(ctx)
	switch {
	case err == nil, errors.Is(err, context.Canceled):
		logger.Printf("disconnecting")
		return time.Since(up), nil
	default:
		return time.Since(up), err
	}
}

// armKillSwitch engages the caller's kill switch on the first successful dial,
// and is a no-op on every dial after it: the switch is already holding, which
// is the state that matters.
//
// It refuses two configurations rather than delivering something worse than
// what was asked for, and both refusals are permanent -- retrying them would
// produce the same answer while the operator watched a log line repeat.
func armKillSwitch(
	killer **dataplane.KillSwitch,
	res client.Result,
	fullTunnel bool,
	logger *vlog.Logger,
) error {
	if *killer != nil {
		return nil
	}
	// A split tunnel routes some prefixes through the VPN and deliberately
	// leaves the rest on the physical link. There is nothing to fail closed:
	// blackholing everything would break the traffic the user asked to keep
	// outside the tunnel.
	if !fullTunnel {
		return fmt.Errorf("connect: -kill-switch needs a full tunnel; "+
			"a split tunnel deliberately sends some traffic outside the VPN, "+
			"and there is nothing there to fail closed: %w", errNoRetry)
	}
	// A mesh reaches its peers at many underlay addresses, so there is no
	// single route to carve out of the blackhole -- and a kill switch with no
	// carve-out is a host that can never reconnect. Refused loudly here rather
	// than delivered as a bricked machine.
	if res.Gateway == nil {
		return fmt.Errorf("connect: -kill-switch needs one server address to keep reachable, "+
			"and this protocol reports none (it reaches peers at many underlay addresses). "+
			"Engaging would leave a host that cannot re-dial: %w", errNoRetry)
	}

	k := dataplane.NewKillSwitch(dataplane.KillSwitchConfig{
		ServerIP: res.Gateway,
		V4:       res.AssignedIP != nil,
		V6:       res.AssignedIP6 != nil,
	})
	if err := k.Engage(); err != nil {
		return err
	}
	*killer = k
	// The recovery command is logged on engage, not on failure. The moment you
	// need it is the moment the host is closed and you cannot reach it to look
	// it up.
	logger.Printf("kill switch engaged: traffic fails closed if the tunnel drops. "+
		"To reopen this host by hand: %s", k.RecoveryCommand())
	if res.AssignedIP != nil && res.AssignedIP6 == nil {
		// Said out loud because it is a change to the host beyond what the
		// tunnel carries, and an operator should not discover it by finding
		// IPv6 dead. It is deliberate: a family the tunnel does not carry is
		// exactly a family that escapes it, and failing closed means closing
		// it too.
		logger.Printf("kill switch: this tunnel carries IPv4 only, so IPv6 is blackholed " +
			"for its lifetime rather than left to leave by the physical link")
	}
	return nil
}

// connectFlags binds a protocol's client flags onto fs and returns a function
// that collects them into the option map client.Dial parses.
//
// It is generated from the protocol's RegisterClientOpts table (see
// optflags.go), so adding a protocol adds no case here -- which is the whole
// point: this used to be 584 lines of one `case` per protocol, restating a
// name, type, default and help text the spec table already carried, and four of
// AGENTS.md's mechanical guards existed only to hold the two copies together.
func connectFlags(protocol string, fs *flag.FlagSet) (func() map[string]string, error) {
	specs, ok := client.ClientOptsFor(protocol)
	if !ok {
		return nil, fmt.Errorf("unknown protocol %q (available: %s)",
			protocol, strings.Join(client.AllProtocols(), ", "))
	}
	return bindSpecFlags(fs, specs), nil
}
