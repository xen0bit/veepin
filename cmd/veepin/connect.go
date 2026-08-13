package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"math/rand/v2"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/xen0bit/veepin/amneziawg"
	"github.com/xen0bit/veepin/anyconnect"
	"github.com/xen0bit/veepin/cisco"
	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/fortinet"
	"github.com/xen0bit/veepin/gp"
	"github.com/xen0bit/veepin/ikev2"
	"github.com/xen0bit/veepin/internal/profile"
	"github.com/xen0bit/veepin/l2tp"
	"github.com/xen0bit/veepin/l2tpv3"
	"github.com/xen0bit/veepin/masque"
	"github.com/xen0bit/veepin/nebula"
	"github.com/xen0bit/veepin/openvpn"
	"github.com/xen0bit/veepin/pulse"
	"github.com/xen0bit/veepin/softether"
	"github.com/xen0bit/veepin/ssh"
	"github.com/xen0bit/veepin/sstp"
	"github.com/xen0bit/veepin/toy"
	"github.com/xen0bit/veepin/wireguard"
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
			strings.Join(client.Protocols(), ", "))
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
					name, strings.Join(client.Protocols(), ", "))
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
	return slices.Contains(client.Protocols(), name)
}

// runConnectBare is the existing single-protocol dial path, kept identical
// so flags_test.go and every protocol's registered flag set are untouched.
func runConnectBare(protocol string, args []string) error {
	fs := flag.NewFlagSet("connect "+protocol, flag.ContinueOnError)
	netCfg := bindNetFlags(fs)

	options, err := connectFlags(protocol, fs)
	if err != nil {
		return err
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	return dialConnect(protocol, options(), *netCfg, logger)
}

// runConnectProfile loads the named profile and dials with its saved protocol
// and options. Per-protocol flags are not bound: the profile file IS the flag
// set; only the global host-networking flags (see netflags.go), and -set
// overrides, apply in args.
func runConnectProfile(cfg profile.Config, args ...string) error {
	fs := flag.NewFlagSet("connect "+cfg.Name, flag.ContinueOnError)
	netCfg := bindNetFlags(fs)
	var sets setList
	fs.Var(&sets, "set", "override a profile option for this dial, key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("connect: unexpected argument %q", fs.Arg(0))
	}
	opts, err := applyOverrides("connect", cfg.Protocol, cfg.Options, sets)
	if err != nil {
		return err
	}
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
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
func dialConnect(protocol string, opts map[string]string, netCfg netFlags, logger *log.Logger) error {
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
	logger *log.Logger,
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
	logger *log.Logger,
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
		// Said plainly because it is a real hole and the flag's name promises
		// otherwise. Closing IPv6 that the tunnel never carried would break
		// connectivity nobody asked us to touch, so the honest answer is to
		// name it.
		logger.Printf("warning: this tunnel carries IPv4 only, so the kill switch closes IPv4 only; " +
			"IPv6 traffic on a dual-stack host still leaves by the physical link")
	}
	return nil
}

// connectFlags binds a protocol's flags onto fs and returns a function that
// collects them into the option map client.Dial parses. A new protocol adds a
// case here; nothing else in this command changes.
func connectFlags(protocol string, fs *flag.FlagSet) (func() map[string]string, error) {
	switch protocol {
	case "ikev2":
		var (
			server    = fs.String("server", "", "VPN server host or IP (required)")
			port      = fs.Int("port", 0, "server IKE port (default 500)")
			psk       = fs.String("psk", "", "pre-shared key (required)")
			id        = fs.String("id", "", "local identity presented to the server (required)")
			serverID  = fs.String("server-id", "", "expected server identity (optional, verified if set)")
			user      = fs.String("user", "", "EAP-MSCHAPv2 username (enables EAP instead of client PSK)")
			pass      = fs.String("pass", "", "EAP-MSCHAPv2 password")
			tun       = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
			rekey     = fs.Int("rekey", 0, "Child SA rekey interval in seconds (0 = default 3600)")
			ikeRekey  = fs.Int("ike-rekey", 0, "IKE SA rekey interval in seconds (0 = default 14400)")
			cert      = fs.String("cert", "", "client certificate PEM (enables certificate auth instead of PSK)")
			key       = fs.String("key", "", "client private-key PEM (with -cert)")
			ca        = fs.String("ca", "", "CA bundle PEM to verify the server (optional; default system roots)")
			shape     = fs.Int("shape", 0, "per-flow upstream shaping budget in bytes: pads each inner flow's first N bytes to the tunnel MTU (0 = off; the server shapes downstream independently)")
			pq        = fs.Bool("post-quantum", false, "offer ML-KEM-768 as an additional key exchange (RFC 9370); hybrid with the classical group, and skipped if the server declines")
			iptfs     = fs.Bool("iptfs", false, "enable AGGFRAG aggregation and fragmentation (RFC 9347) for the Child SA")
			iptfsRate = fs.Int("iptfs-rate", 0, "constant-rate IP-TFS transmission in bytes/sec; 0 = aggregation only")
		)
		return func() map[string]string {
			opts := map[string]string{
				ikev2.OptGateway:   *server,
				ikev2.OptPSK:       *psk,
				ikev2.OptLocalID:   *id,
				ikev2.OptServerID:  *serverID,
				ikev2.OptUser:      *user,
				ikev2.OptPassword:  *pass,
				ikev2.OptTUNName:   *tun,
				ikev2.OptCert:      *cert,
				ikev2.OptKey:       *key,
				ikev2.OptCA:        *ca,
				ikev2.OptShape:     fmt.Sprint(*shape),
				ikev2.OptPQ:        fmt.Sprint(*pq),
				ikev2.OptIPTFS:     fmt.Sprint(*iptfs),
				ikev2.OptIPTFSRate: fmt.Sprint(*iptfsRate),
			}
			if *port != 0 {
				opts[ikev2.OptPort] = fmt.Sprint(*port)
			}
			if *rekey != 0 {
				opts[ikev2.OptRekey] = fmt.Sprint(*rekey)
			}
			if *ikeRekey != 0 {
				opts[ikev2.OptIKERekey] = fmt.Sprint(*ikeRekey)
			}
			return opts
		}, nil
	case "wireguard":
		var (
			config    = fs.String("config", "", "wg-quick style config file (flags below override its values)")
			privKey   = fs.String("private-key", "", "our static private key, base64")
			address   = fs.String("address", "", "our tunnel address in CIDR form, e.g. 10.0.0.2/32")
			dns       = fs.String("dns", "", "comma-separated DNS servers (optional)")
			mtu       = fs.Int("mtu", 0, "inner MTU (default 1420)")
			pubKey    = fs.String("public-key", "", "peer static public key, base64")
			psk       = fs.String("preshared-key", "", "optional preshared key, base64")
			endpoint  = fs.String("endpoint", "", "peer host:port, e.g. vpn.example.com:51820")
			allowed   = fs.String("allowed-ips", "", "comma-separated destinations routed to the peer, e.g. 0.0.0.0/0")
			keepalive = fs.Int("persistent-keepalive", 0, "keepalive interval in seconds (0 = off)")
			rekey     = fs.Int("rekey-seconds", 0, "seconds between key refreshes (0 = protocol default, 120)")
			tun       = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
			listen    = fs.Int("listen-port", 0, "local UDP port to bind (0 = ephemeral; fixes the source port for a stable NAT pinhole)")
			shape     = fs.Int("shape", 0, "per-flow upstream shaping budget in bytes: pads each inner flow's first N bytes to the tunnel MTU (0 = off; the server shapes downstream independently)")
		)
		return func() map[string]string {
			opts := map[string]string{
				wireguard.OptConfig:       *config,
				wireguard.OptPrivateKey:   *privKey,
				wireguard.OptAddress:      *address,
				wireguard.OptDNS:          *dns,
				wireguard.OptPublicKey:    *pubKey,
				wireguard.OptPresharedKey: *psk,
				wireguard.OptEndpoint:     *endpoint,
				wireguard.OptAllowedIPs:   *allowed,
				wireguard.OptTUNName:      *tun,
				wireguard.OptShape:        fmt.Sprint(*shape),
			}
			if *mtu != 0 {
				opts[wireguard.OptMTU] = fmt.Sprint(*mtu)
			}
			if *keepalive != 0 {
				opts[wireguard.OptKeepalive] = fmt.Sprint(*keepalive)
			}
			if *rekey != 0 {
				opts[wireguard.OptRekeySeconds] = fmt.Sprint(*rekey)
			}
			if *listen != 0 {
				opts[wireguard.OptListenPort] = fmt.Sprint(*listen)
			}
			return opts
		}, nil
	case "openvpn":
		var (
			config   = fs.String("config", "", ".ovpn profile (flags below override its values)")
			remote   = fs.String("remote", "", "server host or IP")
			port     = fs.Int("port", 0, "server UDP port (default 1194)")
			ca       = fs.String("ca", "", "path to the CA certificate PEM")
			cert     = fs.String("cert", "", "path to the client certificate PEM")
			key      = fs.String("key", "", "path to the client private key PEM")
			cipher   = fs.String("cipher", "", "data cipher: AES-256-GCM (default) or AES-256-CBC")
			auth     = fs.String("auth", "", "HMAC digest for tls-auth and the CBC data channel (default SHA1)")
			tlsAuth  = fs.String("tls-auth", "", "path to a --tls-auth static key")
			tlsCrypt = fs.String("tls-crypt", "", "path to a --tls-crypt static key")
			keyDir   = fs.Int("key-direction", -1, "tls-auth key direction: 0 or 1 (default: bidirectional)")
			user     = fs.String("username", "", "auth-user-pass username (optional)")
			pass     = fs.String("password", "", "auth-user-pass password (optional)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
			shape    = fs.Int("shape", 0, "per-flow upstream shaping budget in bytes: pads each inner flow's first N bytes to the tunnel MTU (0 = off; the server shapes downstream independently)")
		)
		return func() map[string]string {
			opts := map[string]string{
				openvpn.OptConfig:   *config,
				openvpn.OptRemote:   *remote,
				openvpn.OptCA:       *ca,
				openvpn.OptCert:     *cert,
				openvpn.OptKey:      *key,
				openvpn.OptCipher:   *cipher,
				openvpn.OptAuth:     *auth,
				openvpn.OptTLSAuth:  *tlsAuth,
				openvpn.OptTLSCrypt: *tlsCrypt,
				openvpn.OptShape:    fmt.Sprint(*shape),
				openvpn.OptUsername: *user,
				openvpn.OptPassword: *pass,
				openvpn.OptTUNName:  *tun,
			}
			if *port != 0 {
				opts[openvpn.OptPort] = fmt.Sprint(*port)
			}
			if *keyDir >= 0 {
				opts[openvpn.OptKeyDirection] = fmt.Sprint(*keyDir)
			}
			return opts
		}, nil
	case "sstp":
		var (
			server   = fs.String("server", "", "SSTP server host or IP (required)")
			port     = fs.Int("port", 0, "server TCP port (default 443)")
			user     = fs.String("user", "", "MS-CHAPv2 username (required)")
			pass     = fs.String("pass", "", "MS-CHAPv2 password (required)")
			insecure = fs.Bool("insecure", false, "skip TLS certificate verification (self-signed servers)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				sstp.OptServer:   *server,
				sstp.OptUser:     *user,
				sstp.OptPassword: *pass,
				sstp.OptTUNName:  *tun,
			}
			if *port != 0 {
				opts[sstp.OptPort] = fmt.Sprint(*port)
			}
			if *insecure {
				opts[sstp.OptInsecure] = "true"
			}
			return opts
		}, nil
	case "l2tp":
		var (
			server = fs.String("server", "", "L2TP/IPsec server host or IP (required)")
			port   = fs.Int("port", 0, "server IKE/ESP port (default 500)")
			psk    = fs.String("psk", "", "IPsec pre-shared key (required)")
			user   = fs.String("user", "", "MS-CHAPv2 username (required)")
			pass   = fs.String("pass", "", "MS-CHAPv2 password (required)")
			dns    = fs.String("dns", "", "comma-separated DNS servers (fallback if PPP assigns none)")
			tun    = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				l2tp.OptServer:   *server,
				l2tp.OptPSK:      *psk,
				l2tp.OptUser:     *user,
				l2tp.OptPassword: *pass,
				l2tp.OptDNS:      *dns,
				l2tp.OptTUNName:  *tun,
			}
			if *port != 0 {
				opts[l2tp.OptPort] = fmt.Sprint(*port)
			}
			return opts
		}, nil
	case "anyconnect":
		var (
			server   = fs.String("server", "", "AnyConnect server host or IP (required)")
			port     = fs.Int("port", 0, "server HTTPS port (default 443)")
			user     = fs.String("user", "", "username (required)")
			pass     = fs.String("pass", "", "password (required)")
			insecure = fs.Bool("insecure", false, "skip TLS certificate verification (self-signed servers)")
			noDTLS   = fs.Bool("no-dtls", false, "keep the data channel on TLS instead of DTLS/UDP")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				anyconnect.OptServer:   *server,
				anyconnect.OptUser:     *user,
				anyconnect.OptPassword: *pass,
				anyconnect.OptTUNName:  *tun,
			}
			if *port != 0 {
				opts[anyconnect.OptPort] = fmt.Sprint(*port)
			}
			if *insecure {
				opts[anyconnect.OptInsecure] = "true"
			}
			if *noDTLS {
				opts[anyconnect.OptNoDTLS] = "true"
			}
			return opts
		}, nil
	case "fortinet":
		var (
			server   = fs.String("server", "", "Fortinet SSL VPN server host or IP (required)")
			port     = fs.Int("port", 0, "server HTTPS port (default 443)")
			user     = fs.String("user", "", "username (required)")
			pass     = fs.String("pass", "", "password (required)")
			realm    = fs.String("realm", "", "FortiOS realm (optional)")
			ca       = fs.String("ca", "", "PEM bundle to verify the server against")
			insecure = fs.Bool("insecure", false, "skip TLS certificate verification (self-signed servers)")
			noDTLS   = fs.Bool("no-dtls", false, "stay on the TLS tunnel even where the gateway offers DTLS")
			token    = fs.String("token", "", "one-time code to answer a 2FA challenge (single use)")
			totp     = fs.String("totp", "", "base32 TOTP secret, to generate codes as the gateway asks")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				fortinet.OptServer:   *server,
				fortinet.OptUser:     *user,
				fortinet.OptPassword: *pass,
				fortinet.OptRealm:    *realm,
				fortinet.OptCA:       *ca,
				fortinet.OptToken:    *token,
				fortinet.OptTOTP:     *totp,
				fortinet.OptTUN:      *tun,
			}
			if *port != 0 {
				opts[fortinet.OptPort] = fmt.Sprint(*port)
			}
			if *insecure {
				opts[fortinet.OptInsecure] = "true"
			}
			if *noDTLS {
				opts[fortinet.OptNoDTLS] = "true"
			}
			return opts
		}, nil
	case "cisco":
		var (
			server   = fs.String("server", "", "IPsec gateway host or IP (required)")
			port     = fs.Int("port", 0, "gateway IKE port (default 500)")
			group    = fs.String("group", "", "group name presented as the phase-1 identity (required)")
			groupPSK = fs.String("group-psk", "", "the group's pre-shared key (required)")
			user     = fs.String("user", "", "XAuth username (required)")
			pass     = fs.String("pass", "", "XAuth password (required)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
			shape    = fs.Int("shape", 0, "per-flow outbound shaping budget in bytes (0 = off, 16384 recommended)")
		)
		return func() map[string]string {
			opts := map[string]string{
				cisco.OptServer:   *server,
				cisco.OptGroup:    *group,
				cisco.OptGroupPSK: *groupPSK,
				cisco.OptUser:     *user,
				cisco.OptPassword: *pass,
				cisco.OptTUN:      *tun,
			}
			if *port != 0 {
				opts[cisco.OptPort] = fmt.Sprint(*port)
			}
			if *shape != 0 {
				opts[cisco.OptShape] = fmt.Sprint(*shape)
			}
			return opts
		}, nil
	case "pulse":
		var (
			server   = fs.String("server", "", "Ivanti Connect Secure gateway host or IP (required)")
			port     = fs.Int("port", 0, "gateway HTTPS port (default 443)")
			path     = fs.String("path", "", "request path the IF-T/TLS upgrade is sent to (default \"/\")")
			user     = fs.String("user", "", "username (required)")
			pass     = fs.String("pass", "", "password (required)")
			ca       = fs.String("ca", "", "PEM bundle to verify the gateway against")
			insecure = fs.Bool("insecure", false, "skip TLS certificate verification (self-signed gateways)")
			noESP    = fs.Bool("no-esp", false, "stay on the IF-T/TLS data path even where the gateway hands out ESP keys")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
			shape    = fs.Int("shape", 0, "per-flow outbound shaping budget in bytes (0 = off, 16384 recommended)")
		)
		return func() map[string]string {
			opts := map[string]string{
				pulse.OptServer:   *server,
				pulse.OptPath:     *path,
				pulse.OptUser:     *user,
				pulse.OptPassword: *pass,
				pulse.OptCA:       *ca,
				pulse.OptTUN:      *tun,
			}
			if *port != 0 {
				opts[pulse.OptPort] = fmt.Sprint(*port)
			}
			if *shape != 0 {
				opts[pulse.OptShape] = fmt.Sprint(*shape)
			}
			if *insecure {
				opts[pulse.OptInsecure] = "true"
			}
			if *noESP {
				opts[pulse.OptNoESP] = "true"
			}
			return opts
		}, nil
	case "gp":
		var (
			server   = fs.String("server", "", "GlobalProtect gateway host or IP (required)")
			port     = fs.Int("port", 0, "gateway HTTPS port (default 443)")
			user     = fs.String("user", "", "username (required)")
			pass     = fs.String("pass", "", "password (required)")
			ca       = fs.String("ca", "", "PEM bundle to verify the gateway against")
			insecure = fs.Bool("insecure", false, "skip TLS certificate verification (self-signed gateways)")
			noESP    = fs.Bool("no-esp", false, "stay on the SSL tunnel even where the gateway hands out ESP keys")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
			shape    = fs.Int("shape", 0, "per-flow outbound shaping budget in bytes (0 = off, 16384 recommended)")
		)
		return func() map[string]string {
			opts := map[string]string{
				gp.OptServer:   *server,
				gp.OptUser:     *user,
				gp.OptPassword: *pass,
				gp.OptCA:       *ca,
				gp.OptTUN:      *tun,
			}
			if *port != 0 {
				opts[gp.OptPort] = fmt.Sprint(*port)
			}
			if *shape != 0 {
				opts[gp.OptShape] = fmt.Sprint(*shape)
			}
			if *insecure {
				opts[gp.OptInsecure] = "true"
			}
			if *noESP {
				opts[gp.OptNoESP] = "true"
			}
			return opts
		}, nil
	case "masque":
		var (
			server    = fs.String("server", "", "MASQUE proxy host or IP (required)")
			port      = fs.Int("port", 0, "proxy UDP port (default 443)")
			authority = fs.String("authority", "", "HTTP :authority to present (default: server host)")
			ca        = fs.String("ca", "", "PEM bundle to verify the proxy against")
			insecure  = fs.Bool("insecure", false, "skip proxy certificate verification (self-signed proxies)")
			tun       = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				masque.OptServer:    *server,
				masque.OptAuthority: *authority,
				masque.OptServerCA:  *ca,
				masque.OptTUN:       *tun,
			}
			if *port != 0 {
				opts[masque.OptPort] = fmt.Sprint(*port)
			}
			if *insecure {
				opts[masque.OptInsecure] = "true"
			}
			return opts
		}, nil
	case "toy":
		// An example protocol with no security whatsoever; see internal/toy.
		// The flags are named to make that hard to miss.
		var (
			server = fs.String("server", "", "TOY server host or IP (required)")
			port   = fs.Int("port", 0, "server UDP port (default 5555)")
			user   = fs.String("user", "", "username (required)")
			secret = fs.String("insecure-shared-secret", "", "shared secret (required); provides no real protection")
			tun    = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				toy.OptServer: *server,
				toy.OptUser:   *user,
				toy.OptSecret: *secret,
				toy.OptTUN:    *tun,
			}
			if *port != 0 {
				opts[toy.OptPort] = fmt.Sprint(*port)
			}
			return opts
		}, nil
	case "nebula":
		var (
			ca          = fs.String("ca", "", "path to the CA certificate bundle (required)")
			cert        = fs.String("cert", "", "path to this host's certificate (required)")
			key         = fs.String("key", "", "path to this host's X25519 private key (required)")
			listen      = fs.String("listen", "", "local UDP address to bind (default :4242)")
			staticHosts = fs.String("static-hosts", "", "peer locations: 10.42.0.1=192.0.2.10:4242[,...];...")
			lighthouses = fs.String("lighthouses", "", "comma-separated lighthouse overlay addresses")
			amLH        = fs.Bool("am-lighthouse", false, "answer lighthouse queries from other hosts")
			cipher      = fs.String("cipher", "", "aes (default) or chachapoly; must match the mesh")
			mtu         = fs.Int("mtu", 0, "inner MTU (default 1300)")
			tun         = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				nebula.OptCA:          *ca,
				nebula.OptCert:        *cert,
				nebula.OptKey:         *key,
				nebula.OptListen:      *listen,
				nebula.OptStaticHosts: *staticHosts,
				nebula.OptLighthouses: *lighthouses,
				nebula.OptCipher:      *cipher,
				nebula.OptTUN:         *tun,
			}
			if *amLH {
				opts[nebula.OptAmLighthouse] = "true"
			}
			if *mtu != 0 {
				opts[nebula.OptMTU] = fmt.Sprint(*mtu)
			}
			return opts
		}, nil
	case "ssh":
		var (
			server   = fs.String("server", "", "SSH server host or IP (required)")
			port     = fs.Int("port", 0, "server TCP port (default 22)")
			user     = fs.String("user", "", "SSH username (required)")
			identity = fs.String("identity", "", "path to a private key")
			pass     = fs.String("pass", "", "password (if not using a key)")
			knownH   = fs.String("known-hosts", "", "known_hosts file for host-key verification")
			insecure = fs.Bool("insecure", false, "skip host-key verification")
			address  = fs.String("address", "", "our tunnel address in CIDR form, e.g. 10.200.0.2/30 (required)")
			peer     = fs.String("peer", "", "server tunnel address (point-to-point peer), e.g. 10.200.0.1")
			peerUnit = fs.Int("peer-unit", -1, "remote tun unit to request (default: any; a stock sshd needs a specific unit)")
			dns      = fs.String("dns", "", "comma-separated DNS servers (optional)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				ssh.OptServer:     *server,
				ssh.OptUser:       *user,
				ssh.OptIdentity:   *identity,
				ssh.OptPassword:   *pass,
				ssh.OptKnownHosts: *knownH,
				ssh.OptAddress:    *address,
				ssh.OptPeer:       *peer,
				ssh.OptDNS:        *dns,
				ssh.OptTUNName:    *tun,
			}
			if *port != 0 {
				opts[ssh.OptPort] = fmt.Sprint(*port)
			}
			if *peerUnit >= 0 {
				opts[ssh.OptPeerUnit] = fmt.Sprint(*peerUnit)
			}
			if *insecure {
				opts[ssh.OptInsecure] = "true"
			}
			return opts
		}, nil
	case "softether":
		var (
			server   = fs.String("server", "", "SoftEther VPN gateway host or IP (required)")
			port     = fs.Int("port", 0, "gateway TLS port (default 443)")
			user     = fs.String("user", "", "username (required)")
			pass     = fs.String("pass", "", "password (required)")
			hub      = fs.String("hub", "", "virtual hub name (default VPN)")
			tun      = fs.String("tun", "", "TAP interface name (empty = kernel picks)")
			insecure = fs.Bool("insecure", false, "skip gateway certificate verification (SoftEther ships a self-signed certificate by default; this downgrades the transport to unauthenticated)")
		)
		return func() map[string]string {
			opts := map[string]string{
				softether.OptServer:   *server,
				softether.OptUser:     *user,
				softether.OptPassword: *pass,
				softether.OptTUN:      *tun,
				softether.OptInsecure: fmt.Sprint(*insecure),
			}
			if *port != 0 {
				opts[softether.OptPort] = fmt.Sprint(*port)
			}
			if *hub != "" {
				opts[softether.OptHub] = *hub
			}
			return opts
		}, nil
	case "l2tpv3":
		var (
			gateway   = fs.String("gateway", "", "L2TPv3 peer host or IP (required)")
			port      = fs.Int("port", 0, "peer UDP port (default 1701)")
			lport     = fs.Int("local-port", 0, "local UDP port to bind (default: same as -port; a static pseudowire is symmetric)")
			sid       = fs.Uint("session-id", 0, "our session ID: what the peer sends to (required)")
			psid      = fs.Uint("peer-session-id", 0, "the peer's session ID: what we send to (required)")
			cookie    = fs.String("cookie", "", "hex cookie WE chose, verified on inbound packets (0, 4 or 8 octets)")
			pcookie   = fs.String("peer-cookie", "", "hex cookie the PEER chose, written on outbound packets")
			sublayer  = fs.Bool("sublayer", false, "carry the Default L2-Specific Sublayer (the Linux kernel sends one)")
			tun       = fs.String("tun", "", "TAP interface name (empty = kernel picks)")
			shape     = fs.Int("shape", 0, "per-flow shaping budget in bytes; pads IP-bearing frames only (0 = off)")
			ccid      = fs.Uint("ccid", 0, "our Control Connection ID; with -peer-ccid, enables HELLO keepalives (RFC 3931 quiescent tunnel)")
			pccid     = fs.Uint("peer-ccid", 0, "the peer's Control Connection ID")
			keepalive = fs.Int("keepalive", 0, "HELLO interval in seconds (default 30)")
		)
		return func() map[string]string {
			opts := map[string]string{
				l2tpv3.OptGateway:     *gateway,
				l2tpv3.OptSessionID:   fmt.Sprint(*sid),
				l2tpv3.OptPeerSession: fmt.Sprint(*psid),
				l2tpv3.OptCookie:      *cookie,
				l2tpv3.OptPeerCookie:  *pcookie,
				l2tpv3.OptTUN:         *tun,
				l2tpv3.OptShape:       fmt.Sprint(*shape),
				l2tpv3.OptLocalPort:   fmt.Sprint(*lport),
				l2tpv3.OptCCID:        fmt.Sprint(*ccid),
				l2tpv3.OptPeerCCID:    fmt.Sprint(*pccid),
				l2tpv3.OptKeepalive:   fmt.Sprint(*keepalive),
			}
			if *port != 0 {
				opts[l2tpv3.OptPort] = fmt.Sprint(*port)
			}
			if *sublayer {
				opts[l2tpv3.OptSublayer] = "true"
			}
			return opts
		}, nil
	case "amneziawg":
		// AmneziaWG is WireGuard with the wire format perturbed, so the tunnel
		// flags mirror the wireguard case; the obfuscation flags below are the
		// whole difference. They are not negotiated — both ends must be given
		// identical values, exactly like a pre-shared key.
		var (
			privKey   = fs.String("private-key", "", "our static private key, base64 (required)")
			pubKey    = fs.String("public-key", "", "the server's static public key, base64 (required)")
			psk       = fs.String("preshared-key", "", "optional 32-byte pre-shared key, base64")
			endpoint  = fs.String("endpoint", "", "server host:port (required)")
			address   = fs.String("address", "", "our tunnel address, e.g. 10.0.0.2/24 (required)")
			allowed   = fs.String("allowed-ips", "", "comma-separated allowed IPs (default 0.0.0.0/0)")
			dns       = fs.String("dns", "", "comma-separated DNS servers to install")
			mtu       = fs.Int("mtu", 0, "tunnel MTU (0 = protocol default)")
			tun       = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
			shape     = fs.Int("shape", 0, "per-flow upstream shaping budget in bytes (0 = off)")
			typeInit  = fs.Uint("type-init", 0, "H1: message type replacing handshake initiation (0 = stock 1)")
			typeResp  = fs.Uint("type-resp", 0, "H2: message type replacing handshake response (0 = stock 2)")
			typeCook  = fs.Uint("type-cookie", 0, "H3: message type replacing cookie reply (0 = stock 3)")
			typeTrans = fs.Uint("type-trans", 0, "H4: message type replacing transport data (0 = stock 4)")
			padInit   = fs.Int("pad-init", 0, "S1: random bytes prepended to handshake initiation")
			padResp   = fs.Int("pad-resp", 0, "S2: random bytes prepended to handshake response")
			padCook   = fs.Int("pad-cookie", 0, "S3: random bytes prepended to cookie reply")
			padTrans  = fs.Int("pad-trans", 0, "S4: random bytes prepended to transport data")
			junkCount = fs.Int("junk-count", 0, "Jc: junk datagrams sent before the handshake (0 = none)")
			junkMin   = fs.Int("junk-min", 0, "Jmin: smallest junk datagram in bytes")
			junkMax   = fs.Int("junk-max", 0, "Jmax: largest junk datagram in bytes")
		)
		return func() map[string]string {
			return map[string]string{
				amneziawg.OptPrivateKey:   *privKey,
				amneziawg.OptPublicKey:    *pubKey,
				wireguard.OptPresharedKey: *psk,
				amneziawg.OptEndpoint:     *endpoint,
				amneziawg.OptAddress:      *address,
				amneziawg.OptAllowedIPs:   *allowed,
				amneziawg.OptDNS:          *dns,
				amneziawg.OptMTU:          fmt.Sprint(*mtu),
				amneziawg.OptTUNName:      *tun,
				amneziawg.OptShape:        fmt.Sprint(*shape),
				amneziawg.OptTypeInit:     fmt.Sprint(*typeInit),
				amneziawg.OptTypeResp:     fmt.Sprint(*typeResp),
				amneziawg.OptTypeCookie:   fmt.Sprint(*typeCook),
				amneziawg.OptTypeTrans:    fmt.Sprint(*typeTrans),
				amneziawg.OptPadInit:      fmt.Sprint(*padInit),
				amneziawg.OptPadResp:      fmt.Sprint(*padResp),
				amneziawg.OptPadCookie:    fmt.Sprint(*padCook),
				amneziawg.OptPadTrans:     fmt.Sprint(*padTrans),
				amneziawg.OptJunkCount:    fmt.Sprint(*junkCount),
				amneziawg.OptJunkMin:      fmt.Sprint(*junkMin),
				amneziawg.OptJunkMax:      fmt.Sprint(*junkMax),
			}
		}, nil
	default:
		return nil, fmt.Errorf("unknown protocol %q (available: %s)",
			protocol, strings.Join(client.Protocols(), ", "))
	}
}
