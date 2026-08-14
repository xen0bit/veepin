package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/hostnet"
	"github.com/xen0bit/veepin/internal/mgmt"
	"github.com/xen0bit/veepin/internal/mgmt/ui"
	"github.com/xen0bit/veepin/internal/supervisor"
)

// runServe runs a VPN server. Everything protocol-specific is in the flag set
// that produces the server's options; the rest — constructing the server,
// configuring host networking, and the signal/serve lifecycle — is shared, the
// mirror of runConnect.
//
// Two modes share one subcommand: `veepin serve <protocol> [flags]` is the
// single-protocol command below, unchanged; `veepin serve -config <dir>` is
// supervisor mode: read that directory's listener files, run each as a server
// in one process, and expose a localhost management API plus web panel. The
// supervisor mode is the home of in-process fleet management; bare mode is the
// one-process-per-protocol path the interop matrix verifies.
func runServe(args []string) error {
	// Supervisor mode: `veepin serve -config <dir>` reads a directory of
	// listener JSON files and serves them all in one process. Detect the
	// flag positionally so per-protocol flag parsing is untouched below.
	if len(args) >= 1 && (args[0] == "-config" || args[0] == "--config") {
		return runSupervisorMode(args)
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: veepin serve <protocol> [flags]\nprotocols: %s\n"+
			"       veepin serve -config <dir> [-listen <addr>]",
			strings.Join(client.ServerProtocols(), ", "))
	}
	protocol, args := args[0], args[1:]

	fs := flag.NewFlagSet("serve "+protocol, flag.ContinueOnError)
	setup := fs.Bool("setup-nat", false, "auto-configure the TUN address, routing and NAT via ip/iptables (needs privileges)")
	wanIface := fs.String("wan", "", "WAN interface for -setup-nat masquerading (e.g. eth0)")
	logCfg := bindLogFlags(fs)

	options, err := serveFlags(protocol, fs)
	if err != nil {
		return err
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger, err := logCfg.logger()
	if err != nil {
		return err
	}

	// 1. Construct the server (opens the TUN, validates config); it is not yet
	// listening and has changed no host state.
	srv, err := client.NewServer(protocol, options())
	if err != nil {
		return err
	}
	defer srv.Close()
	logger.Printf("opened TUN interface %s", srv.TUNName())

	// 2. Host networking: the server owns the tunnel, not the host's routing, so
	// the operator opts into (or performs) the address/forwarding/NAT setup.
	//
	// A layer-2 server (L2TPv3) has no tunnel subnet and no gateway inside the
	// tunnel: the interface joins a bridged segment and takes its address from
	// DHCP or ARP in there. Network() is nil for those, so neither the NAT setup
	// nor the advice below applies -- and maskBits would dereference the nil.
	switch {
	case srv.Network() == nil:
		logger.Printf("layer-2 server: %s carries Ethernet frames and assigns no address.", srv.TUNName())
		logger.Printf("Bring it up and bridge or address it yourself:")
		logger.Printf("    sudo ip link set %s up", srv.TUNName())
		logger.Printf("    sudo ip link set %s master br0    # or: ip addr add <addr>/<len> dev %s",
			srv.TUNName(), srv.TUNName())
	case *setup:
		if err := setupNetworking(srv.TUNName(), srv.Gateway(), srv.Network(), *wanIface); err != nil {
			logger.Printf("-setup-nat: %v (continuing; configure manually)", err)
		} else {
			logger.Printf("configured %s gateway=%s and NAT via %s", srv.TUNName(), srv.Gateway(), *wanIface)
		}
	default:
		logger.Printf("TUN not auto-configured. Bring it up with:")
		logger.Printf("    sudo ip addr add %s/%d dev %s", srv.Gateway(), maskBits(srv.Network()), srv.TUNName())
		logger.Printf("    sudo ip link set %s up", srv.TUNName())
		logger.Printf("    sudo sysctl -w net.ipv4.ip_forward=1")
		logger.Printf("    sudo iptables -t nat -A POSTROUTING -s %s -o <wan> -j MASQUERADE", srv.Network())
	}

	// 3. Serve until a signal.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		logger.Printf("shutting down")
		_ = srv.Close()
	}()

	if srv.Network() != nil {
		logger.Printf("%s server ready on %s (clients assigned from %s)", protocol, srv.TUNName(), srv.Network())
	} else {
		logger.Printf("%s server ready on %s (layer 2; no address assignment)", protocol, srv.TUNName())
	}
	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// serveFlags binds a protocol's server flags onto fs and returns a function
// that collects them into the option map client.NewServer parses.
//
// The serve-side twin of connectFlags, generated the same way from
// RegisterServerOpts. Between them they replaced about twelve hundred lines of
// hand-written switch, and with them went step 4 of "Adding a protocol".
func serveFlags(protocol string, fs *flag.FlagSet) (func() map[string]string, error) {
	specs, ok := client.ServerOptsFor(protocol)
	if !ok {
		return nil, fmt.Errorf("unknown server protocol %q (available: %s)",
			protocol, strings.Join(client.ServerProtocols(), ", "))
	}
	return bindSpecFlags(fs, specs), nil
}

// maskBits is the prefix length of a tunnel subnet. A nil network -- a layer-2
// server, which has no subnet of its own -- reports 0 rather than panicking.
func maskBits(n *net.IPNet) int {
	if n == nil {
		return 0
	}
	ones, _ := n.Mask.Size()
	return ones
}

// setupNetworking configures the TUN interface address, brings it up, enables
// IPv4 forwarding and installs MASQUERADE / FORWARD rules tagged for the bare
// "serve" invocation. It is the single-protocol command's caller of
// internal/hostnet, which owns the shared-with-supervisor implementation; the
// operator name "serve" keeps bare-mode iptables comments visually distinct
// from the supervisor's "<listener>" tags.
func setupNetworking(tunName string, gateway net.IP, network *net.IPNet, wan string) error {
	return hostnet.Apply("serve", hostnet.Config{
		TUNName: tunName,
		Gateway: gateway,
		Network: network,
		WAN:     wan,
	})
}

// runSupervisorMode reads -config <dir> and runs the fleet: one client.Server
// per listener file, each in its own goroutine, plus a localhost-only
// management API + embedded panel. -listen overrides the default bind; -no-mgmt
// disables the management plane entirely (the supervisor then just runs the
// fleet and logs).
//
// Two of the bare command's concerns do not apply here: there is no per-protocol
// flag set (the supervisor reads Options from the JSON files), and the signal
// handling shuts down every listener through Manager.Close so SIGINT/SIGTERM
// drain the whole fleet rather than one server.
// stringList is a repeatable string flag: `-allow-host a -allow-host b`.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func runSupervisorMode(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: veepin serve -config <dir> [-listen <addr>] [-no-mgmt]")
	}
	configDir := args[1]
	rest := args[2:]
	fs := flag.NewFlagSet("serve -config", flag.ContinueOnError)
	listenAddr := fs.String("listen", "127.0.0.1:8443", "management API / panel bind address")
	noMgmt := fs.Bool("no-mgmt", false, "run the supervisor without the management API")
	profilesDir := fs.String("profiles", "", "directory of client connection profiles for the panel (default: <config>/profiles)")
	var allowHosts stringList
	fs.Var(&allowHosts, "allow-host", "additional Host header value the panel answers on (repeatable); "+
		"loopback and the -listen address are always allowed")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	// The shared log ring captures every line the supervisor and the API write,
	// for GET /api/logs. Both logger consumers below get the SAME *log.Logger,
	// so a single ring at the source captures listener events, hostnet
	// messages, and the per-request API log alike.
	logRing := mgmt.NewLogRing()
	logger := log.New(io.MultiWriter(os.Stdout, logRing), "", log.LstdFlags|log.Lmicroseconds)
	mgr := supervisor.NewManager(configDir, logger, nil)
	if err := mgr.Apply(); err != nil {
		// A listener that will not start is left tracked in "error" state with
		// its reason, and Apply reports every such failure joined together. That
		// is a warning, not a reason to abort: the listeners that did come up are
		// serving, and the panel is how an operator fixes the ones that did not.
		//
		// Nothing at all coming up is the fatal case -- an unreadable config
		// directory, or every listener broken -- because then there is no fleet
		// to manage and a panel would only obscure that.
		if len(mgr.All()) == 0 {
			_ = mgr.Close()
			return fmt.Errorf("supervisor: %w", err)
		}
		logger.Printf("supervisor: %v", err)
	}
	total := len(mgr.All())
	logger.Printf("supervisor ready: %d of %d listener(s) running", countRunning(mgr), total)

	var httpSrv *http.Server
	if !*noMgmt {
		mgmtOpts := []mgmt.Option{}
		// The profile directory defaults to the same config root the listeners
		// live under, so /api/profiles works out of the box and a fleet's
		// profiles sit next to its listeners.
		if *profilesDir == "" {
			*profilesDir = filepath.Join(configDir, "profiles")
		}
		mgmtOpts = append(mgmtOpts, mgmt.WithProfileDir(*profilesDir))
		mgmtOpts = append(mgmtOpts, mgmt.WithLogRing(logRing))
		mgmtServer, err := mgmt.NewServer(configDir, mgr, logger, mgmtOpts...)
		if err != nil {
			_ = mgr.Close()
			return fmt.Errorf("mgmt: %w", err)
		}
		mux := http.NewServeMux()
		mux.Handle("/api/", mgmtServer.Handler())
		uiHandler, err := ui.NewHandler(string(mgmtServer.Token()), logger)
		if err != nil {
			_ = mgr.Close()
			return fmt.Errorf("ui: %w", err)
		}
		mux.Handle("/", uiHandler)
		// The Host guard wraps panel and API together. The panel cannot require
		// a token -- it is what hands the browser one -- so without this a page
		// that rebinds its own hostname to the loopback address becomes
		// same-origin with the panel, reads the token out of the DOM, and drives
		// every endpoint. See mgmt.RequireHost.
		//
		// -allow-host is the escape hatch the guard needs to be usable off
		// loopback. The allow set is seeded from the literal -listen address, so
		// binding 0.0.0.0 admits only the Host "0.0.0.0" -- which no browser
		// ever sends -- and every real request 403s, panel and API alike. The
		// same goes for a reverse proxy or an `ssh -L` tunnel, where the Host
		// is whatever name the operator dialled. Naming those hosts explicitly
		// keeps the guard strict without making it useless.
		httpSrv = &http.Server{
			Addr:    *listenAddr,
			Handler: mgmt.RequireHost(append([]string{*listenAddr}, allowHosts...), mux),
			// A management plane with no read deadline is one slow client away
			// from holding a connection open indefinitely. The handlers read
			// their bodies before taking the fleet lock, so this is the outer
			// bound rather than the only one.
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			ErrorLog:          logger,
		}
		go func() {
			logger.Printf("management API + panel at http://%s/", *listenAddr)
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Printf("management API: %v", err)
			}
		}()
	}

	// SIGHUP re-reads the config directory and reconciles the live set, the same
	// pass the initial load runs -- so adding, editing, or removing a listener
	// file does not need the API or a restart of the fleet.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			logger.Printf("supervisor: SIGHUP; re-reading %s", configDir)
			if err := mgr.Apply(); err != nil {
				logger.Printf("supervisor: reload: %v", err)
			}
			logger.Printf("supervisor: %d of %d listener(s) running", countRunning(mgr), len(mgr.All()))
			continue
		}
		break
	}
	logger.Printf("supervisor shutting down")
	if httpSrv != nil {
		// Stop answering before the listeners go away, so the panel does not
		// serve a fleet that is halfway torn down.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := httpSrv.Shutdown(ctx); err != nil {
			logger.Printf("management API shutdown: %v", err)
		}
		cancel()
	}
	if err := mgr.Close(); err != nil {
		return fmt.Errorf("supervisor shutdown: %w", err)
	}
	return nil
}

// countRunning returns the number of listeners whose state is "running" for
// the ready-line log. It reads All rather than checking the underlying map so
// the count reflects what the panel will show.
func countRunning(mgr *supervisor.Manager) int {
	var n int
	for _, s := range mgr.All() {
		if s.State == "running" {
			n++
		}
	}
	return n
}
