// Command veepin is a userspace VPN client and server.
//
// It dispatches on a subcommand, most of them on a protocol:
//
//	veepin connect   <protocol|profile> [flags]  bring up a tunnel to a server
//	veepin serve     <protocol> [flags]          run one VPN server
//	veepin serve     -config <dir>               run a fleet of them, with a
//	                                             management API and HTML panel
//	veepin profile   <subcmd>                    manage client connection profiles
//	veepin mgmt      <subcmd> [flags]            talk to a running supervisor's API
//	veepin probe     <protocol> [flags]          diagnostic: handshake + one packet
//	veepin udp-proxy [flags]                     forward a local UDP socket over
//	                                             MASQUE CONNECT-UDP
//
// Running it bare prints the protocols the registry holds, which is the
// authoritative list — every protocol package registers itself, so the command
// never carries a copy of it that can go stale. usage() in this file is the
// same list; it is printed, this one is read, and they are checked against each
// other by nothing, so keep them together.
//
// Creating a TUN device and editing the routing table require CAP_NET_ADMIN —
// run as root, or grant the binary the capability once:
//
//	go build -o veepin ./cmd/veepin
//	sudo setcap cap_net_admin+ep ./veepin
package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/xen0bit/veepin/client"

	// Registers the protocols with the client registry. Adding a protocol here
	// is what makes it dialable by name.
	_ "github.com/xen0bit/veepin/ikev2"
	_ "github.com/xen0bit/veepin/openvpn"
	_ "github.com/xen0bit/veepin/sstp"
	_ "github.com/xen0bit/veepin/wireguard"
)

// Build metadata, stamped via -ldflags at release time (see .goreleaser.yaml).
// Defaults apply to `go build`/`go run` and development binaries.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch cmd := os.Args[1]; cmd {
	case "connect":
		run(runConnect(os.Args[2:]))
	case "serve":
		run(runServe(os.Args[2:]))
	case "profile":
		run(runProfile(os.Args[2:]))
	case "mgmt":
		run(runMgmt(os.Args[2:]))
	case "probe":
		run(runProbe(os.Args[2:]))
	case "udp-proxy":
		run(runUDPProxy(os.Args[2:]))
	case "-version", "--version", "version":
		fmt.Printf("veepin %s (commit %s, built %s, %s)\n", version, commit, date, runtime.Version())
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "veepin: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func run(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "veepin: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `veepin %s — a userspace VPN client and server

Usage:
  veepin connect   <protocol|profile> [flags]  bring up a tunnel
  veepin serve     <protocol> [flags]           run a single VPN server
  veepin serve     -config <dir>                run a fleet of servers
  veepin profile   <subcmd>                     manage client connection profiles
  veepin mgmt      <subcmd> [flags]             talk to a running supervisor's API
  veepin probe     <protocol> [flags]           diagnostic: handshake + one data packet
  veepin udp-proxy [flags]                      forward a local UDP socket via MASQUE CONNECT-UDP
  veepin version                                print build information

Protocols: %s
`, version, strings.Join(client.Protocols(), ", "))
}
