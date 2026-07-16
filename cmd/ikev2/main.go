// Command ikev2 is a userspace IKEv2 VPN client. It connects to an IKEv2 server
// (this project's ikev2d, or any RFC 7296 responder that accepts PSK or
// EAP-MSCHAPv2), obtains an internal address via configuration mode, brings up a
// local TUN interface, installs routes, and runs a userspace ESP-in-UDP data
// path so the host's traffic flows through the tunnel.
//
// Creating a TUN device and editing the routing table require CAP_NET_ADMIN:
//
//	go build -o ikev2 ./cmd/ikev2
//	sudo ./ikev2 -server vpn.example.com -psk 'secret' -id client.example
//
// Authentication is PSK by default; pass -user/-pass to use EAP-MSCHAPv2
// (the server still authenticates itself with the PSK).
//
// The handshake and data path live in the reusable client package; this command
// adds CLI flags, route installation, and signal handling on top.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/dataplane"
)

// Build metadata, stamped via -ldflags at release time (see .goreleaser.yaml).
// Defaults apply to `go build`/`go run` and development binaries.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// printVersion writes the stamped build metadata to stdout.
func printVersion(prog string) {
	fmt.Printf("%s %s (commit %s, built %s, %s)\n",
		prog, version, commit, date, runtime.Version())
}

func main() {
	var (
		showVersion = flag.Bool("version", false, "print version information and exit")
		server      = flag.String("server", "", "VPN server host or IP (required)")
		port        = flag.Int("port", 500, "server IKE port")
		psk         = flag.String("psk", "", "pre-shared key (required)")
		idStr       = flag.String("id", "", "local identity presented to the server (required)")
		remoteID    = flag.String("server-id", "", "expected server identity (optional, verified if set)")
		user        = flag.String("user", "", "EAP-MSCHAPv2 username (enables EAP instead of client PSK)")
		pass        = flag.String("pass", "", "EAP-MSCHAPv2 password")
		tunName     = flag.String("tun", "", "TUN interface name (empty = kernel picks)")
		fullTun     = flag.Bool("full-tunnel", true, "route all traffic through the VPN (default route)")
		noRoute     = flag.Bool("no-route", false, "do not modify routing/addresses (diagnostic)")
	)
	flag.Parse()

	if *showVersion {
		printVersion("ikev2")
		return
	}

	if *server == "" || *psk == "" || *idStr == "" {
		flag.Usage()
		log.Fatal("-server, -psk and -id are required")
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	// 1. Handshake + data path (no routing — that stays this command's job).
	sess, res, err := client.Dial(context.Background(), client.Config{
		Server:      *server,
		Port:        *port,
		PSK:         *psk,
		LocalID:     *idStr,
		ServerID:    *remoteID,
		EAPUser:     *user,
		EAPPassword: *pass,
		TUNName:     *tunName,
		Logger:      logger,
	})
	if err != nil {
		log.Fatalf("ikev2: %v", err)
	}
	defer sess.Close()
	logger.Printf("ikev2: connected on %s, internal IP %s, netmask %s, DNS %v",
		res.TUNName, res.AssignedIP, res.Netmask, res.DNS)

	// 2. Routing.
	if !*noRoute {
		router := dataplane.NewClientRouter(dataplane.ClientNetConfig{
			TUNName:    res.TUNName,
			AssignedIP: res.AssignedIP,
			Netmask:    res.Netmask,
			ServerIP:   res.Gateway,
			DNS:        res.DNS,
			FullTunnel: *fullTun,
		})
		if err := router.Apply(); err != nil {
			logger.Printf("ikev2: routing setup failed: %v (continuing without routes)", err)
		} else {
			logger.Printf("ikev2: routing configured (full-tunnel=%v)", *fullTun)
			defer func() {
				if rerr := router.Revert(); rerr != nil {
					logger.Printf("ikev2: route cleanup: %v", rerr)
				}
			}()
		}
	}

	logger.Printf("ikev2: tunnel up. Press Ctrl-C to disconnect.")

	// 3. Wait for signal.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	logger.Printf("ikev2: disconnecting")
}
