// Command nm-ikennkt-service is the NetworkManager VPN plugin service for
// ikennkt. NetworkManager spawns it (as root) when an ikennkt VPN connection is
// activated; it speaks the org.freedesktop.NetworkManager.VPN.Plugin D-Bus
// contract and drives the reusable ikennkt client to establish the tunnel,
// reporting the assigned address/DNS/routes back to NM for it to apply.
//
// It is not run directly by users. See doc/networkmanager-plugin.md and the
// nm-ikennkt-service.name descriptor.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/godbus/dbus/v5"
	"github.com/xen0bit/ikennkt/nm/internal/dbusplugin"
)

func main() {
	// NetworkManager passes --bus-name; accepted for compatibility, unused (the
	// well-known name is fixed).
	_ = flag.String("bus-name", dbusplugin.BusName, "D-Bus name (compat, ignored)")
	persist := flag.Bool("persist", false, "keep running after disconnect (unused; NM re-spawns)")
	session := flag.Bool("session", false, "connect to the session bus instead of the system bus (debug only)")
	flag.Parse()
	_ = persist

	logger := log.New(os.Stderr, "nm-ikennkt: ", log.LstdFlags)

	connect := dbus.ConnectSystemBus
	if *session {
		connect = dbus.ConnectSessionBus
	}
	conn, err := connect()
	if err != nil {
		logger.Fatalf("connect bus: %v", err)
	}
	defer conn.Close()

	plugin := dbusplugin.New(conn, logger)
	if err := plugin.Export(); err != nil {
		logger.Fatalf("export plugin: %v", err)
	}

	logger.Printf("ready; waiting for NetworkManager")
	plugin.Wait()
	logger.Printf("exiting")
}
