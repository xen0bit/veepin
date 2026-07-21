// Command nm-veepin-service is the NetworkManager VPN plugin service for
// veepin. NetworkManager spawns it (as root) when an veepin VPN connection is
// activated; it speaks the org.freedesktop.NetworkManager.VPN.Plugin D-Bus
// contract and drives the reusable veepin client to establish the tunnel,
// reporting the assigned address/DNS/routes back to NM for it to apply.
//
// It is not run directly by users. See doc/networkmanager-plugin.md and the
// nm-veepin-service.name descriptor.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/godbus/dbus/v5"
	"github.com/xen0bit/veepin/nm/internal/dbusplugin"

	// Registers the protocols this plugin can dial with the client registry.
	// Without the import the binary still links, and every Connect fails at
	// runtime with "unknown protocol" — so a new protocol must be added here (and
	// given requireKeys/secretMissing branches in internal/nmconfig). The insecure
	// "toy" example protocol is deliberately left out.
	_ "github.com/xen0bit/veepin/anyconnect"
	_ "github.com/xen0bit/veepin/fortinet"
	_ "github.com/xen0bit/veepin/ikev2"
	_ "github.com/xen0bit/veepin/l2tp"
	_ "github.com/xen0bit/veepin/masque"
	_ "github.com/xen0bit/veepin/nebula"
	_ "github.com/xen0bit/veepin/openvpn"
	_ "github.com/xen0bit/veepin/ssh"
	_ "github.com/xen0bit/veepin/sstp"
	_ "github.com/xen0bit/veepin/wireguard"
)

func main() {
	// NetworkManager passes --bus-name; accepted for compatibility, unused (the
	// well-known name is fixed).
	_ = flag.String("bus-name", dbusplugin.BusName, "D-Bus name (compat, ignored)")
	persist := flag.Bool("persist", false, "keep running after disconnect (unused; NM re-spawns)")
	session := flag.Bool("session", false, "connect to the session bus instead of the system bus (debug only)")
	flag.Parse()
	_ = persist

	logger := log.New(os.Stderr, "nm-veepin: ", log.LstdFlags)

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
