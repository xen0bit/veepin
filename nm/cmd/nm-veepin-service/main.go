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
	"os"

	"github.com/godbus/dbus/v5"
	"github.com/xen0bit/veepin/internal/vlog"
	"github.com/xen0bit/veepin/nm/internal/dbusplugin"

	// Registers the protocols this plugin can dial with the client registry.
	// Without the import the binary still links, and every Connect fails at
	// runtime with "unknown protocol" — so a new protocol must be added here (and
	// given requireKeys/secretMissing branches in internal/nmconfig). The insecure
	// "toy" example protocol is deliberately left out.
	_ "github.com/xen0bit/veepin/amneziawg"
	_ "github.com/xen0bit/veepin/anyconnect"
	_ "github.com/xen0bit/veepin/cisco"
	_ "github.com/xen0bit/veepin/fortinet"
	_ "github.com/xen0bit/veepin/gp"
	_ "github.com/xen0bit/veepin/ikev2"
	_ "github.com/xen0bit/veepin/l2tp"
	_ "github.com/xen0bit/veepin/l2tpv3"
	_ "github.com/xen0bit/veepin/masque"
	_ "github.com/xen0bit/veepin/nebula"
	_ "github.com/xen0bit/veepin/openvpn"
	_ "github.com/xen0bit/veepin/pulse"
	_ "github.com/xen0bit/veepin/softether"
	_ "github.com/xen0bit/veepin/ssh"
	_ "github.com/xen0bit/veepin/sstp"
	_ "github.com/xen0bit/veepin/wireguard"
)

func main() {
	// NetworkManager passes --bus-name, set to the service= of whichever .name
	// descriptor it matched. veepin ships one descriptor per protocol so that
	// each is its own entry in the OS's "Add VPN" list, and they all name this
	// same program — so the flag is what tells this process which VPN type it
	// was spawned for. It must be honoured: claiming the wrong name leaves NM
	// waiting for a service that never appears.
	busName := flag.String("bus-name", dbusplugin.BusNamePrefix,
		"D-Bus name to claim (NetworkManager sets this per VPN type)")
	persist := flag.Bool("persist", false, "keep running after disconnect (unused; NM re-spawns)")
	session := flag.Bool("session", false, "connect to the session bus instead of the system bus (debug only)")
	flag.Parse()
	_ = persist

	logger := vlog.Text(os.Stderr)

	connect := dbus.ConnectSystemBus
	if *session {
		connect = dbus.ConnectSessionBus
	}
	conn, err := connect()
	if err != nil {
		// Errorf then exit, rather than a Fatalf on the logger: vlog has no
		// Fatal on purpose, because a logger that can end the process is one
		// every package could end the process with.
		logger.Errorf("connect bus: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	plugin := dbusplugin.New(conn, *busName, logger)
	if err := plugin.Export(); err != nil {
		logger.Errorf("export plugin: %v", err)
		os.Exit(1)
	}

	logger.Printf("ready; waiting for NetworkManager")
	plugin.Wait()
	logger.Printf("exiting")
}
