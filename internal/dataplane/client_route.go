package dataplane

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// ClientNetConfig describes the networking changes needed to route a host's
// traffic through the VPN: the TUN interface, the address assigned by the
// server, and the server's public address (which must remain reachable via the
// physical link so ESP packets don't recurse into the tunnel).
type ClientNetConfig struct {
	TUNName    string
	AssignedIP net.IP
	Netmask    net.IP
	ServerIP   net.IP   // VPN server's public IP (host route added outside tunnel)
	DNS        []net.IP // informational; resolv.conf changes are left to the caller
	// FullTunnel routes all traffic through the VPN (default route). When false,
	// only the assigned subnet is routed and the caller adds its own routes.
	FullTunnel bool
}

// ClientRouter applies and reverts client-side networking. It shells out to the
// Linux iproute2 tools; it requires CAP_NET_ADMIN. Reverting restores the prior
// default route.
type ClientRouter struct {
	cfg       ClientNetConfig
	prevGWIP  string // previous default gateway, for restoration
	prevGWDev string
	installed bool
	addedHost bool
	addedDef  bool
}

// NewClientRouter creates a router for the given configuration.
func NewClientRouter(cfg ClientNetConfig) *ClientRouter {
	return &ClientRouter{cfg: cfg}
}

// Apply configures the TUN address, brings the interface up, adds a host route
// to the VPN server via the existing default gateway, and (for a full tunnel)
// replaces the default route to send everything through the TUN.
func (r *ClientRouter) Apply() error {
	// Record the current default route so we can (a) pin a host route to the
	// server through it and (b) restore it on teardown.
	gwIP, gwDev, err := defaultRoute()
	if err != nil {
		return fmt.Errorf("read default route: %w", err)
	}
	r.prevGWIP, r.prevGWDev = gwIP, gwDev

	prefix := maskToPrefix(r.cfg.Netmask)
	steps := [][]string{
		{"ip", "addr", "add", fmt.Sprintf("%s/%d", r.cfg.AssignedIP, prefix), "dev", r.cfg.TUNName},
		{"ip", "link", "set", r.cfg.TUNName, "up"},
	}
	for _, s := range steps {
		if err := run(s); err != nil {
			return err
		}
	}
	r.installed = true

	// Host route: reach the VPN server via the physical gateway, so that the
	// encapsulated ESP packets are NOT themselves routed into the tunnel.
	if r.cfg.ServerIP != nil && gwIP != "" {
		if err := run([]string{"ip", "route", "add", r.cfg.ServerIP.String(), "via", gwIP, "dev", gwDev}); err != nil {
			// Non-fatal if it already exists.
			if !strings.Contains(err.Error(), "File exists") {
				return err
			}
		} else {
			r.addedHost = true
		}
	}

	// Full tunnel: split the default route into two /1 routes via the TUN,
	// which override the existing default without deleting it (a common VPN
	// technique that makes restoration trivial).
	if r.cfg.FullTunnel {
		for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := run([]string{"ip", "route", "add", half, "dev", r.cfg.TUNName}); err != nil {
				return err
			}
		}
		r.addedDef = true
	}
	return nil
}

// Revert removes the routes and address this router added. Best-effort: errors
// are collected but do not stop cleanup.
func (r *ClientRouter) Revert() error {
	var errs []string
	if r.addedDef {
		for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := run([]string{"ip", "route", "del", half, "dev", r.cfg.TUNName}); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if r.addedHost && r.cfg.ServerIP != nil {
		if err := run([]string{"ip", "route", "del", r.cfg.ServerIP.String()}); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if r.installed {
		// Bringing the link down and removing the address; the kernel drops the
		// connected route automatically.
		_ = run([]string{"ip", "link", "set", r.cfg.TUNName, "down"})
	}
	if len(errs) > 0 {
		return fmt.Errorf("revert: %s", strings.Join(errs, "; "))
	}
	return nil
}

// defaultRoute returns the current IPv4 default gateway IP and device.
func defaultRoute() (gwIP, dev string, err error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	// Example: "default via 192.168.1.1 dev eth0 proto dhcp ..."
	fields := strings.Fields(string(out))
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "via":
			gwIP = fields[i+1]
		case "dev":
			dev = fields[i+1]
		}
	}
	if gwIP == "" || dev == "" {
		return "", "", fmt.Errorf("no default route found")
	}
	return gwIP, dev, nil
}

func maskToPrefix(mask net.IP) int {
	if mask == nil {
		return 24
	}
	m := net.IPMask(mask.To4())
	ones, _ := m.Size()
	if ones == 0 {
		return 24
	}
	return ones
}

func run(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
