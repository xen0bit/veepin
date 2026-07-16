package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xen0bit/veepin/ikev2"
)

// runServe runs a VPN server. The TUN, address pool and data path are wired by
// the protocol package; this command owns flags, host networking and signals.
func runServe(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: veepin serve <protocol> [flags]\nprotocols: ikev2")
	}
	protocol, args := args[0], args[1:]
	if protocol != "ikev2" {
		return fmt.Errorf("unknown protocol %q (available: ikev2)", protocol)
	}

	fs := flag.NewFlagSet("serve "+protocol, flag.ContinueOnError)
	var (
		listenIP = fs.String("listen", "0.0.0.0", "local IP to bind IKE sockets on")
		publicIP = fs.String("public", "", "server's public IP as seen by clients (for NAT detection); defaults to -listen if concrete")
		psk      = fs.String("psk", "", "pre-shared key (required)")
		idStr    = fs.String("id", "", "local identity (FQDN or IP address) presented to clients (required)")
		poolCIDR = fs.String("pool", "10.10.10.0/24", "internal address pool handed to clients")
		dnsList  = fs.String("dns", "1.1.1.1,8.8.8.8", "comma-separated DNS servers pushed to clients")
		tunName  = fs.String("tun", "", "TUN interface name (empty = kernel picks, e.g. tun0)")
		setup    = fs.Bool("setup-nat", false, "auto-configure the TUN address, routing and NAT via ip/iptables (needs privileges)")
		wanIface = fs.String("wan", "", "WAN interface for -setup-nat masquerading (e.g. eth0)")
		eapFile  = fs.String("eap-users", "", "path to a username:password file enabling EAP-MSCHAPv2 auth (optional)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *psk == "" || *idStr == "" {
		fs.Usage()
		return fmt.Errorf("both -psk and -id are required")
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	// -public defaults to -listen when that is a concrete address.
	pubIP := net.ParseIP(*publicIP)
	if pubIP == nil {
		if ip := net.ParseIP(*listenIP); ip != nil && !ip.IsUnspecified() {
			pubIP = ip
		}
	}

	srv, err := ikev2.NewServer(ikev2.ServerConfig{
		ListenIP: *listenIP,
		PSK:      *psk,
		LocalID:  *idStr,
		PublicIP: pubIP,
		Pool:     *poolCIDR,
		DNS:      parseDNS(*dnsList),
		TUNName:  *tunName,
		EAPUsers: *eapFile,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	defer srv.Close()
	logger.Printf("opened TUN interface %s", srv.TUNName())

	// Host networking: the server owns the tunnel, not the host's routing.
	if *setup {
		if err := setupNetworking(srv.TUNName(), srv.Gateway(), srv.Network(), *wanIface); err != nil {
			logger.Printf("-setup-nat: %v (continuing; configure manually)", err)
		} else {
			logger.Printf("configured %s gateway=%s and NAT via %s", srv.TUNName(), srv.Gateway(), *wanIface)
		}
	} else {
		logger.Printf("TUN not auto-configured. Bring it up with:")
		logger.Printf("    sudo ip addr add %s/%d dev %s", srv.Gateway(), maskBits(srv.Network()), srv.TUNName())
		logger.Printf("    sudo ip link set %s up", srv.TUNName())
		logger.Printf("    sudo sysctl -w net.ipv4.ip_forward=1")
		logger.Printf("    sudo iptables -t nat -A POSTROUTING -s %s -o <wan> -j MASQUERADE", srv.Network())
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		logger.Printf("shutting down")
		_ = srv.Close()
	}()

	logger.Printf("VPN server ready — clients authenticate with PSK and identity, and receive an address from %s", *poolCIDR)
	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func parseDNS(list string) []net.IP {
	var out []net.IP
	for _, d := range strings.Split(list, ",") {
		if d = strings.TrimSpace(d); d != "" {
			if ip := net.ParseIP(d); ip != nil {
				out = append(out, ip)
			}
		}
	}
	return out
}

func maskBits(n *net.IPNet) int {
	ones, _ := n.Mask.Size()
	return ones
}

// setupNetworking configures the TUN interface address, brings it up, enables
// IPv4 forwarding and installs a MASQUERADE rule for the pool via the WAN
// interface. It shells out to ip/iptables/sysctl, which must be present and
// runnable with sufficient privileges.
func setupNetworking(tunName string, gateway net.IP, network *net.IPNet, wan string) error {
	bits := maskBits(network)
	cmds := [][]string{
		{"ip", "addr", "add", fmt.Sprintf("%s/%d", gateway, bits), "dev", tunName},
		{"ip", "link", "set", tunName, "up"},
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
	}
	if wan != "" {
		cmds = append(cmds,
			[]string{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", network.String(), "-o", wan, "-j", "MASQUERADE"},
			[]string{"iptables", "-A", "FORWARD", "-i", tunName, "-j", "ACCEPT"},
			[]string{"iptables", "-A", "FORWARD", "-o", tunName, "-j", "ACCEPT"},
		)
	}
	for _, c := range cmds {
		cmd := exec.Command(c[0], c[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
	}
	if wan == "" {
		return fmt.Errorf("interface configured but no -wan given, so no MASQUERADE installed")
	}
	return nil
}
