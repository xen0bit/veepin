// Command ikev2d is a userspace IKEv2 VPN server. It performs the IKEv2 key
// exchange (IKE_SA_INIT + IKE_AUTH, pre-shared-key auth) with NAT traversal,
// hands connecting clients an internal address via IKEv2 configuration mode
// (CP), and runs a userspace ESP-in-UDP data path over a TUN device.
//
// A standards-compliant OS VPN client (Linux strongSwan/NetworkManager, Windows,
// macOS/iOS, Android) configured for "IKEv2 / machine-cert-less / PSK" can
// connect to it.
//
// The data path is userspace: the server opens a TUN interface and moves inner
// IP packets between that interface and ESP-in-UDP on port 4500. Creating a TUN
// device requires CAP_NET_ADMIN — run as root, or grant the binary the
// capability once:
//
//	go build -o ikev2d ./cmd/ikev2d
//	sudo setcap cap_net_admin+ep ./ikev2d
//
// then configure forwarding/NAT for the tunnel subnet (see -help output).
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/eap"
	"github.com/xen0bit/veepin/internal/ikev2/ike"
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
		listenIP    = flag.String("listen", "0.0.0.0", "local IP to bind IKE sockets on")
		publicIP    = flag.String("public", "", "server's public IP as seen by clients (for NAT detection); defaults to -listen if concrete")
		psk         = flag.String("psk", "", "pre-shared key (required)")
		idStr       = flag.String("id", "", "local identity (FQDN or IP address) presented to clients (required)")
		poolCIDR    = flag.String("pool", "10.10.10.0/24", "internal address pool handed to clients")
		dnsList     = flag.String("dns", "1.1.1.1,8.8.8.8", "comma-separated DNS servers pushed to clients")
		tunName     = flag.String("tun", "", "TUN interface name (empty = kernel picks, e.g. tun0)")
		setup       = flag.Bool("setup-nat", false, "auto-configure the TUN address, routing and NAT via ip/iptables (needs privileges)")
		wanIface    = flag.String("wan", "", "WAN interface for -setup-nat masquerading (e.g. eth0)")
		eapFile     = flag.String("eap-users", "", "path to a username:password file enabling EAP-MSCHAPv2 auth (optional)")
	)
	flag.Parse()

	if *showVersion {
		printVersion("ikev2d")
		return
	}

	if *psk == "" || *idStr == "" {
		flag.Usage()
		log.Fatal("both -psk and -id are required")
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	// Address pool + gateway (the server's tunnel-side IP).
	pool, gateway, err := dataplane.NewAddrPool(*poolCIDR)
	if err != nil {
		log.Fatalf("ikev2d: address pool: %v", err)
	}
	var dnsServers []net.IP
	for _, d := range strings.Split(*dnsList, ",") {
		if d = strings.TrimSpace(d); d != "" {
			if ip := net.ParseIP(d); ip != nil {
				dnsServers = append(dnsServers, ip)
			}
		}
	}

	// TUN device for the userspace data path.
	tun, err := dataplane.OpenTUN(*tunName)
	if err != nil {
		log.Fatalf("ikev2d: %v", err)
	}
	defer tun.Close()
	logger.Printf("ikev2d: opened TUN interface %s", tun.Name())

	// Optionally auto-configure the interface address, routing and NAT.
	if *setup {
		if err := setupNetworking(tun.Name(), gateway, pool.Network(), *wanIface); err != nil {
			logger.Printf("ikev2d: -setup-nat: %v (continuing; configure manually)", err)
		} else {
			logger.Printf("ikev2d: configured %s gateway=%s and NAT via %s", tun.Name(), gateway, *wanIface)
		}
	} else {
		logger.Printf("ikev2d: TUN not auto-configured. Bring it up with:")
		logger.Printf("    sudo ip addr add %s/%d dev %s", gateway, maskBits(pool.Network()), tun.Name())
		logger.Printf("    sudo ip link set %s up", tun.Name())
		logger.Printf("    sudo sysctl -w net.ipv4.ip_forward=1")
		logger.Printf("    sudo iptables -t nat -A POSTROUTING -s %s -o <wan> -j MASQUERADE", pool.Network())
	}

	// Server config: the data path is created after we know the send function.
	pubIP := net.ParseIP(*publicIP)
	if pubIP == nil {
		if ip := net.ParseIP(*listenIP); ip != nil && !ip.IsUnspecified() {
			pubIP = ip
		}
	}

	// Optional EAP-MSCHAPv2 credentials.
	var eapLookup eap.CredentialLookup
	if *eapFile != "" {
		store, lerr := eap.LoadFileStore(*eapFile)
		if lerr != nil {
			log.Fatalf("ikev2d: loading -eap-users: %v", lerr)
		}
		eapLookup = store.Lookup
		logger.Printf("ikev2d: EAP-MSCHAPv2 enabled with %d user(s) from %s", store.Count(), *eapFile)
	}

	cfg := ike.Config{
		ListenIP: *listenIP,
		PSK:      []byte(*psk),
		LocalID:  parseIdentity(*idStr),
		PublicIP: pubIP,
		Logger:   logger,
		AssignAddr: func() (net.IP, net.IP, []net.IP, error) {
			ip, aerr := pool.Allocate()
			if aerr != nil {
				return nil, nil, nil, aerr
			}
			return ip, pool.Netmask(), dnsServers, nil
		},
		ReleaseAddr:    func(ip net.IP) { pool.Release(ip) },
		EAPCredentials: eapLookup,
		EAPServerName:  *idStr,
	}

	srv, err := ike.NewServer(cfg)
	if err != nil {
		log.Fatalf("ikev2d: %v", err)
	}

	// Data path: pump between TUN and ESP-in-UDP. The pump's send function
	// hands encapsulated ESP back to the server's NAT-T socket, and inbound
	// packets are demuxed on the ESP SPI.
	pump := dataplane.NewPump(tun, srv.SendESP, dataplane.SPIDemux, logger)
	dp := ike.NewPumpDataPath(pump)
	srv.SetDataPath(dp)

	go pump.Run()
	defer pump.Close()

	// Graceful shutdown.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		logger.Printf("ikev2d: shutting down")
		pump.Close()
		_ = srv.Close()
	}()

	logger.Printf("ikev2d: VPN server ready — clients authenticate with PSK and identity, and receive an address from %s", *poolCIDR)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("ikev2d: serve: %v", err)
	}
}

func parseIdentity(s string) ike.Identity {
	if ip := net.ParseIP(s); ip != nil {
		return ike.IPIdentity(ip)
	}
	return ike.FQDNIdentity(s)
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
