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

	"github.com/xen0bit/veepin/anyconnect"
	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/fortinet"
	"github.com/xen0bit/veepin/ikev2"
	"github.com/xen0bit/veepin/l2tp"
	"github.com/xen0bit/veepin/masque"
	"github.com/xen0bit/veepin/nebula"
	"github.com/xen0bit/veepin/openvpn"
	"github.com/xen0bit/veepin/ssh"
	"github.com/xen0bit/veepin/sstp"
	"github.com/xen0bit/veepin/toy"
	"github.com/xen0bit/veepin/wireguard"
)

// runServe runs a VPN server. Everything protocol-specific is in the flag set
// that produces the server's options; the rest — constructing the server,
// configuring host networking, and the signal/serve lifecycle — is shared, the
// mirror of runConnect.
func runServe(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: veepin serve <protocol> [flags]\nprotocols: %s",
			strings.Join(client.ServerProtocols(), ", "))
	}
	protocol, args := args[0], args[1:]

	fs := flag.NewFlagSet("serve "+protocol, flag.ContinueOnError)
	setup := fs.Bool("setup-nat", false, "auto-configure the TUN address, routing and NAT via ip/iptables (needs privileges)")
	wanIface := fs.String("wan", "", "WAN interface for -setup-nat masquerading (e.g. eth0)")

	options, err := serveFlags(protocol, fs)
	if err != nil {
		return err
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

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

	// 3. Serve until a signal.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		logger.Printf("shutting down")
		_ = srv.Close()
	}()

	logger.Printf("%s server ready on %s (clients assigned from %s)", protocol, srv.TUNName(), srv.Network())
	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// serveFlags binds a protocol's server flags onto fs and returns a function that
// collects them into the option map client.NewServer parses. A new server-capable
// protocol adds a case here; nothing else in this command changes.
func serveFlags(protocol string, fs *flag.FlagSet) (func() map[string]string, error) {
	switch protocol {
	case "ikev2":
		var (
			listen   = fs.String("listen", "0.0.0.0", "local IP to bind IKE sockets on")
			public   = fs.String("public", "", "server's public IP as seen by clients (for NAT detection); defaults to -listen if concrete")
			psk      = fs.String("psk", "", "pre-shared key (required)")
			id       = fs.String("id", "", "local identity (FQDN or IP address) presented to clients (required)")
			pool     = fs.String("pool", "10.10.10.0/24", "internal address pool handed to clients")
			dns      = fs.String("dns", "1.1.1.1,8.8.8.8", "comma-separated DNS servers pushed to clients")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks, e.g. tun0)")
			eapUsers = fs.String("eap-users", "", "path to a username:password file enabling EAP-MSCHAPv2 auth (optional)")
		)
		return func() map[string]string {
			return map[string]string{
				ikev2.OptServerListen:   *listen,
				ikev2.OptServerPublic:   *public,
				ikev2.OptServerPSK:      *psk,
				ikev2.OptServerIdentity: *id,
				ikev2.OptServerPool:     *pool,
				ikev2.OptServerDNS:      *dns,
				ikev2.OptServerTUN:      *tun,
				ikev2.OptServerEAPUsers: *eapUsers,
			}
		}, nil
	case "wireguard":
		var (
			config     = fs.String("config", "", "wg-quick server config file (defines the interface and peers)")
			privKey    = fs.String("private-key", "", "server static private key, base64 (required unless in -config)")
			listenIP   = fs.String("listen", "0.0.0.0", "local IP to bind the UDP socket on")
			listenPort = fs.Int("listen-port", 0, "UDP port to listen on (default 51820)")
			address    = fs.String("address", "", "server tunnel address in CIDR form, e.g. 10.10.0.1/24")
			mtu        = fs.Int("mtu", 0, "inner MTU (default 1420)")
			tun        = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
			peerPub    = fs.String("peer-public-key", "", "a single peer's static public key, base64 (adds one peer)")
			peerPSK    = fs.String("peer-preshared-key", "", "the -peer-public-key peer's preshared key, base64 (optional)")
			peerIPs    = fs.String("peer-allowed-ips", "", "the -peer-public-key peer's allowed IPs, comma-separated CIDRs")
		)
		return func() map[string]string {
			opts := map[string]string{
				wireguard.OptServerConfig:           *config,
				wireguard.OptServerPrivateKey:       *privKey,
				wireguard.OptServerListenIP:         *listenIP,
				wireguard.OptServerAddress:          *address,
				wireguard.OptServerTUN:              *tun,
				wireguard.OptServerPeerPublicKey:    *peerPub,
				wireguard.OptServerPeerPresharedKey: *peerPSK,
				wireguard.OptServerPeerAllowedIPs:   *peerIPs,
			}
			if *listenPort != 0 {
				opts[wireguard.OptServerListenPort] = fmt.Sprint(*listenPort)
			}
			if *mtu != 0 {
				opts[wireguard.OptServerMTU] = fmt.Sprint(*mtu)
			}
			return opts
		}, nil
	case "openvpn":
		var (
			ca       = fs.String("ca", "", "path to the CA certificate PEM (required)")
			cert     = fs.String("cert", "", "path to the server certificate PEM (required)")
			key      = fs.String("key", "", "path to the server private key PEM (required)")
			listenIP = fs.String("listen", "0.0.0.0", "local IP to bind the UDP socket on")
			port     = fs.Int("port", 0, "UDP port to listen on (default 1194)")
			pool     = fs.String("pool", "10.8.0.0/24", "internal address pool handed to clients")
			dns      = fs.String("dns", "", "comma-separated DNS servers pushed to clients")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				openvpn.OptServerCA:       *ca,
				openvpn.OptServerCert:     *cert,
				openvpn.OptServerKey:      *key,
				openvpn.OptServerListenIP: *listenIP,
				openvpn.OptServerPool:     *pool,
				openvpn.OptServerDNS:      *dns,
				openvpn.OptServerTUN:      *tun,
			}
			if *port != 0 {
				opts[openvpn.OptServerListenPort] = fmt.Sprint(*port)
			}
			return opts
		}, nil
	case "sstp":
		var (
			cert     = fs.String("cert", "", "path to the server TLS certificate PEM (required)")
			key      = fs.String("key", "", "path to the server TLS private key PEM (required)")
			listenIP = fs.String("listen", "0.0.0.0", "local IP to bind the TCP socket on")
			port     = fs.Int("port", 0, "TCP port to listen on (default 443)")
			pool     = fs.String("pool", "10.9.0.0/24", "internal address pool handed to clients")
			dns      = fs.String("dns", "", "comma-separated DNS servers assigned to clients")
			user     = fs.String("user", "", "MS-CHAPv2 username to accept (required)")
			pass     = fs.String("pass", "", "the user's password (required)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				sstp.OptServerCert:     *cert,
				sstp.OptServerKey:      *key,
				sstp.OptServerListenIP: *listenIP,
				sstp.OptServerPool:     *pool,
				sstp.OptServerDNS:      *dns,
				sstp.OptServerUser:     *user,
				sstp.OptServerPassword: *pass,
				sstp.OptServerTUN:      *tun,
			}
			if *port != 0 {
				opts[sstp.OptServerPort] = fmt.Sprint(*port)
			}
			return opts
		}, nil
	case "fortinet":
		var (
			cert     = fs.String("cert", "", "path to the server TLS certificate PEM (required)")
			key      = fs.String("key", "", "path to the server TLS private key PEM (required)")
			listenIP = fs.String("listen", "0.0.0.0", "local IP to bind the HTTPS socket on")
			port     = fs.Int("port", 0, "HTTPS port to listen on (default 443)")
			pool     = fs.String("pool", "10.40.0.0/24", "internal address pool handed to clients")
			dns      = fs.String("dns", "", "comma-separated DNS servers offered to clients")
			user     = fs.String("user", "", "username to accept (required)")
			pass     = fs.String("pass", "", "the user's password (required)")
			noDTLS   = fs.Bool("no-dtls", false, "serve the TLS tunnel only, leaving the UDP port unbound")
			totp     = fs.String("totp", "", "base32 TOTP secret; set it to require a second factor from the user")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				fortinet.OptServerCert:   *cert,
				fortinet.OptServerKey:    *key,
				fortinet.OptServerListen: *listenIP,
				fortinet.OptServerPool:   *pool,
				fortinet.OptServerDNS:    *dns,
				fortinet.OptServerUser:   *user,
				fortinet.OptServerPass:   *pass,
				fortinet.OptServerTOTP:   *totp,
				fortinet.OptServerTUN:    *tun,
			}
			if *port != 0 {
				opts[fortinet.OptServerPort] = fmt.Sprint(*port)
			}
			if *noDTLS {
				opts[fortinet.OptServerNoDTLS] = "true"
			}
			return opts
		}, nil
	case "masque":
		var (
			cert     = fs.String("cert", "", "path to the server TLS certificate PEM (required)")
			key      = fs.String("key", "", "path to the server TLS private key PEM (required)")
			listenIP = fs.String("listen", "0.0.0.0", "local IP to bind the UDP socket on")
			port     = fs.Int("port", 0, "UDP port to listen on (default 443)")
			pool     = fs.String("pool", "10.30.0.0/24", "internal address pool handed to clients")
			mtu      = fs.Int("mtu", 0, "inner MTU offered to clients (default 1350)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				masque.OptServerCert:   *cert,
				masque.OptServerKey:    *key,
				masque.OptServerListen: *listenIP,
				masque.OptServerPool:   *pool,
				masque.OptServerTUN:    *tun,
			}
			if *port != 0 {
				opts[masque.OptServerPort] = fmt.Sprint(*port)
			}
			if *mtu != 0 {
				opts[masque.OptServerMTU] = fmt.Sprint(*mtu)
			}
			return opts
		}, nil
	case "l2tp":
		var (
			listenIP = fs.String("listen", "0.0.0.0", "local IP to bind the IKE/ESP sockets on")
			public   = fs.String("public", "", "server's public IP as clients reach it (IKE identity and traffic selector); required when -listen is the wildcard")
			port     = fs.Int("port", 0, "UDP port to listen on (default 500)")
			psk      = fs.String("psk", "", "IPsec pre-shared key (required)")
			pool     = fs.String("pool", "10.20.0.0/24", "internal address pool handed to clients")
			dns      = fs.String("dns", "", "comma-separated DNS servers assigned to clients")
			user     = fs.String("user", "", "MS-CHAPv2 username to accept (required)")
			pass     = fs.String("pass", "", "the user's password (required)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				l2tp.OptServerListen:   *listenIP,
				l2tp.OptServerPublic:   *public,
				l2tp.OptServerPSK:      *psk,
				l2tp.OptServerPool:     *pool,
				l2tp.OptServerDNS:      *dns,
				l2tp.OptServerUser:     *user,
				l2tp.OptServerPassword: *pass,
				l2tp.OptServerTUN:      *tun,
			}
			if *port != 0 {
				opts[l2tp.OptServerPort] = fmt.Sprint(*port)
			}
			return opts
		}, nil
	case "toy":
		// An example protocol with no security whatsoever; see internal/toy.
		var (
			listenIP = fs.String("listen", "0.0.0.0", "local IP to bind the UDP socket on")
			port     = fs.Int("port", 0, "UDP port to listen on (default 5555)")
			pool     = fs.String("pool", "10.9.0.0/24", "internal address pool handed to clients")
			dns      = fs.String("dns", "", "comma-separated DNS servers assigned to clients")
			user     = fs.String("user", "", "username to accept (required)")
			secret   = fs.String("insecure-shared-secret", "", "that user's secret (required); provides no real protection")
			mtu      = fs.Int("mtu", 0, "inner MTU offered to clients (default 1400)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				toy.OptServerListen: *listenIP,
				toy.OptServerPool:   *pool,
				toy.OptServerDNS:    *dns,
				toy.OptServerUser:   *user,
				toy.OptServerSecret: *secret,
				toy.OptServerTUN:    *tun,
			}
			if *port != 0 {
				opts[toy.OptServerPort] = fmt.Sprint(*port)
			}
			if *mtu != 0 {
				opts[toy.OptServerMTU] = fmt.Sprint(*mtu)
			}
			return opts
		}, nil
	case "nebula":
		// `serve nebula` runs a lighthouse: an ordinary mesh member that also
		// answers questions about where other members are. There is no address
		// pool or user list, because a nebula host's address and identity come
		// from the certificate its CA signed.
		var (
			ca          = fs.String("ca", "", "path to the CA certificate bundle (required)")
			cert        = fs.String("cert", "", "path to this lighthouse's certificate (required)")
			key         = fs.String("key", "", "path to this lighthouse's X25519 private key (required)")
			listen      = fs.String("listen", "", "local UDP address to bind (default :4242)")
			staticHosts = fs.String("static-hosts", "", "peer locations: 10.42.0.1=192.0.2.10:4242[,...];...")
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
				nebula.OptCipher:      *cipher,
				nebula.OptTUN:         *tun,
			}
			if *mtu != 0 {
				opts[nebula.OptMTU] = fmt.Sprint(*mtu)
			}
			return opts
		}, nil
	case "anyconnect":
		var (
			cert     = fs.String("cert", "", "path to the server TLS certificate PEM (required)")
			key      = fs.String("key", "", "path to the server TLS private key PEM (required)")
			listenIP = fs.String("listen", "0.0.0.0", "local IP to bind the TCP socket on")
			port     = fs.Int("port", 0, "TCP port to listen on (default 443)")
			pool     = fs.String("pool", "10.11.0.0/24", "internal address pool handed to clients")
			dns      = fs.String("dns", "", "comma-separated DNS servers assigned to clients")
			user     = fs.String("user", "", "username to accept (required)")
			pass     = fs.String("pass", "", "the user's password (required)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				anyconnect.OptServerCert:     *cert,
				anyconnect.OptServerKey:      *key,
				anyconnect.OptServerListen:   *listenIP,
				anyconnect.OptServerPool:     *pool,
				anyconnect.OptServerDNS:      *dns,
				anyconnect.OptServerUser:     *user,
				anyconnect.OptServerPassword: *pass,
				anyconnect.OptServerTUN:      *tun,
			}
			if *port != 0 {
				opts[anyconnect.OptServerPort] = fmt.Sprint(*port)
			}
			return opts
		}, nil
	case "ssh":
		var (
			hostKey  = fs.String("host-key", "", "path to the server SSH host private key (required)")
			listenIP = fs.String("listen", "0.0.0.0", "local IP to bind the TCP socket on")
			port     = fs.Int("port", 0, "TCP port to listen on (default 22)")
			pool     = fs.String("pool", "10.200.0.0/24", "tunnel subnet clients use")
			dns      = fs.String("dns", "", "comma-separated DNS servers (informational)")
			user     = fs.String("user", "", "username to accept (password auth)")
			pass     = fs.String("pass", "", "the user's password")
			authKeys = fs.String("authorized-keys", "", "path to an authorized_keys file (public-key auth)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				ssh.OptServerHostKey:        *hostKey,
				ssh.OptServerListenIP:       *listenIP,
				ssh.OptServerPool:           *pool,
				ssh.OptServerDNS:            *dns,
				ssh.OptServerUser:           *user,
				ssh.OptServerPassword:       *pass,
				ssh.OptServerAuthorizedKeys: *authKeys,
				ssh.OptServerTUN:            *tun,
			}
			if *port != 0 {
				opts[ssh.OptServerPort] = fmt.Sprint(*port)
			}
			return opts
		}, nil
	default:
		return nil, fmt.Errorf("unknown protocol %q (server protocols: %s)",
			protocol, strings.Join(client.ServerProtocols(), ", "))
	}
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
