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

	"github.com/xen0bit/veepin/amneziawg"
	"github.com/xen0bit/veepin/anyconnect"
	"github.com/xen0bit/veepin/cisco"
	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/fortinet"
	"github.com/xen0bit/veepin/gp"
	"github.com/xen0bit/veepin/ikev2"
	"github.com/xen0bit/veepin/internal/hostnet"
	"github.com/xen0bit/veepin/internal/mgmt"
	"github.com/xen0bit/veepin/internal/mgmt/ui"
	"github.com/xen0bit/veepin/internal/supervisor"
	"github.com/xen0bit/veepin/l2tp"
	"github.com/xen0bit/veepin/l2tpv3"
	"github.com/xen0bit/veepin/masque"
	"github.com/xen0bit/veepin/nebula"
	"github.com/xen0bit/veepin/openvpn"
	"github.com/xen0bit/veepin/pulse"
	"github.com/xen0bit/veepin/softether"
	"github.com/xen0bit/veepin/ssh"
	"github.com/xen0bit/veepin/sstp"
	"github.com/xen0bit/veepin/toy"
	"github.com/xen0bit/veepin/wireguard"
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
			pool6    = fs.String("pool6", "", "internal IPv6 address pool, CIDR (default fd00:10:10::/64)")
			dns      = fs.String("dns", "1.1.1.1,8.8.8.8", "comma-separated DNS servers pushed to clients")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks, e.g. tun0)")
			eapUsers = fs.String("eap-users", "", "path to a username:password file enabling EAP-MSCHAPv2 auth (optional)")
			cert     = fs.String("cert", "", "server certificate PEM (enables certificate auth instead of PSK)")
			key      = fs.String("key", "", "server private-key PEM (with -cert)")
			clientCA = fs.String("client-ca", "", "CA bundle PEM enabling client certificate auth (optional)")
			shape    = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes: pads each inner flow's first N bytes to the tunnel MTU, hiding an inner TLS handshake's size pattern (0 = off, 16384 recommended)")
			iptfs    = fs.Bool("iptfs", false, "permit AGGFRAG / IP-TFS (RFC 9347) for clients that request it")
		)
		return func() map[string]string {
			return map[string]string{
				ikev2.OptServerIPTFS:    fmt.Sprint(*iptfs),
				ikev2.OptServerListen:   *listen,
				ikev2.OptServerPublic:   *public,
				ikev2.OptServerPSK:      *psk,
				ikev2.OptServerIdentity: *id,
				ikev2.OptServerPool:     *pool,
				ikev2.OptServerPool6:    *pool6,
				ikev2.OptServerDNS:      *dns,
				ikev2.OptServerTUN:      *tun,
				ikev2.OptServerEAPUsers: *eapUsers,
				ikev2.OptServerCert:     *cert,
				ikev2.OptServerKey:      *key,
				ikev2.OptServerClientCA: *clientCA,
				ikev2.OptServerShape:    fmt.Sprint(*shape),
			}
		}, nil
	case "amneziawg":
		// Same tunnel surface as `serve wireguard` — AmneziaWG changes only what
		// the packets look like — plus the obfuscation parameters, which must
		// match every client exactly because nothing about them is negotiated.
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
			peers      = fs.String("peers", "", "additional peers as a JSON array (managed by client-config generation)")
			shape      = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes (0 = off)")
			typeInit   = fs.Uint("type-init", 0, "H1: message type replacing handshake initiation (0 = stock 1)")
			typeResp   = fs.Uint("type-resp", 0, "H2: message type replacing handshake response (0 = stock 2)")
			typeCook   = fs.Uint("type-cookie", 0, "H3: message type replacing cookie reply (0 = stock 3)")
			typeTrans  = fs.Uint("type-trans", 0, "H4: message type replacing transport data (0 = stock 4)")
			padInit    = fs.Int("pad-init", 0, "S1: random bytes prepended to handshake initiation")
			padResp    = fs.Int("pad-resp", 0, "S2: random bytes prepended to handshake response")
			padCook    = fs.Int("pad-cookie", 0, "S3: random bytes prepended to cookie reply")
			padTrans   = fs.Int("pad-trans", 0, "S4: random bytes prepended to transport data")
		)
		return func() map[string]string {
			opts := map[string]string{
				amneziawg.OptServerConfig:           *config,
				amneziawg.OptServerPrivateKey:       *privKey,
				amneziawg.OptServerListenIP:         *listenIP,
				amneziawg.OptServerAddress:          *address,
				amneziawg.OptServerTUNName:          *tun,
				amneziawg.OptServerPeerPublicKey:    *peerPub,
				amneziawg.OptServerPeerPresharedKey: *peerPSK,
				amneziawg.OptServerPeerAllowedIPs:   *peerIPs,
				amneziawg.OptServerPeers:            *peers,
				amneziawg.OptServerShape:            fmt.Sprint(*shape),
				amneziawg.OptTypeInit:               fmt.Sprint(*typeInit),
				amneziawg.OptTypeResp:               fmt.Sprint(*typeResp),
				amneziawg.OptTypeCookie:             fmt.Sprint(*typeCook),
				amneziawg.OptTypeTrans:              fmt.Sprint(*typeTrans),
				amneziawg.OptPadInit:                fmt.Sprint(*padInit),
				amneziawg.OptPadResp:                fmt.Sprint(*padResp),
				amneziawg.OptPadCookie:              fmt.Sprint(*padCook),
				amneziawg.OptPadTrans:               fmt.Sprint(*padTrans),
			}
			if *listenPort != 0 {
				opts[amneziawg.OptServerListenPort] = fmt.Sprint(*listenPort)
			}
			if *mtu != 0 {
				opts[amneziawg.OptServerMTU] = fmt.Sprint(*mtu)
			}
			return opts
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
			peers      = fs.String("peers", "", "additional peers as a JSON array, e.g. [{\"public-key\":\"...\",\"allowed-ips\":[\"10.0.0.2/32\"]}]")
			shape      = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes: pads each inner flow's first N bytes to the tunnel MTU, hiding an inner TLS handshake's size pattern (0 = off, 16384 recommended)")
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
				wireguard.OptServerPeers:            *peers,
			}
			if *listenPort != 0 {
				opts[wireguard.OptServerListenPort] = fmt.Sprint(*listenPort)
			}
			if *mtu != 0 {
				opts[wireguard.OptServerMTU] = fmt.Sprint(*mtu)
			}
			opts[wireguard.OptServerShape] = fmt.Sprint(*shape)
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
			tlsAuth  = fs.String("tls-auth", "", "static key adding an HMAC to every control packet (must match the client's --tls-auth)")
			tlsCrypt = fs.String("tls-crypt", "", "static key encrypting and authenticating every control packet; drops an unauthenticated opener silently (must match the client's --tls-crypt)")
			auth     = fs.String("auth", "", "HMAC digest for -tls-auth: SHA1 (default) or SHA256")
			keyDir   = fs.Int("key-direction", -1, "the client's --key-direction for -tls-auth: 0, 1, or -1 for a bidirectional key")
			shape    = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes: pads each inner flow's first N bytes to the tunnel MTU, hiding an inner TLS handshake's size pattern (0 = off, 16384 recommended)")
		)
		return func() map[string]string {
			opts := map[string]string{
				openvpn.OptServerCA:           *ca,
				openvpn.OptServerCert:         *cert,
				openvpn.OptServerKey:          *key,
				openvpn.OptServerTLSAuth:      *tlsAuth,
				openvpn.OptServerTLSCrypt:     *tlsCrypt,
				openvpn.OptServerAuth:         *auth,
				openvpn.OptServerKeyDirection: fmt.Sprint(*keyDir),
				openvpn.OptServerListenIP:     *listenIP,
				openvpn.OptServerPool:         *pool,
				openvpn.OptServerDNS:          *dns,
				openvpn.OptServerTUN:          *tun,
			}
			if *shape != 0 {
				opts[openvpn.OptServerShape] = fmt.Sprint(*shape)
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
			shape    = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes: pads each inner flow's first N bytes to the tunnel MTU, hiding an inner TLS handshake's size pattern (0 = off, 16384 recommended)")
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
			if *shape != 0 {
				opts[sstp.OptServerShape] = fmt.Sprint(*shape)
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
			shape    = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes: pads each inner flow's first N bytes to the tunnel MTU, hiding an inner TLS handshake's size pattern (0 = off, 16384 recommended)")
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
			if *shape != 0 {
				opts[fortinet.OptServerShape] = fmt.Sprint(*shape)
			}
			if *port != 0 {
				opts[fortinet.OptServerPort] = fmt.Sprint(*port)
			}
			if *noDTLS {
				opts[fortinet.OptServerNoDTLS] = "true"
			}
			return opts
		}, nil
	case "cisco":
		var (
			listenIP     = fs.String("listen", "0.0.0.0", "local IP to bind the IKE sockets on")
			port         = fs.Int("port", 0, "IKE port to listen on (default 500; the NAT-T port is always 4500)")
			group        = fs.String("group", "", "group name clients must present (required)")
			groupPSK     = fs.String("group-psk", "", "the group's pre-shared key (required)")
			user         = fs.String("user", "", "XAuth username to accept (required)")
			pass         = fs.String("pass", "", "the user's password (required)")
			pool         = fs.String("pool", "10.60.0.0/24", "internal address pool handed to clients")
			dns          = fs.String("dns", "", "comma-separated DNS servers offered to clients")
			domain       = fs.String("domain", "", "default search domain offered to clients")
			banner       = fs.String("banner", "", "login banner shown to clients")
			splitInclude = fs.String("split-include", "", "comma-separated CIDRs clients should route into the tunnel (empty = everything)")
			public       = fs.String("public", "", "address clients reach this gateway on (empty = the bound address)")
			tun          = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
			shape        = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes: pads each inner flow's first N bytes towards the tunnel MTU with RFC 4303 traffic-flow padding (0 = off, 16384 recommended)")
		)
		return func() map[string]string {
			opts := map[string]string{
				cisco.OptServerListen:       *listenIP,
				cisco.OptServerGroup:        *group,
				cisco.OptServerGroupPSK:     *groupPSK,
				cisco.OptServerUser:         *user,
				cisco.OptServerPass:         *pass,
				cisco.OptServerPool:         *pool,
				cisco.OptServerDNS:          *dns,
				cisco.OptServerDomain:       *domain,
				cisco.OptServerBanner:       *banner,
				cisco.OptServerSplitInclude: *splitInclude,
				cisco.OptServerTUN:          *tun,
			}
			if *port != 0 {
				opts[cisco.OptServerPort] = fmt.Sprint(*port)
			}
			if *public != "" {
				opts[cisco.OptServerPublicIP] = *public
			}
			if *shape != 0 {
				opts[cisco.OptServerShape] = fmt.Sprint(*shape)
			}
			return opts
		}, nil
	case "pulse":
		var (
			cert         = fs.String("cert", "", "path to the server TLS certificate PEM (required)")
			key          = fs.String("key", "", "path to the server TLS private key PEM (required)")
			listenIP     = fs.String("listen", "0.0.0.0", "local IP to bind the HTTPS socket on")
			port         = fs.Int("port", 0, "HTTPS port to listen on (default 443)")
			espPort      = fs.Int("esp-port", 0, "UDP port for the ESP data path (default 4500)")
			public       = fs.String("public", "", "address clients reach this gateway on (empty = the bound address)")
			pool         = fs.String("pool", "10.70.0.0/24", "internal address pool handed to clients")
			dns          = fs.String("dns", "", "comma-separated DNS servers offered to clients")
			domain       = fs.String("domain", "", "DNS search domain offered to clients")
			splitInclude = fs.String("split-include", "", "comma-separated CIDRs clients should route into the tunnel (empty = everything)")
			user         = fs.String("user", "", "username to accept (required)")
			pass         = fs.String("pass", "", "the user's password (required)")
			noESP        = fs.Bool("no-esp", false, "serve the IF-T/TLS data path only, leaving the UDP port unbound")
			tun          = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
			shape        = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes: pads each inner flow's first N bytes towards the tunnel MTU (0 = off, 16384 recommended)")
		)
		return func() map[string]string {
			opts := map[string]string{
				pulse.OptServerCert:         *cert,
				pulse.OptServerKey:          *key,
				pulse.OptServerListen:       *listenIP,
				pulse.OptServerPool:         *pool,
				pulse.OptServerDNS:          *dns,
				pulse.OptServerDomain:       *domain,
				pulse.OptServerSplitInclude: *splitInclude,
				pulse.OptServerUser:         *user,
				pulse.OptServerPass:         *pass,
				pulse.OptServerTUN:          *tun,
			}
			if *port != 0 {
				opts[pulse.OptServerPort] = fmt.Sprint(*port)
			}
			if *espPort != 0 {
				opts[pulse.OptServerESPPort] = fmt.Sprint(*espPort)
			}
			if *public != "" {
				opts[pulse.OptServerPublicIP] = *public
			}
			if *shape != 0 {
				opts[pulse.OptServerShape] = fmt.Sprint(*shape)
			}
			if *noESP {
				opts[pulse.OptServerNoESP] = "true"
			}
			return opts
		}, nil
	case "gp":
		var (
			cert     = fs.String("cert", "", "path to the server TLS certificate PEM (required)")
			key      = fs.String("key", "", "path to the server TLS private key PEM (required)")
			listenIP = fs.String("listen", "0.0.0.0", "local IP to bind the HTTPS socket on")
			port     = fs.Int("port", 0, "HTTPS port to listen on (default 443)")
			espPort  = fs.Int("esp-port", 0, "UDP port for the ESP data path (default 4501)")
			public   = fs.String("public", "", "address clients reach this gateway on, advertised as the ESP endpoint (empty = the address their control connection arrived on)")
			pool     = fs.String("pool", "10.50.0.0/24", "internal address pool handed to clients")
			dns      = fs.String("dns", "", "comma-separated DNS servers offered to clients")
			user     = fs.String("user", "", "username to accept (required)")
			pass     = fs.String("pass", "", "the user's password (required)")
			noESP    = fs.Bool("no-esp", false, "serve the SSL tunnel only, leaving the UDP port unbound")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
			shape    = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes: pads each inner flow's first N bytes to the tunnel MTU, hiding an inner TLS handshake's size pattern (0 = off, 16384 recommended)")
		)
		return func() map[string]string {
			opts := map[string]string{
				gp.OptServerCert:   *cert,
				gp.OptServerKey:    *key,
				gp.OptServerListen: *listenIP,
				gp.OptServerPool:   *pool,
				gp.OptServerDNS:    *dns,
				gp.OptServerUser:   *user,
				gp.OptServerPass:   *pass,
				gp.OptServerTUN:    *tun,
			}
			if *port != 0 {
				opts[gp.OptServerPort] = fmt.Sprint(*port)
			}
			if *espPort != 0 {
				opts[gp.OptServerESPPort] = fmt.Sprint(*espPort)
			}
			if *public != "" {
				opts[gp.OptServerPublicIP] = *public
			}
			if *shape != 0 {
				opts[gp.OptServerShape] = fmt.Sprint(*shape)
			}
			if *noESP {
				opts[gp.OptServerNoESP] = "true"
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
			shape    = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes: pads each inner flow's first N bytes to the tunnel MTU, hiding an inner TLS handshake's size pattern (0 = off, 16384 recommended)")
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
			if *shape != 0 {
				opts[l2tp.OptServerShape] = fmt.Sprint(*shape)
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
			noDTLS   = fs.Bool("no-dtls", false, "serve the TLS tunnel only, leaving the UDP port unbound")
			shape    = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes: pads each inner flow's first N bytes to the tunnel MTU, hiding an inner TLS handshake's size pattern (0 = off, 16384 recommended)")
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
				anyconnect.OptServerNoDTLS:   fmt.Sprint(*noDTLS),
			}
			if *shape != 0 {
				opts[anyconnect.OptServerShape] = fmt.Sprint(*shape)
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
	case "softether":
		var (
			cert   = fs.String("cert", "", "path to TLS certificate PEM (required)")
			key    = fs.String("key", "", "path to TLS private key PEM (required)")
			user   = fs.String("user", "", "username to accept (required)")
			pass   = fs.String("pass", "", "password to accept (required)")
			tun    = fs.String("tun", "", "TAP interface name (empty = kernel picks)")
			pool   = fs.String("pool", "10.70.0.0/24", "address pool")
			listen = fs.String("listen", "", "local IP to bind the TLS listener on (default 0.0.0.0)")
			port   = fs.Int("port", 0, "TLS port to listen on (default 443)")
		)
		return func() map[string]string {
			opts := map[string]string{
				softether.OptServerCert:   *cert,
				softether.OptServerKey:    *key,
				softether.OptServerUser:   *user,
				softether.OptServerPass:   *pass,
				softether.OptServerTUN:    *tun,
				softether.OptServerPool:   *pool,
				softether.OptServerListen: *listen,
			}
			if *port != 0 {
				opts[softether.OptServerPort] = fmt.Sprint(*port)
			}
			return opts
		}, nil
	case "l2tpv3":
		var (
			listen    = fs.String("listen", "", "local IP to bind (default 0.0.0.0)")
			port      = fs.Int("port", 0, "UDP port (default 1701)")
			sid       = fs.Uint("session-id", 0, "our session ID: what the peer sends to (required)")
			psid      = fs.Uint("peer-session-id", 0, "the peer's session ID: what we send to (required)")
			cookie    = fs.String("cookie", "", "hex cookie WE chose, verified on inbound packets (0, 4 or 8 octets)")
			pcookie   = fs.String("peer-cookie", "", "hex cookie the PEER chose, written on outbound packets")
			sublayer  = fs.Bool("sublayer", false, "carry the Default L2-Specific Sublayer (the Linux kernel sends one)")
			tun       = fs.String("tun", "", "TAP interface name (empty = kernel picks)")
			shape     = fs.Int("shape", 0, "per-flow downstream shaping budget in bytes; pads IP-bearing frames only (0 = off)")
			ccid      = fs.Uint("ccid", 0, "our Control Connection ID; with -peer-ccid, enables HELLO keepalives (RFC 3931 quiescent tunnel)")
			pccid     = fs.Uint("peer-ccid", 0, "the peer's Control Connection ID")
			keepalive = fs.Int("keepalive", 0, "HELLO interval in seconds (default 30)")
		)
		return func() map[string]string {
			opts := map[string]string{
				l2tpv3.OptServerShape:  fmt.Sprint(*shape),
				l2tpv3.OptCCID:         fmt.Sprint(*ccid),
				l2tpv3.OptPeerCCID:     fmt.Sprint(*pccid),
				l2tpv3.OptKeepalive:    fmt.Sprint(*keepalive),
				l2tpv3.OptServerListen: *listen,
				l2tpv3.OptTUN:          *tun,
				l2tpv3.OptSessionID:    fmt.Sprint(*sid),
				l2tpv3.OptPeerSession:  fmt.Sprint(*psid),
				l2tpv3.OptCookie:       *cookie,
				l2tpv3.OptPeerCookie:   *pcookie,
			}
			if *port != 0 {
				opts[l2tpv3.OptPort] = fmt.Sprint(*port)
			}
			if *sublayer {
				opts[l2tpv3.OptSublayer] = "true"
			}
			return opts
		}, nil
	default:
		return nil, fmt.Errorf("unknown protocol %q (server protocols: %s)",
			protocol, strings.Join(client.ServerProtocols(), ", "))
	}
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
