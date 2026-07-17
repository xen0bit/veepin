package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/ikev2"
	"github.com/xen0bit/veepin/openvpn"
	"github.com/xen0bit/veepin/ssh"
	"github.com/xen0bit/veepin/sstp"
	"github.com/xen0bit/veepin/wireguard"
)

// runConnect brings up a tunnel and applies the negotiated configuration to the
// system. The dial itself is protocol-agnostic — everything specific to a
// protocol is in the flag set that produces its options.
func runConnect(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: veepin connect <protocol> [flags]\nprotocols: %s",
			strings.Join(client.Protocols(), ", "))
	}
	protocol, args := args[0], args[1:]

	fs := flag.NewFlagSet("connect "+protocol, flag.ContinueOnError)
	fullTunnel := fs.Bool("full-tunnel", true, "route all traffic through the VPN (default route)")
	noRoute := fs.Bool("no-route", false, "do not modify routing/addresses (diagnostic)")

	options, err := connectFlags(protocol, fs)
	if err != nil {
		return err
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	// 1. Handshake + data path. Dial installs no routes — that is this command's
	// job, and the split is what lets NetworkManager reuse the same dial.
	sess, res, err := client.Dial(context.Background(), protocol, options())
	if err != nil {
		return err
	}
	defer sess.Close()
	logger.Printf("connected on %s, internal IP %s, netmask %s, DNS %v",
		res.TUNName, res.AssignedIP, res.Netmask, res.DNS)

	// 2. Routing.
	if !*noRoute {
		router := dataplane.NewClientRouter(dataplane.ClientNetConfig{
			TUNName:    res.TUNName,
			AssignedIP: res.AssignedIP,
			Netmask:    res.Netmask,
			ServerIP:   res.Gateway,
			DNS:        res.DNS,
			FullTunnel: *fullTunnel,
		})
		if err := router.Apply(); err != nil {
			logger.Printf("routing setup failed: %v (continuing without routes)", err)
		} else {
			logger.Printf("routing configured (full-tunnel=%v)", *fullTunnel)
			defer func() {
				if rerr := router.Revert(); rerr != nil {
					logger.Printf("route cleanup: %v", rerr)
				}
			}()
		}
	}

	logger.Printf("tunnel up. Press Ctrl-C to disconnect.")

	// 3. Wait for a signal or for the session to end on its own.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	_ = sess.Wait(ctx)
	logger.Printf("disconnecting")
	return nil
}

// connectFlags binds a protocol's flags onto fs and returns a function that
// collects them into the option map client.Dial parses. A new protocol adds a
// case here; nothing else in this command changes.
func connectFlags(protocol string, fs *flag.FlagSet) (func() map[string]string, error) {
	switch protocol {
	case "ikev2":
		var (
			server   = fs.String("server", "", "VPN server host or IP (required)")
			port     = fs.Int("port", 0, "server IKE port (default 500)")
			psk      = fs.String("psk", "", "pre-shared key (required)")
			id       = fs.String("id", "", "local identity presented to the server (required)")
			serverID = fs.String("server-id", "", "expected server identity (optional, verified if set)")
			user     = fs.String("user", "", "EAP-MSCHAPv2 username (enables EAP instead of client PSK)")
			pass     = fs.String("pass", "", "EAP-MSCHAPv2 password")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				ikev2.OptGateway:  *server,
				ikev2.OptPSK:      *psk,
				ikev2.OptLocalID:  *id,
				ikev2.OptServerID: *serverID,
				ikev2.OptUser:     *user,
				ikev2.OptPassword: *pass,
				ikev2.OptTUNName:  *tun,
			}
			if *port != 0 {
				opts[ikev2.OptPort] = fmt.Sprint(*port)
			}
			return opts
		}, nil
	case "wireguard":
		var (
			config    = fs.String("config", "", "wg-quick style config file (flags below override its values)")
			privKey   = fs.String("private-key", "", "our static private key, base64")
			address   = fs.String("address", "", "our tunnel address in CIDR form, e.g. 10.0.0.2/32")
			dns       = fs.String("dns", "", "comma-separated DNS servers (optional)")
			mtu       = fs.Int("mtu", 0, "inner MTU (default 1420)")
			pubKey    = fs.String("public-key", "", "peer static public key, base64")
			psk       = fs.String("preshared-key", "", "optional preshared key, base64")
			endpoint  = fs.String("endpoint", "", "peer host:port, e.g. vpn.example.com:51820")
			allowed   = fs.String("allowed-ips", "", "comma-separated destinations routed to the peer, e.g. 0.0.0.0/0")
			keepalive = fs.Int("persistent-keepalive", 0, "keepalive interval in seconds (0 = off)")
			rekey     = fs.Int("rekey-seconds", 0, "seconds between key refreshes (0 = protocol default, 120)")
			tun       = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				wireguard.OptConfig:       *config,
				wireguard.OptPrivateKey:   *privKey,
				wireguard.OptAddress:      *address,
				wireguard.OptDNS:          *dns,
				wireguard.OptPublicKey:    *pubKey,
				wireguard.OptPresharedKey: *psk,
				wireguard.OptEndpoint:     *endpoint,
				wireguard.OptAllowedIPs:   *allowed,
				wireguard.OptTUNName:      *tun,
			}
			if *mtu != 0 {
				opts[wireguard.OptMTU] = fmt.Sprint(*mtu)
			}
			if *keepalive != 0 {
				opts[wireguard.OptKeepalive] = fmt.Sprint(*keepalive)
			}
			if *rekey != 0 {
				opts[wireguard.OptRekeySeconds] = fmt.Sprint(*rekey)
			}
			return opts
		}, nil
	case "openvpn":
		var (
			config   = fs.String("config", "", ".ovpn profile (flags below override its values)")
			remote   = fs.String("remote", "", "server host or IP")
			port     = fs.Int("port", 0, "server UDP port (default 1194)")
			ca       = fs.String("ca", "", "path to the CA certificate PEM")
			cert     = fs.String("cert", "", "path to the client certificate PEM")
			key      = fs.String("key", "", "path to the client private key PEM")
			cipher   = fs.String("cipher", "", "data cipher: AES-256-GCM (default) or AES-256-CBC")
			auth     = fs.String("auth", "", "HMAC digest for tls-auth and the CBC data channel (default SHA1)")
			tlsAuth  = fs.String("tls-auth", "", "path to a --tls-auth static key")
			tlsCrypt = fs.String("tls-crypt", "", "path to a --tls-crypt static key")
			keyDir   = fs.Int("key-direction", -1, "tls-auth key direction: 0 or 1 (default: bidirectional)")
			user     = fs.String("username", "", "auth-user-pass username (optional)")
			pass     = fs.String("password", "", "auth-user-pass password (optional)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				openvpn.OptConfig:   *config,
				openvpn.OptRemote:   *remote,
				openvpn.OptCA:       *ca,
				openvpn.OptCert:     *cert,
				openvpn.OptKey:      *key,
				openvpn.OptCipher:   *cipher,
				openvpn.OptAuth:     *auth,
				openvpn.OptTLSAuth:  *tlsAuth,
				openvpn.OptTLSCrypt: *tlsCrypt,
				openvpn.OptUsername: *user,
				openvpn.OptPassword: *pass,
				openvpn.OptTUNName:  *tun,
			}
			if *port != 0 {
				opts[openvpn.OptPort] = fmt.Sprint(*port)
			}
			if *keyDir >= 0 {
				opts[openvpn.OptKeyDirection] = fmt.Sprint(*keyDir)
			}
			return opts
		}, nil
	case "sstp":
		var (
			server   = fs.String("server", "", "SSTP server host or IP (required)")
			port     = fs.Int("port", 0, "server TCP port (default 443)")
			user     = fs.String("user", "", "MS-CHAPv2 username (required)")
			pass     = fs.String("pass", "", "MS-CHAPv2 password (required)")
			insecure = fs.Bool("insecure", false, "skip TLS certificate verification (self-signed servers)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				sstp.OptServer:   *server,
				sstp.OptUser:     *user,
				sstp.OptPassword: *pass,
				sstp.OptTUNName:  *tun,
			}
			if *port != 0 {
				opts[sstp.OptPort] = fmt.Sprint(*port)
			}
			if *insecure {
				opts[sstp.OptInsecure] = "true"
			}
			return opts
		}, nil
	case "ssh":
		var (
			server   = fs.String("server", "", "SSH server host or IP (required)")
			port     = fs.Int("port", 0, "server TCP port (default 22)")
			user     = fs.String("user", "", "SSH username (required)")
			identity = fs.String("identity", "", "path to a private key")
			pass     = fs.String("pass", "", "password (if not using a key)")
			knownH   = fs.String("known-hosts", "", "known_hosts file for host-key verification")
			insecure = fs.Bool("insecure", false, "skip host-key verification")
			address  = fs.String("address", "", "our tunnel address in CIDR form, e.g. 10.200.0.2/30 (required)")
			peer     = fs.String("peer", "", "server tunnel address (point-to-point peer), e.g. 10.200.0.1")
			peerUnit = fs.Int("peer-unit", -1, "remote tun unit to request (default: any; a stock sshd needs a specific unit)")
			dns      = fs.String("dns", "", "comma-separated DNS servers (optional)")
			tun      = fs.String("tun", "", "TUN interface name (empty = kernel picks)")
		)
		return func() map[string]string {
			opts := map[string]string{
				ssh.OptServer:     *server,
				ssh.OptUser:       *user,
				ssh.OptIdentity:   *identity,
				ssh.OptPassword:   *pass,
				ssh.OptKnownHosts: *knownH,
				ssh.OptAddress:    *address,
				ssh.OptPeer:       *peer,
				ssh.OptDNS:        *dns,
				ssh.OptTUNName:    *tun,
			}
			if *port != 0 {
				opts[ssh.OptPort] = fmt.Sprint(*port)
			}
			if *peerUnit >= 0 {
				opts[ssh.OptPeerUnit] = fmt.Sprint(*peerUnit)
			}
			if *insecure {
				opts[ssh.OptInsecure] = "true"
			}
			return opts
		}, nil
	default:
		return nil, fmt.Errorf("unknown protocol %q (available: %s)",
			protocol, strings.Join(client.Protocols(), ", "))
	}
}
