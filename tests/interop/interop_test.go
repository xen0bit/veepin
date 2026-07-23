//go:build interop

// Docker-based interoperability tests: they stand up veepin and strongSwan in
// containers and prove a real ESP-in-UDP tunnel by pinging across it, in both
// directions. Run with `make interop` or `go test -tags interop ./tests/interop/`.
//
// These shell out to `docker compose`; they are stdlib-only (no new module
// dependency) and skip cleanly where Docker is unavailable.
package interop

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/livingreadme"
)

// pingDeadline bounds how long we retry the cross-tunnel ping. It must cover
// image build, container start, the client's connect-retry loop, and (for
// strongSwan) charon startup.
const pingDeadline = 100 * time.Second

// logDeadline bounds how long we wait for a line that proves *which* carrier is
// moving packets. It is separate from pingDeadline because it starts only once
// the tunnel is already up, and the thing it waits for (a DTLS channel coming up
// beside the TLS tunnel, with a retry if the first attempt loses a datagram) is
// slower on a loaded CI runner than on a developer's machine.
const logDeadline = 60 * time.Second

// TestInteropSelf is the infra sanity check: veepin client <-> veepin server.
// It isolates the container/TUN/NAT-T/ping harness from strongSwan.
func TestInteropSelf(t *testing.T) {
	runInteropBench(t, "compose.selftest.yml", "client", "server", "10.10.10.1")
}

// TestInteropVeepinClientStrongswanServer is Direction A: the veepin client
// (ikev2) tunnels to a strongSwan responder and pings a strongSwan-side address.
func TestInteropVeepinClientStrongswanServer(t *testing.T) {
	runInteropBench(t, "compose.client-ss.yml", "veepin-client", "strongswan-server", "10.20.30.254")
}

// TestInteropStrongswanClientVeepinServer is Direction B: a strongSwan
// initiator tunnels to the veepin server (`veepin serve ikev2`) and pings its TUN gateway.
func TestInteropStrongswanClientVeepinServer(t *testing.T) {
	runInteropBench(t, "compose.server-ss.yml", "strongswan-client", "veepin-server", "10.10.10.1")
}

// TestInteropStrongswanClientVeepinServerFragmented is Direction B with IKE
// fragmentation forced (RFC 7383): the strongSwan initiator splits its IKE_AUTH
// into SKF fragments (fragmentation=force + a small fragment_size), which the
// veepin server must reassemble before it can authenticate the peer. A
// successful in-tunnel ping proves the reassembled IKE_AUTH established the SA.
func TestInteropStrongswanClientVeepinServerFragmented(t *testing.T) {
	runInterop(t, "compose.server-ss-frag.yml", "strongswan-client", "10.10.10.1")
}

// TestInteropVeepinClientWireguardServer proves the WireGuard initiator against
// the reference wireguard-go responder: the veepin client performs the
// Noise_IKpsk2 handshake and transport data path, then pings 10.10.10.1 (the
// responder's tunnel address) across it. A success exercises the handshake,
// the counter-nonce transport crypto, and cryptokey routing end to end against
// an implementation veepin shares no code with.
func TestInteropVeepinClientWireguardServer(t *testing.T) {
	runInteropBench(t, "compose.wireguard.yml", "veepin-wg-client", "wg-server", "10.10.10.1")
}

// TestInteropWireguardClientVeepinServer is the mirror: a real wireguard-go
// client performs the handshake against the veepin *server* (`veepin serve
// wireguard`) and pings its tunnel gateway. It proves the responder — mac1
// verification, static-key lookup, the response message, and multi-peer
// cryptokey routing — against a client veepin shares no code with.
func TestInteropWireguardClientVeepinServer(t *testing.T) {
	runInteropBench(t, "compose.wireguard-server.yml", "wg-client", "veepin-wg-server", "10.10.10.1")
}

// TestInteropWireguardSelf is the veepin<->veepin WireGuard sanity check: the
// veepin client and server over real sockets and TUNs, isolating a veepin break
// from an interop break.
func TestInteropWireguardSelf(t *testing.T) {
	runInteropBench(t, "compose.wireguard-self.yml", "veepin-wg-client", "veepin-wg-server", "10.10.10.1")
}

// TestInteropVeepinClientOpenVPNServer proves the OpenVPN client against a real
// OpenVPN server it shares no code with: the veepin client runs the TLS control
// channel, key method 2 exchange and AES-256-GCM data path, then pings 10.8.0.1
// (the server's tunnel address). A shared throwaway PKI is generated per run and
// mounted into both ends, so no keys live in the repo.
func TestInteropVeepinClientOpenVPNServer(t *testing.T) {
	runOpenVPNInterop(t, "compose.openvpn.yml")
}

// TestInteropOpenVPNTLSAuth adds --tls-auth: an HMAC-SHA256 over every
// control-channel packet under a shared static key (server key-direction 0,
// client 1). It proves the veepin client's control-channel HMAC wrapping and
// replay/packet-id handling against a real server, with the AES-GCM data path
// unchanged.
func TestInteropOpenVPNTLSAuth(t *testing.T) {
	runOpenVPNInterop(t, "compose.openvpn-tls-auth.yml")
}

// TestInteropOpenVPNTLSCrypt adds --tls-crypt: HMAC-SHA256 authentication and
// AES-256-CTR encryption of every control-channel packet. It proves the veepin
// client's tls-crypt wrap/unwrap and key derivation against a real server.
func TestInteropOpenVPNTLSCrypt(t *testing.T) {
	runOpenVPNInterop(t, "compose.openvpn-tls-crypt.yml")
}

// TestInteropOpenVPNCBC exercises the older AES-256-CBC data channel
// (encrypt-then-MAC, HMAC-SHA256) instead of AES-GCM. It proves the veepin
// client's non-AEAD seal/open, PKCS#7 padding, and CBC key derivation against a
// real server.
func TestInteropOpenVPNCBC(t *testing.T) {
	runOpenVPNInterop(t, "compose.openvpn-cbc.yml")
}

// TestInteropVeepinClientSSTPServer proves the SSTP client against a real
// SoftEther SSTP server it shares no code with. An `init` sidecar provisions the
// server (enables SSTP, creates the MS-CHAPv2 user, turns on SecureNAT), then the
// veepin client runs the TLS carrier, the SSTP_DUPLEX_POST handshake, the
// CALL_CONNECT crypto binding, MS-CHAPv2 authentication and the PPP/IPCP data
// path, and pings 192.168.30.1 (the SecureNAT virtual gateway) across the tunnel.
// A success exercises the whole SSTP stack end to end against Microsoft's wire
// format.
func TestInteropVeepinClientSSTPServer(t *testing.T) {
	runInterop(t, "compose.sstp.yml", "client", "192.168.30.1")
}

// TestInteropSSTPSelf is the veepin<->veepin SSTP sanity check: the veepin client
// and server over a real TLS/TCP connection and TUNs. It exercises the SSTP
// responder end to end — the SSTP_DUPLEX_POST handshake, CALL_CONNECT_ACK nonce,
// the server-role PPP/MS-CHAPv2 authentication, crypto-binding verification, and
// IPCP address assignment — isolating a veepin break from an interop break.
func TestInteropSSTPSelf(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("sstp", "pki")
	if err := generateSSTPServerCert(pkiDir); err != nil {
		t.Fatalf("generate SSTP cert: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInteropBench(t, "compose.sstp-self.yml", "veepin-sstp-client", "veepin-sstp-server", "10.9.0.1")
}

// TestInteropSSTPClientVeepinServer is the reverse direction: a real SSTP client
// (sstp-client's sstpc driving pppd) tunnels to the veepin *server* and pings its
// tunnel gateway. It proves the responder — the SSTP_DUPLEX_POST handshake, the
// CALL_CONNECT_ACK nonce, the server-role PPP/MS-CHAPv2 authenticator, crypto
// binding verification and IPCP assignment — against a client veepin shares no
// code with.
func TestInteropSSTPClientVeepinServer(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("sstp", "pki")
	if err := generateSSTPServerCert(pkiDir); err != nil {
		t.Fatalf("generate SSTP cert: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInteropBench(t, "compose.sstp-server.yml", "sstp-client", "veepin-sstp-server", "10.9.0.1")
}

// TestInteropSSHSelf is the veepin<->veepin SSH sanity check: the veepin client
// and server over a real SSH/TCP connection and TUNs, forwarding IP through the
// tun@openssh.com channel. It exercises the whole SSH VPN path — the SSH
// handshake, key auth, tunnel-channel open, and the address-family packet framing
// — isolating a veepin break from an interop break.
func TestInteropSSHSelf(t *testing.T) {
	requireDocker(t)
	keyDir := filepath.Join("ssh", "keys")
	if err := generateSSHKeys(keyDir); err != nil {
		t.Fatalf("generate SSH keys: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(keyDir) })
	runInteropBench(t, "compose.ssh-self.yml", "veepin-ssh-client", "veepin-ssh-server", "10.200.0.1")
}

// TestInteropSSHClientVeepinServer is the reverse direction: a real OpenSSH
// client (`ssh -w`) opens a tunnel-forwarding channel to the veepin *server* and
// pings its tunnel gateway. It proves the responder — the SSH server handshake,
// the tun@openssh.com channel, and the address-family packet framing — against a
// client veepin shares no code with, and is the real check on the framing.
func TestInteropSSHClientVeepinServer(t *testing.T) {
	requireDocker(t)
	keyDir := filepath.Join("ssh", "keys")
	if err := generateSSHKeys(keyDir); err != nil {
		t.Fatalf("generate SSH keys: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(keyDir) })
	runInteropBench(t, "compose.ssh-server.yml", "ssh-client", "veepin-ssh-server", "10.200.0.1")
}

// TestInteropVeepinClientSSHServer proves the veepin SSH client against a real
// OpenSSH server (sshd with PermitTunnel yes): the client opens the
// tun@openssh.com channel, requesting the remote unit sshd binds to its
// pre-configured tun0, and pings the server's tunnel address across the tunnel.
func TestInteropVeepinClientSSHServer(t *testing.T) {
	requireDocker(t)
	keyDir := filepath.Join("ssh", "keys")
	if err := generateSSHKeys(keyDir); err != nil {
		t.Fatalf("generate SSH keys: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(keyDir) })
	runInteropBench(t, "compose.ssh-sshd.yml", "veepin-ssh-client", "sshd", "10.200.0.1")
}

// runOpenVPNInterop generates the shared throwaway PKI (and static key), then
// runs an OpenVPN client-vs-server ping across the given compose profile.
func runOpenVPNInterop(t *testing.T, composeFile string) {
	t.Helper()
	requireDocker(t)
	pkiDir := filepath.Join("openvpn", "pki")
	if err := generateOpenVPNPKI(pkiDir); err != nil {
		t.Fatalf("generate PKI: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInteropBench(t, composeFile, "veepin-ovpn-client", "openvpn-server", "10.8.0.1")
}

// TestInteropOpenVPNClientVeepinServer is the reverse direction: a real OpenVPN
// client tunnels to the veepin *server* (`veepin serve openvpn`) and pings its
// tunnel gateway. It proves the responder — the server-role TLS control channel,
// the key method 2 server exchange, PUSH_REPLY address assignment and the
// server's data path — against a client veepin shares no code with.
func TestInteropOpenVPNClientVeepinServer(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("openvpn", "pki")
	if err := generateOpenVPNPKI(pkiDir); err != nil {
		t.Fatalf("generate PKI: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInteropBench(t, "compose.openvpn-server.yml", "openvpn-client", "veepin-ovpn-server", "10.8.0.1")
}

// TestInteropOpenVPNSelf is the veepin<->veepin OpenVPN sanity check: the veepin
// client and server over a real socket and TUNs, isolating a veepin break from
// an interop break.
func TestInteropOpenVPNSelf(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("openvpn", "pki")
	if err := generateOpenVPNPKI(pkiDir); err != nil {
		t.Fatalf("generate PKI: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInteropBench(t, "compose.openvpn-self.yml", "veepin-ovpn-client", "veepin-ovpn-server", "10.8.0.1")
}

// TestInteropWireguardRekey proves the client rekey loop end to end: the veepin
// client re-runs the handshake every few seconds (a shrunk REKEY_SECONDS),
// rotating a fresh keypair and receiver index into a live tunnel, while a
// sustained ping runs across those rotations. Zero packet loss shows the
// keypair-set data path holds the tunnel open through each rekey, and the
// server's repeated handshakes show the rekeys are real rather than one session
// coasting under its original key.
func TestInteropWireguardRekey(t *testing.T) {
	requireDocker(t)
	const file = "compose.wireguard-rekey.yml"

	if out, err := compose(t, file, "up", "--build", "-d"); err != nil {
		t.Fatalf("compose up: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			if logs, err := compose(t, file, "logs", "--no-color"); err == nil {
				t.Logf("--- compose logs (%s) ---\n%s", file, logs)
			}
		}
		_, _ = compose(t, file, "down", "-v", "--timeout", "5")
	})

	// 1. Wait for the tunnel to come up (first successful ping).
	if !waitPing(t, file, "veepin-wg-client", "10.10.10.1") {
		t.Fatalf("tunnel never came up within %s", pingDeadline)
	}

	// 2. Sustain traffic across several rekey intervals. With REKEY_SECONDS=8, a
	// ~48-second ping spans roughly six key rotations; a break in the data path
	// across any receiver-index change would surface as loss here.
	out, err := compose(t, file, "exec", "-T", "veepin-wg-client",
		"ping", "-c", "48", "-i", "1", "-W", "2", "10.10.10.1")
	if err != nil || !strings.Contains(out, "0% packet loss") {
		t.Fatalf("sustained ping across rekeys lost packets: %v\n%s", err, out)
	}

	// 3. Confirm the rekeys actually happened: the server completes a fresh
	// handshake for each, so its log carries several "handshake complete" lines.
	logs, err := compose(t, file, "logs", "--no-color", "veepin-wg-server")
	if err != nil {
		t.Fatalf("reading server logs: %v", err)
	}
	if n := strings.Count(logs, "handshake complete"); n < 3 {
		t.Fatalf("server logged %d handshakes, want >=3 (rekeys not happening):\n%s", n, logs)
	}
}

// TestInteropVeepinClientAnyConnectServer proves the AnyConnect client against
// ocserv — the open-source implementation of this protocol, written by the
// author of its specification, and therefore the authoritative peer to test
// against. The veepin client runs the XML credential exchange, the CONNECT that
// assigns addressing, and the CSTP data path, then pings 10.12.0.1 (ocserv's own
// tunnel-side address) across the tunnel.
func TestInteropVeepinClientAnyConnectServer(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("anyconnect", "pki")
	if err := generateAnyConnectServerCert(pkiDir); err != nil {
		t.Fatalf("generate AnyConnect cert: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInteropBench(t, "compose.anyconnect.yml", "veepin-anyconnect-client", "ocserv", "10.12.0.1")
}

// TestInteropAnyConnectClientVeepinServer is the reverse direction: the real
// openconnect client against the veepin *server*. It proves the responder — the
// server-role XML credential exchange, the CONNECT reply whose headers carry the
// assigned address, netmask, DNS and MTU, and the server's CSTP data path —
// against a client veepin shares no code with. openconnect pings 10.11.0.1, the
// veepin server's tunnel gateway.
func TestInteropAnyConnectClientVeepinServer(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("anyconnect", "pki")
	if err := generateAnyConnectServerCert(pkiDir); err != nil {
		t.Fatalf("generate AnyConnect cert: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInteropBench(t, "compose.anyconnect-server.yml", "openconnect", "veepin-anyconnect-server", "10.11.0.1")
}

// TestInteropAnyConnectSelf is the veepin<->veepin AnyConnect sanity check: both
// ends over a real TLS connection and TUNs, isolating a veepin break from an
// interop break.
func TestInteropAnyConnectSelf(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("anyconnect", "pki")
	if err := generateAnyConnectServerCert(pkiDir); err != nil {
		t.Fatalf("generate AnyConnect cert: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInteropBench(t, "compose.anyconnect-self.yml", "veepin-anyconnect-client", "veepin-anyconnect-server", "10.11.0.1")
}

// TestInteropVeepinClientL2TPServer proves the L2TP/IPsec client against the
// reference stack it exists to speak to: strongSwan terminating the IKEv1-keyed
// ESP transport SA and xl2tpd terminating L2TP inside it, driving pppd for the
// PPP session. The veepin client runs Main Mode with a PSK, Quick Mode for the
// transport SA, the L2TP control channel and MS-CHAPv2/IPCP, then pings
// 10.30.0.1 — pppd's LNS-side address — across the tunnel. Every layer here
// faces an implementation veepin shares no code with.
func TestInteropVeepinClientL2TPServer(t *testing.T) {
	runInteropBench(t, "compose.l2tp.yml", "veepin-l2tp-client", "l2tp-server", "10.30.0.1")
}

// TestInteropL2TPClientVeepinServer is the reverse direction: strongSwan as the
// IKEv1 initiator and xl2tpd as the LAC — the pair a Linux desktop dials an
// L2TP/IPsec VPN with — against the veepin *server*. It proves the responder
// side of every layer: Main Mode proposal selection and HASH_I verification,
// Quick Mode, the LNS role of the L2TP control channel, and the server-role PPP
// with MS-CHAPv2 and pool-based IPCP assignment. The client pings 10.20.0.1, the
// veepin server's tunnel gateway.
func TestInteropL2TPClientVeepinServer(t *testing.T) {
	runInteropBench(t, "compose.l2tp-server.yml", "l2tp-client", "veepin-l2tp-server", "10.20.0.1")
}

// TestInteropL2TPSelf is the veepin<->veepin L2TP/IPsec sanity check, and the
// broadest single test here: one ping crosses IKEv1 (Main + Quick mode), an ESP
// transport SA, the L2TP control and data channels, and a PPP/MS-CHAPv2/IPCP
// session before it reaches the server's tunnel gateway. Because the stack is so
// layered, this isolates a break in any one layer from an interop break.
func TestInteropL2TPSelf(t *testing.T) {
	runInteropBench(t, "compose.l2tp-self.yml", "veepin-l2tp-client", "veepin-l2tp-server", "10.20.0.1")
}

// TestInteropVeepinNebulaHostReferenceLighthouse proves the veepin nebula host
// against the real slackhq/nebula daemon: the Noise_IX handshake, the 16-octet
// header whose contents are authenticated as AEAD additional data, and the
// certificate format -- veepin parses and verifies certificates issued per run
// by the reference nebula-cert, which is what proves its protobuf encoder
// agrees with protobuf-go byte for byte. The veepin host finds the reference
// host through nebula's own lighthouse protocol rather than a static entry,
// then pings 10.42.0.1.
func TestInteropVeepinNebulaHostReferenceLighthouse(t *testing.T) {
	runInteropBench(t, "compose.nebula.yml", "veepin-nebula", "nebula-host", "10.42.0.1")
}

// TestInteropNebulaHostVeepinLighthouse is the mirror, and the direction that
// proves veepin's responder and its lighthouse: the reference daemon reports
// its location to a veepin lighthouse, queries it, and handshakes against
// veepin's responder side. The reference host pings 10.42.0.1, the veepin
// lighthouse's overlay address.
func TestInteropNebulaHostVeepinLighthouse(t *testing.T) {
	runInteropBench(t, "compose.nebula-server.yml", "nebula-host", "veepin-nebula", "10.42.0.1")
}

// TestInteropNebulaSelf is the veepin<->veepin mesh check, and the one cell that
// exercises discovery end to end: two veepin members are given no static entry
// for each other, so the ping to 10.42.0.3 can only cross if one queries the
// lighthouse, the lighthouse answers and nudges the other to punch, and the two
// then handshake directly. It isolates a veepin break from an interop break.
func TestInteropNebulaSelf(t *testing.T) {
	runInteropBench(t, "compose.nebula-self.yml", "veepin-host-b", "veepin-host-c", "10.42.0.3")
}

// MASQUE CONNECT-IP (RFC 9484) is IP-over-HTTP/3. The independent peer is
// aioquic driven from the RFCs, so these cells test veepin's from-scratch
// HTTP/3 layer -- varints, QPACK, the SETTINGS handshake, Extended CONNECT and
// capsules -- against a QUIC/HTTP-3 stack that shares none of veepin's code. A
// drift in any of that framing stops the ping crossing.

// TestInteropVeepinMasqueClientAioquicProxy runs the veepin CONNECT-IP client
// against the aioquic proxy and pings 10.31.0.1, the proxy's gateway.
func TestInteropVeepinMasqueClientAioquicProxy(t *testing.T) {
	runInteropBench(t, "compose.masque.yml", "veepin-masque-client", "aioquic-masque-server", "10.31.0.1")
}

// TestInteropAioquicClientVeepinProxy is the mirror, exercising veepin's
// responder: Extended CONNECT handling, address assignment, and a capsule
// stream the foreign client has to parse.
func TestInteropAioquicClientVeepinProxy(t *testing.T) {
	runInteropBench(t, "compose.masque-server.yml", "aioquic-masque-client", "veepin-masque-server", "10.32.0.1")
}

// TestInteropMasqueSelf is the veepin<->veepin sanity check over real QUIC. Its
// value is attribution: if it passes while the two cross-implementation cells
// fail, veepin and the RFC have diverged rather than veepin being broken.
func TestInteropMasqueSelf(t *testing.T) {
	runInteropBench(t, "compose.masque-self.yml", "veepin-masque-client", "veepin-masque-server", "10.30.0.1")
}

// MASQUE CONNECT-UDP (RFC 9298) proxies one UDP flow rather than whole IP
// packets. The data-path check is a UDP echo round-trip rather than a ping: a
// forwarder binds a local socket, a datagram is proxied to an echo target, and
// its reply must come back. The independent peer is again aioquic from the RFCs.

// TestInteropVeepinUDPClientAioquicProxy runs the veepin CONNECT-UDP forwarder
// against the aioquic proxy.
func TestInteropVeepinUDPClientAioquicProxy(t *testing.T) {
	runInteropUDPEcho(t, "compose.masque-udp.yml", "veepin-masque-udp", "127.0.0.1:5353")
}

// TestInteropAioquicUDPClientVeepinProxy is the mirror: veepin's server-side
// CONNECT-UDP handling against a foreign forwarder.
func TestInteropAioquicUDPClientVeepinProxy(t *testing.T) {
	runInteropUDPEcho(t, "compose.masque-udp-server.yml", "aioquic-masque-udp", "127.0.0.1:5353")
}

// TestInteropMasqueUDPSelf is the veepin<->veepin CONNECT-UDP sanity check.
func TestInteropMasqueUDPSelf(t *testing.T) {
	runInteropUDPEcho(t, "compose.masque-udp-self.yml", "veepin-masque-udp", "127.0.0.1:5353")
}

// Fortinet FortiOS SSL VPN. The independent peer is the real openconnect client
// (--protocol=fortinet), which fully implements the data channel -- so this cell
// moves packets and verifies veepin's server-side login, config XML, 6-octet
// framing and PPP against a stack that shares none of veepin's code. There is no
// open FortiOS *server* to run the veepin client against with a full data path,
// so that direction is covered by the self cell and unit tests.

// TestInteropOpenconnectFortinetClientVeepinServer runs the openconnect Fortinet
// client against the veepin gateway and pings 10.40.0.1, the gateway.
func TestInteropOpenconnectFortinetClientVeepinServer(t *testing.T) {
	runInteropBench(t, "compose.fortinet.yml", "opnc-fortinet-client", "veepin-fortinet-server", "10.40.0.1")
}

// TestInteropFortinetSelf is the veepin<->veepin sanity check. veepin's client
// prefers the DTLS data channel where the gateway offers one, so this also
// exercises the certificate-based DTLS handshake between the two veepin roles.
func TestInteropFortinetSelf(t *testing.T) {
	runInteropRequiringLog(t, "compose.fortinet-self.yml", "veepin-fortinet-client", "10.40.0.1",
		"data channel over DTLS")
	measureThroughput(t, "compose.fortinet-self.yml", "veepin-fortinet-server", "veepin-fortinet-client", "10.40.0.1")
}

// TestInteropOpenconnectFortinet2FA adds a second factor: the gateway answers
// the password with a ret=2 challenge, and openconnect generates the TOTP code
// from a shared secret. Both ends compute the code independently, so this pins
// veepin's RFC 6238 arithmetic and its challenge form against the real client.
func TestInteropOpenconnectFortinet2FA(t *testing.T) {
	runInterop(t, "compose.fortinet-2fa.yml", "opnc-fortinet-client", "10.40.0.1")
}

// TestInteropOpenconnectFortinetDTLS is the same cell with the UDP data channel
// left on: openconnect attaches its own DTLS session to the TLS tunnel and
// prefers it. The ping alone would pass on a silent fallback to TLS, so the run
// additionally requires openconnect to report an established DTLS connection.
func TestInteropOpenconnectFortinetDTLS(t *testing.T) {
	runInteropRequiringLog(t, "compose.fortinet-dtls.yml", "opnc-fortinet-client", "10.40.0.1",
		"Established DTLS connection")
}

// TOY is the example protocol (internal/toy) and provides no security; these
// cells prove the *specification*, not the cryptography. The peer they talk to
// is an independent Python implementation written from internal/toy/SPEC.md
// that shares no code, no language and no libraries with veepin, so a drift in
// framing, key derivation, keystream, tag or handshake stops the ping crossing.

// TestInteropVeepinToyClientReferencePeer runs the veepin TOY client against
// that independent peer and pings 10.9.0.1, the peer's gateway.
func TestInteropVeepinToyClientReferencePeer(t *testing.T) {
	runInteropBench(t, "compose.toy.yml", "veepin-toy-client", "toy-server", "10.9.0.1")
}

// TestInteropToyClientVeepinServer is the mirror, exercising veepin's responder:
// session allocation, proof verification, pool assignment, and a WELCOME the
// independent client has to be able to parse.
func TestInteropToyClientVeepinServer(t *testing.T) {
	runInteropBench(t, "compose.toy-server.yml", "toy-client", "veepin-toy-server", "10.9.0.1")
}

// TestInteropToySelf is the veepin<->veepin sanity check. Its value is
// attribution: if it passes while the two cross-implementation cells fail, the
// spec and the implementation have diverged rather than veepin being broken.
func TestInteropToySelf(t *testing.T) {
	runInteropBench(t, "compose.toy-self.yml", "veepin-toy-client", "veepin-toy-server", "10.9.0.1")
}

// waitPing retries a short ping from pingSvc to target until one reports no loss
// or pingDeadline elapses, reporting whether the tunnel came up.
func waitPing(t *testing.T, composeFile, pingSvc, target string) bool {
	t.Helper()
	deadline := time.Now().Add(pingDeadline)
	for time.Now().Before(deadline) {
		out, err := compose(t, composeFile, "exec", "-T", pingSvc,
			"ping", "-c2", "-W2", target)
		if err == nil && strings.Contains(out, "0% packet loss") {
			return true
		}
		time.Sleep(3 * time.Second)
	}
	return false
}

// runInterop brings up the given compose file, then retries a ping from pingSvc
// to target across the tunnel until it succeeds or pingDeadline elapses. A
// successful ping proves the full path: handshake, config-mode addressing, and
// bidirectional ESP. The stack is always torn down; logs are dumped on failure.
func runInterop(t *testing.T, composeFile, pingSvc, target string) {
	t.Helper()
	requireDocker(t)

	if out, err := compose(t, composeFile, "up", "--build", "-d"); err != nil {
		t.Fatalf("compose up: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			if logs, err := compose(t, composeFile, "logs", "--no-color"); err == nil {
				t.Logf("--- compose logs (%s) ---\n%s", composeFile, logs)
			}
		}
		_, _ = compose(t, composeFile, "down", "-v", "--timeout", "5")
	})

	deadline := time.Now().Add(pingDeadline)
	var last string
	for time.Now().Before(deadline) {
		out, err := compose(t, composeFile, "exec", "-T", pingSvc,
			"ping", "-c2", "-W2", target)
		if err == nil && strings.Contains(out, "0% packet loss") {
			t.Logf("tunnel up: %s pinged %s across the tunnel", pingSvc, target)
			return
		}
		last = out
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("cross-tunnel ping %s -> %s never succeeded within %s:\n%s",
		pingSvc, target, pingDeadline, last)
}

// benchWarmup lets an iperf3 server settle before the client connects.
const benchWarmup = 1 * time.Second

// runInteropBench is runInterop plus an iperf3 throughput measurement across the
// tunnel it just proved. serverSvc is the container reachable at target (it runs
// `iperf3 -s`); pingSvc is both the ping source and the iperf3 client. The result
// feeds the interop-benchmark table in the README.
//
// The measurement is best-effort: it never fails the test. The interop pass/fail
// is the ping (runInterop); a cell whose iperf3 cannot run — a peer without a
// bindable tunnel address, a firewall that permits only ICMP — simply reports no
// number and shows an em dash in the table, rather than turning a working tunnel
// red.
func runInteropBench(t *testing.T, composeFile, pingSvc, serverSvc, target string) {
	t.Helper()
	runInterop(t, composeFile, pingSvc, target)
	measureThroughput(t, composeFile, serverSvc, pingSvc, target)
}

// measureThroughput runs one iperf3 flow across an already-up tunnel: `iperf3 -s`
// (one-shot) in serverSvc, `iperf3 -c target` in clientSvc, and logs the received
// rate as a livingreadme marker that `go test -json` carries out to the
// README-generation step. Any failure is logged and swallowed (see
// runInteropBench).
func measureThroughput(t *testing.T, composeFile, serverSvc, clientSvc, target string) {
	t.Helper()

	// -s server, one-shot (-1: exit after a single client), detached. No -B, so
	// it listens on all interfaces including the tunnel one; the client reaches
	// it by the tunnel-internal target address.
	if out, err := compose(t, composeFile, "exec", "-d", serverSvc, "iperf3", "-s", "-1"); err != nil {
		t.Logf("throughput: iperf3 server did not start in %s (skipped): %v\n%s", serverSvc, err, out)
		return
	}
	time.Sleep(benchWarmup)

	// -J JSON, -t short measured window, -O omit the first second (TCP slow
	// start), bounded connect. -c takes the tunnel-internal server address.
	out, err := compose(t, composeFile, "exec", "-T", clientSvc,
		"iperf3", "-c", target, "-J", "-t", "4", "-O", "1", "--connect-timeout", "5000")
	if err != nil {
		t.Logf("throughput: iperf3 client %s -> %s failed (skipped): %v\n%s", clientSvc, target, err, out)
		return
	}
	bps, err := parseIperfBits(out)
	if err != nil {
		t.Logf("throughput: could not read iperf3 result (skipped): %v", err)
		return
	}
	// The marker the interop-benchmark region is generated from, keyed by the
	// test name so the manifest can place it in the matrix.
	t.Log(livingreadme.IperfLine(t.Name(), bps))
	t.Logf("throughput %s -> %s: %.0f bit/s", clientSvc, target, bps)
}

// parseIperfBits pulls the received bits/second out of `iperf3 -J` output. The
// stream is CombinedOutput, so it isolates the JSON object before decoding in
// case a warning is interleaved on stderr.
func parseIperfBits(out string) (float64, error) {
	start := strings.IndexByte(out, '{')
	end := strings.LastIndexByte(out, '}')
	if start < 0 || end < start {
		return 0, fmt.Errorf("no JSON object in iperf3 output")
	}
	var r struct {
		End struct {
			SumReceived struct {
				BitsPerSecond float64 `json:"bits_per_second"`
			} `json:"sum_received"`
		} `json:"end"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out[start:end+1]), &r); err != nil {
		return 0, err
	}
	if r.Error != "" {
		return 0, fmt.Errorf("iperf3: %s", r.Error)
	}
	if r.End.SumReceived.BitsPerSecond <= 0 {
		return 0, fmt.Errorf("iperf3 reported no throughput")
	}
	return r.End.SumReceived.BitsPerSecond, nil
}

// runInteropRequiringLog is runInterop plus an assertion on the compose logs. It
// exists for cells where the ping proves a tunnel but not *which* carrier moved
// it: a fallback path that still works would otherwise pass as a false green.
//
// The log is polled rather than read once, because the carrier it is looking for
// comes up asynchronously to the ping. A client brings its UDP channel up
// alongside the TLS tunnel and may retry after a first attempt fails, so the
// tunnel can be pingable seconds before the line appears -- reading once turns
// "not yet" into "never".
func runInteropRequiringLog(t *testing.T, composeFile, pingSvc, target, want string) {
	t.Helper()
	runInterop(t, composeFile, pingSvc, target)

	deadline := time.Now().Add(logDeadline)
	var logs string
	for time.Now().Before(deadline) {
		out, err := compose(t, composeFile, "logs", "--no-color", pingSvc)
		if err == nil {
			logs = out
			if strings.Contains(logs, want) {
				t.Logf("%s reported %q", pingSvc, want)
				return
			}
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("the tunnel came up but %q never appeared in %s's logs within %s:\n%s",
		want, pingSvc, logDeadline, logs)
}

// runInteropUDPEcho brings up a CONNECT-UDP compose file, then sends a UDP
// datagram from probeSvc to its local forwarder address and checks the echo
// target's reply returns through the tunnel. It is the CONNECT-UDP counterpart
// of runInterop's ping: a UDP flow rather than an IP tunnel, so the proof is a
// datagram round-trip rather than ICMP.
func runInteropUDPEcho(t *testing.T, composeFile, probeSvc, listen string) {
	t.Helper()
	requireDocker(t)

	if out, err := compose(t, composeFile, "up", "--build", "-d"); err != nil {
		t.Fatalf("compose up: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			if logs, err := compose(t, composeFile, "logs", "--no-color"); err == nil {
				t.Logf("--- compose logs (%s) ---\n%s", composeFile, logs)
			}
		}
		_, _ = compose(t, composeFile, "down", "-v", "--timeout", "5")
	})

	// A distinct token per attempt is unnecessary; the echo returns whatever it
	// was sent, so a fixed token proves the round trip.
	const token = "veepin-connect-udp-interop"
	probe := fmt.Sprintf("echo -n %s | socat -t3 - UDP:%s", token, listen)

	deadline := time.Now().Add(pingDeadline)
	var last string
	for time.Now().Before(deadline) {
		out, err := compose(t, composeFile, "exec", "-T", probeSvc, "sh", "-c", probe)
		if err == nil && strings.Contains(out, token) {
			t.Logf("CONNECT-UDP echo round-tripped through %s", composeFile)
			return
		}
		last = out
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("CONNECT-UDP echo never returned within %s:\n%s", pingDeadline, last)
}

// compose runs `docker compose -f <file> <args...>` in the test's directory
// (which holds the compose files and their relative build contexts).
func compose(t *testing.T, file string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	full := append([]string{"compose", "-f", file}, args...)
	out, err := exec.CommandContext(ctx, "docker", full...).CombinedOutput()
	return string(out), err
}

// requireDocker skips the test unless a working Docker daemon is reachable.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not available")
	}
}
