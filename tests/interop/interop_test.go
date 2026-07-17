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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pingDeadline bounds how long we retry the cross-tunnel ping. It must cover
// image build, container start, the client's connect-retry loop, and (for
// strongSwan) charon startup.
const pingDeadline = 100 * time.Second

// TestInteropSelf is the infra sanity check: veepin client <-> veepin server.
// It isolates the container/TUN/NAT-T/ping harness from strongSwan.
func TestInteropSelf(t *testing.T) {
	runInterop(t, "compose.selftest.yml", "client", "10.10.10.1")
}

// TestInteropVeepinClientStrongswanServer is Direction A: the veepin client
// (ikev2) tunnels to a strongSwan responder and pings a strongSwan-side address.
func TestInteropVeepinClientStrongswanServer(t *testing.T) {
	runInterop(t, "compose.client-ss.yml", "veepin-client", "10.20.30.254")
}

// TestInteropStrongswanClientVeepinServer is Direction B: a strongSwan
// initiator tunnels to the veepin server (`veepin serve ikev2`) and pings its TUN gateway.
func TestInteropStrongswanClientVeepinServer(t *testing.T) {
	runInterop(t, "compose.server-ss.yml", "strongswan-client", "10.10.10.1")
}

// TestInteropVeepinClientWireguardServer proves the WireGuard initiator against
// the reference wireguard-go responder: the veepin client performs the
// Noise_IKpsk2 handshake and transport data path, then pings 10.10.10.1 (the
// responder's tunnel address) across it. A success exercises the handshake,
// the counter-nonce transport crypto, and cryptokey routing end to end against
// an implementation veepin shares no code with.
func TestInteropVeepinClientWireguardServer(t *testing.T) {
	runInterop(t, "compose.wireguard.yml", "veepin-wg-client", "10.10.10.1")
}

// TestInteropWireguardClientVeepinServer is the mirror: a real wireguard-go
// client performs the handshake against the veepin *server* (`veepin serve
// wireguard`) and pings its tunnel gateway. It proves the responder — mac1
// verification, static-key lookup, the response message, and multi-peer
// cryptokey routing — against a client veepin shares no code with.
func TestInteropWireguardClientVeepinServer(t *testing.T) {
	runInterop(t, "compose.wireguard-server.yml", "wg-client", "10.10.10.1")
}

// TestInteropWireguardSelf is the veepin<->veepin WireGuard sanity check: the
// veepin client and server over real sockets and TUNs, isolating a veepin break
// from an interop break.
func TestInteropWireguardSelf(t *testing.T) {
	runInterop(t, "compose.wireguard-self.yml", "veepin-wg-client", "10.10.10.1")
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
	runInterop(t, "compose.sstp-self.yml", "veepin-sstp-client", "10.9.0.1")
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
	runInterop(t, "compose.sstp-server.yml", "sstp-client", "10.9.0.1")
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
	runInterop(t, "compose.ssh-self.yml", "veepin-ssh-client", "10.200.0.1")
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
	runInterop(t, "compose.ssh-server.yml", "ssh-client", "10.200.0.1")
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
	runInterop(t, "compose.ssh-sshd.yml", "veepin-ssh-client", "10.200.0.1")
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
	runInterop(t, composeFile, "veepin-ovpn-client", "10.8.0.1")
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
	runInterop(t, "compose.openvpn-server.yml", "openvpn-client", "10.8.0.1")
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
	runInterop(t, "compose.openvpn-self.yml", "veepin-ovpn-client", "10.8.0.1")
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
