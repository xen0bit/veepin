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
	"strconv"
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

// TestInteropStrongswanClientVeepinServerEAP is Direction B with the initiator
// authenticating by EAP-MSCHAPv2 instead of the PSK.
//
// EAP-MSCHAPv2 is listed in the README beside PSK and X.509 and has had
// -eap-users on the server for as long, but no interop cell ever exercised it:
// an entire authentication path shipped without once being run against a real
// peer. The asymmetry RFC 7296 §2.16 describes is what makes it worth its own
// cell — the initiator omits its AUTH to request EAP, the responder still
// authenticates with the PSK, and after EAP succeeds both sides compute a final
// AUTH keyed by the EAP MSK rather than the PSK. A break anywhere in the
// MSCHAPv2 arithmetic (NT hash, challenge response, MSK derivation) stops the
// ping.
func TestInteropStrongswanClientVeepinServerEAP(t *testing.T) {
	runInterop(t, "compose.server-ss-eap.yml", "strongswan-client", "10.10.10.1")
}

// TestInteropStrongswanClientVeepinServerShaped is Direction B with downstream
// flow shaping on: the veepin server pads outbound ESP with RFC 4303 2.7
// traffic-flow-confidentiality padding, and a real strongSwan initiator has to
// cope with it.
//
// This is the cell that gates the -shape default. The filler is delimited only
// by the inner IP header's own length, so a successful ping proves two things a
// unit test cannot: that strongSwan accepts the padded packets at all, and that
// it trims them by the header rather than by the ESP payload length -- a
// receiver doing the latter would hand its stack a packet with garbage attached
// and could not answer.
func TestInteropStrongswanClientVeepinServerShaped(t *testing.T) {
	runInterop(t, "compose.server-ss-shaped.yml", "strongswan-client", "10.10.10.1")
}

// TestInteropVeepinClientStrongswanServerV6Underlay is Direction A with the OUTER
// ESP/IKE transport over IPv6: the veepin client dials strongSwan at an IPv6
// literal and the handshake and ESP ride UDP/IPv6. The inner ping stays IPv4, so
// a successful cross-tunnel ping isolates the underlay. Proves veepin's client
// socket path and outer host-route work over an IPv6 underlay against strongSwan.
func TestInteropVeepinClientStrongswanServerV6Underlay(t *testing.T) {
	runInterop(t, "compose.client-ss-v6underlay.yml", "veepin-client", "10.20.30.254")
}

// TestInteropStrongswanClientVeepinServerV6Underlay is Direction B over an IPv6
// underlay: a strongSwan initiator dials the veepin server (`veepin serve ikev2
// -listen ::`) at its IPv6 address. Exercises the server's dual-stack bind and
// the pktconn IPv6 source-pinning path; the inner ping to the TUN gateway is IPv4.
func TestInteropStrongswanClientVeepinServerV6Underlay(t *testing.T) {
	runInterop(t, "compose.server-ss-v6underlay.yml", "strongswan-client", "10.10.10.1")
}

// TestInteropVeepinClientStrongswanServerChaCha20 is Direction A with the
// strongSwan responder forcing ChaCha20-Poly1305 (RFC 7634): the veepin client
// must negotiate ChaCha20 for the IKE and Child SAs. A successful cross-tunnel
// ping proves veepin's RFC 7634 framing interoperates byte-for-byte with
// strongSwan's chacha20poly1305.
func TestInteropVeepinClientStrongswanServerChaCha20(t *testing.T) {
	runInterop(t, "compose.client-ss-chacha.yml", "veepin-client", "10.20.30.254")
}

// TestInteropVeepinClientAmneziaWGServer is the client direction against the
// real amneziawg-go: veepin's initiator must produce datagrams an implementation
// it shares no code with recognises as AmneziaWG, and complete a Noise IK
// handshake through them.
//
// This cell is what proved the header substitution had to move inside the noise
// layer. mac1 authenticates the message *including* its type word, so rewriting
// the type after the MAC is stamped invalidates it — invisible between two
// veepin endpoints, which both compute over the stock value and agree, and
// rejected outright by amneziawg-go as "invalid mac1".
func TestInteropVeepinClientAmneziaWGServer(t *testing.T) {
	runInteropBench(t, "compose.amneziawg-client.yml", "veepin-awg-client", "awg-server", "10.61.0.1")
}

// TestInteropAmneziaWGClientVeepinServer is the other direction: the veepin
// responder must recognise obfuscated datagrams from amneziawg-go and shape its
// own replies so amneziawg-go accepts them — including the response's mac1,
// which that implementation does check.
//
// It measures, like the other two AmneziaWG cells. It did not, and the published
// throughput table rendered the hole as "—" — which that table's own legend
// defines as "iperf3 does not apply to this cell". It applies here: both ends
// hold a routable tunnel address and both images carry iperf3. An unmeasured
// cell that reads as a deliberate omission is the same class of quiet wrong as
// a skipped test that reads as a pass.
func TestInteropAmneziaWGClientVeepinServer(t *testing.T) {
	runInteropBench(t, "compose.amneziawg-server.yml", "awg-client", "veepin-awg-server", "10.61.0.1")
}

// TestInteropAmneziaWGSelf runs the veepin AmneziaWG client against the veepin
// AmneziaWG server with every obfuscation knob engaged: all four message types
// replaced, all four paddings non-zero, and junk datagrams ahead of the
// handshake. A successful cross-tunnel ping proves the transform is reversible
// over real sockets — the unit tests only round-trip it in memory.
func TestInteropAmneziaWGSelf(t *testing.T) {
	runInteropBench(t, "compose.amneziawg-self.yml", "veepin-awg-client", "veepin-awg-server", "10.60.0.1")
}

// TestInteropVeepinClientStrongswanServerPQ is Direction A with a post-quantum
// hybrid key exchange: the veepin client offers ML-KEM-768 as an RFC 9370
// additional key exchange, carried in an RFC 9242 IKE_INTERMEDIATE exchange,
// against a strongSwan responder configured with ke1_mlkem768.
//
// The log assertion is the point. RFC 9370 negotiation degrades silently by
// design — a responder that declines simply omits the transform and the
// handshake proceeds classically — so a bare ping proves only that IKEv2 works,
// which it did even when the exchange was completely broken. The assertion
// reads strongSwan's log rather than our own: the claim worth making is that a
// different implementation saw and accepted the exchange, not that we think we
// sent it.
func TestInteropVeepinClientStrongswanServerPQ(t *testing.T) {
	runInteropRequiringLogFrom(t, "compose.client-ss-pq.yml", "veepin-client", "strongswan-server", "10.20.30.254",
		"parsed IKE_INTERMEDIATE request")
}

// TestInteropStrongswanClientVeepinServerPQ is Direction B with the same hybrid
// exchange: strongSwan initiates with ke1_mlkem768 and the veepin server must
// select the ADDKE transform, answer the IKE_INTERMEDIATE, and fold the KEM
// secret into SKEYSEED. Asserted on the server's log for the reason above.
func TestInteropStrongswanClientVeepinServerPQ(t *testing.T) {
	runInteropRequiringLogFrom(t, "compose.server-ss-pq.yml", "strongswan-client", "veepin-server", "10.10.10.1",
		"negotiated additional key exchange ML-KEM-768")
}

// TestInteropVeepinClientStrongswanServerCert is Direction A with certificate
// authentication: the veepin client authenticates to a strongSwan responder with
// an ECDSA certificate (no PSK), each verifying the other's chain and RFC 7427
// Digital Signature (AUTH method 14). A successful cross-tunnel ping proves our
// CERT/CERTREQ payloads and method-14 signing interoperate with strongSwan.
func TestInteropVeepinClientStrongswanServerCert(t *testing.T) {
	runInterop(t, "compose.client-ss-cert.yml", "veepin-client", "10.20.30.254")
}

// TestInteropVeepinClientStrongswanServerCertRSA is the cell above with the
// fixture's blind spot removed. That one mints ECDSA P-256 -- the smallest
// certificate there is -- so its IKE_AUTH fits in one datagram, which is why it
// passed for as long as veepin never fragmented its own output. Here the chain
// is RSA-2048 leaf + intermediate, putting IKE_AUTH at 2.5-3.5 KB, and the
// strongSwan side drops every non-first IP fragment.
//
// The required log line is the whole point. A ping passes just as happily if
// the message somehow got through unfragmented, and "the handshake worked" is
// exactly the evidence that hid the original defect. Requiring the client to
// SAY it fragmented is what makes this a test of the code rather than of the
// network.
func TestInteropVeepinClientStrongswanServerCertRSA(t *testing.T) {
	runInteropRequiringLog(t, "compose.client-ss-cert-rsa.yml", "veepin-client", "10.20.30.254",
		"fragmenting request into")
}

// TestInteropStrongswanClientVeepinServerCertRSA is the responder half, and it
// covers two gaps at once: no cell tested certificate authentication in
// Direction B at all, and the veepin server's IKE_AUTH builder (ike_auth.go)
// had the same missing outbound size check the client's did. A veepin server
// therefore could not answer a strongSwan client whose CA issues RSA.
//
// The strongSwan initiator drops non-first IP fragments, so its ping succeeds
// only if the veepin RESPONDER fragmented. The log line is required from the
// server for the same reason as above.
func TestInteropStrongswanClientVeepinServerCertRSA(t *testing.T) {
	runInteropRequiringLogFrom(t, "compose.server-ss-cert-rsa.yml",
		"strongswan-client", "veepin-server", "10.10.10.1",
		"fragmenting")
}

// TestInteropVeepinClientStrongswanServerIPv6 is Direction A dual-stack: the
// strongSwan responder assigns both an IPv4 and an IPv6 virtual address and
// offers v4+v6 traffic selectors, and the veepin client pings a strongSwan-side
// address in each family across the one Child SA. It proves the INTERNAL_IP6
// config-mode assignment, the v6 traffic selector, and IPv6-in-ESP (next-header
// 41) interoperate with strongSwan.
func TestInteropVeepinClientStrongswanServerIPv6(t *testing.T) {
	runInterop(t, "compose.client-ss-v6.yml", "veepin-client", "10.20.30.254", "fd00:20:30::254")
}

// TestInteropStrongswanClientVeepinServerIPv6 is Direction B dual-stack: a
// strongSwan initiator requests a virtual address in both families and pings the
// veepin server's own tunnel gateway in each.
//
// The v6 ping is the point, and it is a claim about the HOST rather than about
// the protocol. compose.client-ss-v6 already proves veepin speaks INTERNAL_IP6
// -- but in that direction it is strongSwan that configures its own host, so
// veepin's host-side v6 was never on the path. ikev2's Server.Gateway6/Network6
// were documented as being "for routing and NAT rules" and had no caller
// anywhere in the tree, while config mode handed every client a v6 address from
// a pool that defaults. The gateway address therefore never reached the TUN and
// nothing answered fd00:10:10::1, while the v4 ping in
// TestInteropStrongswanClientVeepinServer passed throughout.
//
// That is the shape of gap this matrix exists to close: a capability proven in
// one direction and never in the other.
func TestInteropStrongswanClientVeepinServerIPv6(t *testing.T) {
	runInterop(t, "compose.server-ss-v6.yml", "strongswan-client", "10.10.10.1", "fd00:10:10::1")
}

// TestInteropStrongswanClientVeepinServerFragmented is Direction B with IKE
// fragmentation forced (RFC 7383): the strongSwan initiator splits its IKE_AUTH
// into SKF fragments (fragmentation=force + a small fragment_size), which the
// veepin server must reassemble before it can authenticate the peer. A
// successful in-tunnel ping proves the reassembled IKE_AUTH established the SA.
func TestInteropStrongswanClientVeepinServerFragmented(t *testing.T) {
	runInterop(t, "compose.server-ss-frag.yml", "strongswan-client", "10.10.10.1")
}

// TestInteropIKEv2ChildRekey proves proactive Child SA rekey (RFC 7296 2.8): the
// veepin client rekeys its ESP SA every 2s (REKEY=2), and traffic survives the
// SA swap. It waits until the server has accepted a client-driven
// CREATE_CHILD_SA (the observable proof the client rekeyed — the client's own
// session log is discarded on the CLI path), then pings across the now-rekeyed
// tunnel so the ping exercises a data path swapped onto fresh keys.
func TestInteropIKEv2ChildRekey(t *testing.T) {
	requireDocker(t)
	const composeFile = "compose.selftest-rekey.yml"

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

	// Wait until the server has set up a client-driven CREATE_CHILD_SA rekey.
	deadline := time.Now().Add(logDeadline)
	rekeyed := false
	var last string
	for time.Now().Before(deadline) {
		out, err := compose(t, composeFile, "logs", "--no-color", "server")
		if err == nil {
			last = out
			if strings.Contains(out, "CREATE_CHILD_SA up") {
				rekeyed = true
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if !rekeyed {
		t.Fatalf("server never accepted a client-driven Child SA rekey within %s:\n%s", logDeadline, last)
	}
	t.Log("client rekeyed the Child SA; pinging across the swapped data path")

	// Now ping across the tunnel: success proves the post-rekey SA carries traffic.
	pingDL := time.Now().Add(pingDeadline)
	for time.Now().Before(pingDL) {
		out, err := compose(t, composeFile, "exec", "-T", "client", "ping", "-c2", "-W2", "10.10.10.1")
		if err == nil && strings.Contains(out, "0% packet loss") {
			t.Log("ping across the rekeyed tunnel succeeded")
			return
		}
		last = out
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("ping across the rekeyed tunnel never succeeded within %s:\n%s", pingDeadline, last)
}

// TestInteropIKEv2IKERekey proves proactive IKE SA rekey (RFC 7296 2.18): the
// veepin client rotates the IKE SA itself every 2s (IKE_REKEY=2) — a fresh DH
// exchange for new control keys — while the inherited Child SA keeps carrying
// traffic. It waits until the server has accepted a client-driven IKE SA rekey
// (the server logs "IKE SA rekeyed"), then pings across the tunnel: success
// proves the Child SA survived the control-channel rotation untouched.
func TestInteropIKEv2IKERekey(t *testing.T) {
	requireDocker(t)
	const composeFile = "compose.selftest-ike-rekey.yml"

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

	// Wait until the server has accepted a client-driven IKE SA rekey.
	deadline := time.Now().Add(logDeadline)
	rekeyed := false
	var last string
	for time.Now().Before(deadline) {
		out, err := compose(t, composeFile, "logs", "--no-color", "server")
		if err == nil {
			last = out
			if strings.Contains(out, "IKE SA rekeyed") {
				rekeyed = true
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if !rekeyed {
		t.Fatalf("server never accepted a client-driven IKE SA rekey within %s:\n%s", logDeadline, last)
	}
	t.Log("client rekeyed the IKE SA; pinging across the inherited Child SA")

	// Ping across the tunnel: success proves the Child SA survived the IKE SA
	// rotation (its ESP keys are inherited, not re-derived).
	pingDL := time.Now().Add(pingDeadline)
	for time.Now().Before(pingDL) {
		out, err := compose(t, composeFile, "exec", "-T", "client", "ping", "-c2", "-W2", "10.10.10.1")
		if err == nil && strings.Contains(out, "0% packet loss") {
			t.Log("ping across the IKE-rekeyed tunnel succeeded")
			return
		}
		last = out
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("ping after IKE SA rekey never succeeded within %s:\n%s", pingDeadline, last)
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
// TestInteropWireguardClientVeepinServerV6 carries IPv6 inside the tunnel, over
// an IPv4 underlay, against the reference wireguard-go.
//
// It exists because `AllowedIPs` accepted a v6 prefix and the inbound half of
// cryptokey routing then dropped every v6 packet -- an option accepted and
// ignored, with no log line, because a drop there looks exactly like a packet
// that never arrived.
//
// **The server direction is the only one that tests it.** verifySource is set
// on the server (wireguard/server.go) and not on the client
// (wireguard/wireguard.go), so sourceAllowed runs in one role only. A
// client-direction version of this cell was written first, and it passed with
// the old v4-only check deliberately restored -- a green cell asserting nothing,
// which is the exact failure mode the matrix exists to avoid and which only
// re-breaking the code on purpose revealed.
//
// It now proves a second thing. The entrypoint used to add the server's own v6
// address to tun0 by hand, with a comment saying only the v4 half of the
// config's Address line was installed -- so the cell was testing cryptokey
// routing over a host somebody else had configured. veepin implements
// client.DualStackServer now, `-setup-nat` installs the address and v6
// forwarding, and the script touches no `ip -6` at all. A regression there
// stops this ping.
func TestInteropWireguardClientVeepinServerV6(t *testing.T) {
	runInterop(t, "compose.wireguard-v6.yml", "wg-client", "fd00:10:10::1")
}

// TestInteropVeepinClientWireguardServerV6 is the client-direction mirror: a
// dual-stack tunnel where wireguard-go owns the host configuration and veepin
// has to report the v6 half of its own address.
//
// It tests a different thing from the server cell above, which is why both
// exist. That one covers inbound cryptokey routing and the server's own address
// on the host; this one covers client.Result. The client parsed the whole
// Address line, validated every entry, and kept only the first -- so a
// dual-stack invocation came up IPv4-only with nothing logged, and
// dataplane.AddrPool6's single consumer in the tree stayed single.
func TestInteropVeepinClientWireguardServerV6(t *testing.T) {
	runInterop(t, "compose.wireguard-client-v6.yml", "veepin-wg-client", "fd00:10:10::1")
}

func TestInteropWireguardClientVeepinServer(t *testing.T) {
	runInteropBench(t, "compose.wireguard-server.yml", "wg-client", "veepin-wg-server", "10.10.10.1")
}

// TestInteropWireguardClientVeepinServerShaped is the WireGuard half of the
// shaping proof: the veepin server pads transport messages far past the
// protocol's mandatory 16-octet alignment, and a real wireguard-go client must
// still recover the inner packet -- which it can only do by trimming to the
// inner IP header's declared length.
func TestInteropWireguardClientVeepinServerShaped(t *testing.T) {
	runInterop(t, "compose.wireguard-server-shaped.yml", "wg-client", "10.10.10.1")
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

// TestInteropSSTPClientVeepinServerShaped is the same cell with downstream flow
// shaping on: the veepin server pads the PPP Information field past the inner IP
// packet, as RFC 1661 5.1 allows, and a real pppd has to cope with it.
//
// The filler is delimited only by the inner IP header's own length, so a
// successful ping proves two things a unit test cannot: that pppd accepts the
// over-long frames at all, and that the IP layer behind it trims by the header
// rather than trusting the frame size -- a receiver doing the latter would hand
// its stack a packet with garbage attached and could not answer.
func TestInteropSSTPClientVeepinServerShaped(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("sstp", "pki")
	if err := generateSSTPServerCert(pkiDir); err != nil {
		t.Fatalf("generate SSTP cert: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInterop(t, "compose.sstp-server-shaped.yml", "sstp-client", "10.9.0.1")
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

// TestInteropSSHClientVeepinServerShaped is the cell that makes SSH's shaping
// mean something, and the one that decides a framing question a unit test
// cannot.
//
// An SSH channel is a byte stream with no packet delimiter, so veepin's reader
// recovers boundaries from the IP length -- which means trailing filler would
// be read as the next packet's address-family header. ReadPacket now skips
// whole zero words, which a header (00 00 00 02 / 00 00 00 0a) can never be.
// A real `ssh -w` needs none of that: it writes each channel message to its tun
// in one call and the kernel delimits the packet by Total Length.
//
// That last sentence is an argument until this cell runs. The log line is
// required as well as the ping, because a ping passes just as happily on a
// shaper that did nothing.
func TestInteropSSHClientVeepinServerShaped(t *testing.T) {
	requireDocker(t)
	keyDir := filepath.Join("ssh", "keys")
	if err := generateSSHKeys(keyDir); err != nil {
		t.Fatalf("generate SSH keys: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(keyDir) })
	runInteropRequiringLogFrom(t, "compose.ssh-server-shaped.yml",
		"ssh-client", "veepin-ssh-server", "10.200.0.1",
		"shaping outbound packets to")
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

// TestInteropOpenVPNClientVeepinServerV6 is the same cell with a dual-stack
// tunnel: the veepin server pushes ifconfig-ipv6 beside ifconfig, and a stock
// OpenVPN client configures its v6 address entirely from what arrives. The
// client config asks for nothing v6-specific, so a malformed option or a prefix
// the client rejects leaves it IPv4-only.
//
// **The ping goes server -> client, and the direction is the whole test.** The
// obvious cell -- client pings the server's fd00:8::1 -- passes with the two
// ifconfig-ipv6 arguments swapped, because a client that configured the
// server's address as its own answers that ping from its own interface without
// a packet crossing anything. It was written that way first and the swap was
// deliberately introduced to check; it passed in 13 seconds.
//
// Pinging the *client's* derived address from the server cannot be satisfied
// that way. It requires the client to hold fd00:8::2 and not fd00:8::1, the
// server to hold fd00:8::1 (installed by -setup-nat through
// client.DualStackServer, with nothing in the entrypoint touching `ip -6`), and
// the v6 half of the data path to carry the request and the reply. One ping,
// and every part of the feature is in it.
func TestInteropOpenVPNClientVeepinServerV6(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("openvpn", "pki")
	if err := generateOpenVPNPKI(pkiDir); err != nil {
		t.Fatalf("generate PKI: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInterop(t, "compose.openvpn-server-v6.yml", "veepin-ovpn-server", "fd00:8::2")
}

// TestInteropOpenVPNClientVeepinServerShaped is the same cell with downstream
// flow shaping on: the veepin server pads the data-channel payload past the
// inner IP packet.
//
// The data channel length-delimits its payload and says nothing about padding,
// so the filler is inert only because the receiver delimits the real packet by
// the inner IP header's Total Length. A ping reply is what turns that into a
// tested fact -- a mis-trimmed packet could not produce a valid reply. OpenVPN
// carries the most published fingerprinting work of any protocol here (Xue et
// al., USENIX Security 2022), which is why the cell earns its runtime.
func TestInteropOpenVPNClientVeepinServerShaped(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("openvpn", "pki")
	if err := generateOpenVPNPKI(pkiDir); err != nil {
		t.Fatalf("generate PKI: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInterop(t, "compose.openvpn-server-shaped.yml", "openvpn-client", "10.8.0.1")
}

// TestInteropOpenVPNClientVeepinServerTLSCrypt is the mirror of the tls-crypt
// client cell: a real OpenVPN client with --tls-crypt against the veepin
// *server*.
//
// It proves two things the plain server cell cannot. The wrapping is not
// negotiated, so before the server could unwrap a control packet this
// configuration could not connect at all. And a successful tunnel means the
// server's opener authentication accepted a genuinely wrapped hard reset --
// the same check that silently drops one from a peer without the static key,
// which is what denies an active prober the hard-reset-and-certificate reply
// that the OpenVPN fingerprinting work (USENIX Security 2022) relies on.
func TestInteropOpenVPNClientVeepinServerTLSCrypt(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("openvpn", "pki")
	if err := generateOpenVPNPKI(pkiDir); err != nil {
		t.Fatalf("generate PKI: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInterop(t, "compose.openvpn-server-tls-crypt.yml", "openvpn-client", "10.8.0.1")
}

// TestInteropOpenVPNClientVeepinServerTLSAuth is the mirror of the tls-auth
// client cell, and the direction that exercises the harder half: here the veepin
// server *verifies* an HMAC-SHA256 on every control packet rather than
// generating one.
//
// tls-auth splits the static key into per-direction halves, so a server
// verifying with its own half instead of the client's rejects every packet. The
// tls-crypt cell cannot catch that — tls-crypt has no key direction — and the
// client-side tls-auth cell only proves generation. The README claims tls-auth
// in both roles; until this cell, only the client role was proven against a real
// peer.
func TestInteropOpenVPNClientVeepinServerTLSAuth(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("openvpn", "pki")
	if err := generateOpenVPNPKI(pkiDir); err != nil {
		t.Fatalf("generate PKI: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInterop(t, "compose.openvpn-server-tls-auth.yml", "openvpn-client", "10.8.0.1")
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

// TestInteropAnyConnectClientVeepinServerDTLS is the same cell with the UDP data
// channel left on: openconnect brings the CSTP tunnel up, then attaches a
// DTLS 1.2 session keyed by the RFC 5705 exporter and prefers it.
//
// It is a separate cell because openconnect falls back to TLS silently. This
// used to be one cell with DTLS merely enabled, so a ping that crossed on TLS
// proved the DTLS claim exactly as well as one that crossed on DTLS — which is
// to say, not at all. The run now requires openconnect to report an established
// DTLS connection, so a fallback fails the cell instead of passing as a false
// green.
//
// The TLS1.3 requirement is the precondition, not decoration. internal/anyconnect
// documents that the DTLS PSK is derived through the RFC 5705 exporter, which
// needs TLS 1.3 or Extended Master Secret — and that when neither is available a
// silent fallback to the TLS tunnel is *correct*, not a failure. So demanding
// DTLS is only legitimate while the CSTP session is known to offer the exporter.
// Asserting that first means a session that ever stopped being TLS 1.3 fails
// here, naming the reason, instead of failing on the DTLS line and reading as a
// veepin bug.
func TestInteropAnyConnectClientVeepinServerDTLS(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("anyconnect", "pki")
	if err := generateAnyConnectServerCert(pkiDir); err != nil {
		t.Fatalf("generate AnyConnect cert: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInteropRequiringLog(t, "compose.anyconnect-server-dtls.yml", "openconnect", "10.11.0.1",
		"ciphersuite (TLS1.3)", "Established DTLS connection")
}

// TestInteropAnyConnectClientVeepinServerShaped is the same cell with downstream
// flow shaping on: the veepin server pads the CSTP data payload past the inner
// IP packet.
//
// This is the load-bearing cell for AnyConnect, because CSTP has no padding
// provision of its own -- its length field just says how many octets follow.
// The filler is inert only because the receiver delimits the real packet by the
// IP header's Total Length, which every IP stack must do since Ethernet pads
// short frames the same way. A successful ping is what turns that argument into
// a tested fact, since a mis-trimmed packet could not produce a valid reply.
func TestInteropAnyConnectClientVeepinServerShaped(t *testing.T) {
	requireDocker(t)
	pkiDir := filepath.Join("anyconnect", "pki")
	if err := generateAnyConnectServerCert(pkiDir); err != nil {
		t.Fatalf("generate AnyConnect cert: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })
	runInterop(t, "compose.anyconnect-server-shaped.yml", "openconnect", "10.11.0.1")
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

// TestInteropL2TPClientVeepinServerShaped is the same cell with downstream flow
// shaping on. L2TP/IPsec stacks PPP inside L2TP inside ESP, and the padding goes
// in the innermost of those -- the PPP Information field, which RFC 1661 5.1
// allows to be padded and leaves the carried protocol to delimit. Padding there
// rather than with ESP's own TFC padding keeps the shaper reading the inner
// 5-tuple, the only place it is still visible.
//
// A ping reply proves pppd trims the filler by the inner IP header rather than
// merely tolerating it, since a mis-trimmed packet could not produce one.
func TestInteropL2TPClientVeepinServerShaped(t *testing.T) {
	runInterop(t, "compose.l2tp-server-shaped.yml", "l2tp-client", "10.20.0.1")
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

// TestInteropVeepinNebulaShaped is the cell that makes nebula's shaping mean
// something. veepin pads each inner packet out to the interface MTU inside the
// AEAD plaintext, and the reference slackhq/nebula daemon is told nothing about
// it: it decrypts, writes the plaintext to its TUN, and the kernel delimits the
// real packet by the inner IP header's Total Length.
//
// A veepin-to-veepin cell would prove only that our padder and our trimmer
// agree, which is the failure this matrix exists to distrust. The claim is
// about a receiver we did not write.
func TestInteropVeepinNebulaShaped(t *testing.T) {
	// The log line is required, not decorative. A ping passes just as happily
	// on a shaper that quietly did nothing -- the same silent-fallback trap
	// runInteropRequiringLog exists for elsewhere in this file -- so the cell
	// has to demand that padding actually happened as well as that the peer
	// tolerated it.
	runInteropRequiringLog(t, "compose.nebula-shaped.yml", "veepin-nebula", "10.42.0.1",
		"shaping outbound packets to")
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
// TestInteropNebulaRelay proves the relay fallback: two hosts whose direct UDP
// path is dropped by iptables, reaching each other through the lighthouse.
//
// It uses runInteropRequiringLog rather than a bare ping, and that is the point
// of the cell rather than a detail of it. A ping across a working direct path
// and a ping across a working relay are indistinguishable from outside, so a
// cell that only pinged would pass just as happily if the iptables rules had
// not taken effect and the relay code had never run. The log lines require both
// halves of the negotiation to have actually happened: the middle host agreeing
// to forward, and the end host recording the relay as established.
//
// This is the same discipline that caught the Pulse ESP keying bug, where a
// silent fallback to the TLS tunnel was passing a bare ping while the ESP path
// -- the thing under test -- was broken at both ends.
func TestInteropNebulaRelay(t *testing.T) {
	runInteropRequiringLogFrom(t, "compose.nebula-relay.yml",
		"veepin-host-b", "veepin-lighthouse", "10.42.0.3",
		"relaying for 10.42.0.2 to 10.42.0.3")
}

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

// TestInteropAioquicClientVeepinProxyShaped is the cell that makes MASQUE's
// shaping mean something. veepin pads each inner packet out to the inner MTU
// inside the DATAGRAM capsule's value, and aioquic is told nothing about it:
// RFC 9484's context-0 payload carries no length of its own, so the receiver
// hands everything after the context ID to its TUN and the kernel delimits the
// real packet by the inner IP header's Total Length.
//
// The log line is required as well as the ping. A ping passes just as happily
// on a shaper that quietly did nothing, which is the whole failure mode the
// -shape work exists to avoid claiming.
func TestInteropAioquicClientVeepinProxyShaped(t *testing.T) {
	runInteropRequiringLogFrom(t, "compose.masque-server-shaped.yml",
		"aioquic-masque-client", "veepin-masque-server", "10.32.0.1",
		"shaping outbound packets to")
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

// TestInteropOpenconnectFortinetClientVeepinServerShaped is the same cell with
// downstream flow shaping on. The Fortinet data channel is PPP over TLS, so the
// padding vehicle is the one RFC 1661 5.1 sanctions -- arbitrary filler after
// the Information field, distinguished from data by the carried protocol -- and
// this proves openconnect's Fortinet receive path actually trims it by the inner
// IP header rather than passing the whole frame through.
func TestInteropOpenconnectFortinetClientVeepinServerShaped(t *testing.T) {
	runInterop(t, "compose.fortinet-shaped.yml", "opnc-fortinet-client", "10.40.0.1")
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

// GlobalProtect (Palo Alto Networks SSL VPN). The independent peer is the real
// openconnect client (--protocol=gp), which implements both of the protocol's
// data paths -- so these cells move packets and verify veepin's server-side
// login, the positional jnlp document, the config XML including its keying
// block, the 16-octet framing and the ESP path against a stack that shares none
// of veepin's code. There is no open Palo Alto *gateway* to run the veepin
// client against with a full data path, so that direction is covered by the self
// cell and unit tests.

// TestInteropOpenconnectGPClientVeepinServer runs the openconnect GlobalProtect
// client against the veepin gateway on the SSL tunnel and pings 10.50.0.1, the
// gateway.
func TestInteropOpenconnectGPClientVeepinServer(t *testing.T) {
	runInteropBench(t, "compose.gp.yml", "opnc-gp-client", "veepin-gp-server", "10.50.0.1")
}

// TestInteropOpenconnectGPClientVeepinServerESP is the same cell on the ESP data
// path, which is the part of GlobalProtect nothing else here resembles: the
// gateway generates both SPIs and all four keys and hands them over inside the
// configuration XML, and the client wakes the path up with marker ICMP pings.
// The ping alone would pass on a silent fallback to the SSL tunnel, so the run
// additionally requires openconnect to report an established ESP session.
func TestInteropOpenconnectGPClientVeepinServerESP(t *testing.T) {
	runInteropRequiringLog(t, "compose.gp-esp.yml", "opnc-gp-client", "10.50.0.1",
		"ESP session established with server")
}

// TestInteropOpenconnectGPClientVeepinServerShaped is the SSL-tunnel cell with
// downstream flow shaping on. GlobalProtect's tunnel carries bare layer-3
// packets, so the padding is trailing filler after the inner packet and the
// receiver must trim it by the IP header's own Total Length -- which every IP
// stack does. This proves openconnect's GlobalProtect receive path does too,
// rather than handing the padded buffer to the interface whole.
func TestInteropOpenconnectGPClientVeepinServerShaped(t *testing.T) {
	runInterop(t, "compose.gp-shaped.yml", "opnc-gp-client", "10.50.0.1")
}

// TestInteropGPSelf is the veepin<->veepin sanity check. veepin's client prefers
// the ESP path wherever the gateway hands out keys for one, so this also
// exercises the activation exchange between the two veepin roles.
func TestInteropGPSelf(t *testing.T) {
	runInteropRequiringLog(t, "compose.gp-self.yml", "veepin-gp-client", "10.50.0.1",
		"tunnel up over ESP")
	measureThroughput(t, "compose.gp-self.yml", "veepin-gp-server", "veepin-gp-client", "10.50.0.1")
}

// Cisco IPsec is the other IKEv1 profile in this tree: Aggressive Mode with a
// group pre-shared key, XAuth, Mode-Config and a tunnel-mode ESP SA. Both
// directions run against strongSwan, which is the only open-source stack that
// implements both roles of it — so unlike the SSL VPNs, this protocol gets a
// real peer in the client direction as well as the server one.

// TestInteropVeepinCiscoClientStrongSwanServer runs the veepin client against a
// strongSwan Aggressive Mode + XAuth responder and pings 10.20.30.254, the
// address strongSwan holds inside its own traffic selector.
func TestInteropVeepinCiscoClientStrongSwanServer(t *testing.T) {
	runInteropBench(t, "compose.cisco.yml", "veepin-cisco-client", "strongswan-cisco-server", "10.20.30.254")
}

// TestInteropStrongSwanCiscoClientVeepinServer is the mirror, exercising
// veepin's responder: the group-key lookup from the Aggressive Mode identity,
// the XAuth exchange it drives, the Mode-Config assignment, and a Quick Mode
// whose traffic selectors strongSwan's policy has to accept.
func TestInteropStrongSwanCiscoClientVeepinServer(t *testing.T) {
	runInteropBench(t, "compose.cisco-server.yml", "strongswan-cisco-client", "veepin-cisco-server", "10.60.0.1")
}

// TestInteropStrongSwanCiscoClientVeepinServerShaped is the same cell with
// downstream shaping on. The padding is RFC 4303 section 2.7
// traffic-flow-confidentiality filler, which strongSwan negotiated nothing for
// and must discard by reading the inner IP header's own length. A receiver that
// handed the padded buffer up whole would not answer the ping.
func TestInteropStrongSwanCiscoClientVeepinServerShaped(t *testing.T) {
	runInterop(t, "compose.cisco-server-shaped.yml", "strongswan-cisco-client", "10.60.0.1")
}

// TestInteropCiscoSelf is the veepin<->veepin sanity check.
func TestInteropCiscoSelf(t *testing.T) {
	runInterop(t, "compose.cisco-self.yml", "veepin-cisco-client", "10.60.0.1")
	measureThroughput(t, "compose.cisco-self.yml", "veepin-cisco-server", "veepin-cisco-client", "10.60.0.1")
}

// Ivanti Connect Secure has no open-source server, so only the server direction
// gets a real peer: openconnect's --protocol=pulse is the only implementation of
// this protocol outside Ivanti's own, and it implements the client alone. The
// client-direction cell carries the fixed label rather than a false failure.

// TestInteropOpenconnectPulseClientVeepinServer runs the openconnect Ivanti
// client against the veepin gateway on the IF-T/TLS data path and pings
// 10.70.0.1, the gateway.
func TestInteropOpenconnectPulseClientVeepinServer(t *testing.T) {
	runInteropBench(t, "compose.pulse.yml", "opnc-pulse-client", "veepin-pulse-server", "10.70.0.1")
}

// TestInteropOpenconnectPulseClientVeepinServerESP is the same cell on the ESP
// data path. The ping alone would pass on a silent fallback to the IF-T/TLS
// connection, so the run additionally requires openconnect to report that the
// ESP path came up.
func TestInteropOpenconnectPulseClientVeepinServerESP(t *testing.T) {
	runInteropRequiringLog(t, "compose.pulse-esp.yml", "opnc-pulse-client", "10.70.0.1",
		"ESP session established")
}

// TestInteropOpenconnectPulseClientVeepinServerShaped is the IF-T/TLS cell with
// downstream shaping on: the padding is trailing filler the receiver must trim
// by the inner IP header's own length.
func TestInteropOpenconnectPulseClientVeepinServerShaped(t *testing.T) {
	runInterop(t, "compose.pulse-shaped.yml", "opnc-pulse-client", "10.70.0.1")
}

// TestInteropPulseSelf is the veepin<->veepin sanity check, over the ESP path
// both ends prefer.
func TestInteropPulseSelf(t *testing.T) {
	runInterop(t, "compose.pulse-self.yml", "veepin-pulse-client", "10.70.0.1")
	measureThroughput(t, "compose.pulse-self.yml", "veepin-pulse-server", "veepin-pulse-client", "10.70.0.1")
}

// TestInteropSoftEtherSelf is the cell internal/livingreadme/interop.go said was
// owed for as long as the SoftEther row existed -- and building it is what found
// why it could not be built.
//
// Neither end pumped frames. softether.Dial opened a TAP, returned its name in
// the Result and started nothing; the server's switch forwarded between
// *sessions* only, with the host's own interface not on the switch at all. So
// every SoftEther tunnel came up, authenticated, reported an interface and
// carried nothing, and the row's three dashes read as "not built yet" rather
// than "there is no data path".
//
// The ping is therefore the whole point: it leaves the client's TAP, crosses
// TLS, is switched onto the server's local bridge port, and arrives on an
// interface the server's kernel answers for. A handshake that completes and
// moves no frame fails here, which is the state this protocol was in until now.
// TestInteropVeepinClientSoftEtherServer is the cross-implementation cell the
// README's `‡` footnote has owed since the SoftEther row landed: veepin's
// client against SoftEther VPN Server speaking its own native protocol.
//
// Building it is what found that the row had never been interoperable. The
// PACK codec was little-endian where the reference is big-endian, element
// names were written as C strings where the reference writes a length that
// counts a NUL it omits, passwords were hashed with SHA-1 where the reference
// uses SHA-0 over a different concatenation, the control plane had no HTTP
// layer at all, and the data path wrote one little-endian length per frame
// where the reference writes a big-endian block count. Five layers, five
// mistakes, and a veepin-to-veepin cell that passed through every one of them
// because both ends made the same choice each time.
//
// The ping target is SecureNAT's virtual gateway. Reaching it means an ARP
// request left veepin's TAP, crossed a real SoftEther's switch, and was
// answered -- which is the claim the row makes and could not previously back.
func TestInteropVeepinClientSoftEtherServer(t *testing.T) {
	// runInterop, not runInteropBench. The ping target is SecureNAT's virtual
	// gateway, which is synthesised by the SoftEther daemon rather than being
	// an address on any interface -- there is nothing to run `iperf3 -s` on,
	// and the image does not carry iperf3 at all. That is the case the
	// throughput table's legend already describes as a dash: "a peer with no
	// bindable tunnel address (SoftEther's SecureNAT gateway)". Measuring
	// anyway would publish a ✗, which that table defines as a measurement
	// that is broken rather than absent, and would be a false accusation
	// against a cell that passes.
	runInterop(t, "compose.softether.yml", "veepin-softether-client", "192.168.30.1")
}

// TestInteropSoftEtherShaped runs the same veepin<->veepin cell with the server
// padding the first 4 KiB of each inner flow out towards the frame MTU.
//
// The claim is that the padding is inert, and layer 2 is where that claim is
// most easily broken: ARP has no length field to trim by, so an implementation
// that padded every frame rather than only the IP-bearing ones would corrupt
// the first exchange across the segment and the tunnel would never carry
// anything. A ping that crosses proves both halves -- the padding was applied
// and the receiver trimmed it.
func TestInteropSoftEtherShaped(t *testing.T) {
	runInterop(t, "compose.softether-shaped.yml", "veepin-softether-client", "10.70.0.1")
}

func TestInteropSoftEtherSelf(t *testing.T) {
	runInteropBench(t, "compose.softether-self.yml",
		"veepin-softether-client", "veepin-softether-server", "10.70.0.1")
}

// TestInteropSoftEtherClientVeepinServer is the direction the README's `‡`
// footnote has owed since the SoftEther row landed: SoftEther's own vpnclient
// against veepin's server, which closes the last cell in the matrix that was
// work outstanding rather than a limitation.
//
// Building it found one incompatibility, and in the same layer the client
// direction found four of its five: vpnclient opens the connection with `GET /`
// and posts the signature second. ServerDownloadSignature is a loop that
// answers up to nineteen requests before the signature arrives; veepin's server
// read exactly one request and judged it, so every real client was refused on
// its opening move. Nothing in the tree noticed, because veepin's own client
// posts the signature first and the self cell therefore never exercised the
// case.
//
// It also settled two things internal/softether/README.md had named as blockers
// and neither was. The welcome carries no policy structure: PackGetPolicy
// zero-fills, so a welcome without one parses, and the client enforces none of
// the fields locally. And the client opens no additional connections, because
// max_connection=1 is what the welcome advertises and ClientAdditionalConnectChance
// compares the live count against exactly that. Both had been reasoned about
// for months; the cell answered them in an afternoon, which is the argument for
// cells over reasoning in one sentence.
//
// The ARP assertion is the layer-2 claim and nothing else here makes it: a ping
// between two statically-addressed endpoints succeeds identically over an L3
// tunnel, so the neighbour entry -- learned on the virtual NIC specifically --
// is what proves Ethernet frames crossed.
func TestInteropSoftEtherClientVeepinServer(t *testing.T) {
	runInteropBench(t, "compose.softether-server.yml",
		"se-client", "veepin-softether-server", "10.71.0.1")
	requireARPInsideTunnel(t, "compose.softether-server.yml", "se-client", "vpn_se", "10.71.0.1")
}

// The IP-TFS (RFC 9347 AGGFRAG) cells, against strongSwan 6.0.7.
//
// Every one of them requires a log line naming AGGFRAG, and that is not
// belt-and-braces. swanctl.opt says of the mode outright: "The transport, iptfs
// and beet modes are subject to mode negotiation; tunnel mode is negotiated if
// the preferred mode is not available." So a veepin that failed to negotiate
// USE_AGGFRAG gets an ordinary tunnel-mode Child SA from strongSwan and a ping
// that crosses it perfectly. A bare ping is the textbook false green here, in
// the peer's own documented words.
//
// AGGFRAG had no cross-implementation cell at all until these, and
// internal/ikev2/aggfrag/README.md said so: "a self-test shows the two halves
// agree, not that either is right." Building them found two bugs neither half
// could see. The notify was sent with an empty body where RFC 9347 §6.1.4 gives
// it one octet of flags, which strongSwan refuses the whole IKE_AUTH message
// over. And inbound AGGFRAG was decapsulated by the single-packet method on any
// TUN with GSO -- which rejects ESP next header 144 outright, so every packet
// was dropped while the handshake reported IP-TFS working.

// TestInteropVeepinClientStrongswanIPTFS drives veepin's client against a
// strongSwan responder configured with `mode = iptfs`.
func TestInteropVeepinClientStrongswanIPTFS(t *testing.T) {
	runInteropRequiringLog(t, "compose.iptfs.yml", "veepin-client", "10.20.30.254",
		"AGGFRAG (RFC 9347) negotiated")
}

// TestInteropStrongswanClientVeepinServerIPTFS is the direction that catches a
// responder echoing USE_AGGFRAG without meaning it: strongSwan installs an XFRM
// SA in mode 5 (IPTFS) on the strength of the echo, so a veepin that then sent
// plain inner IP would have every packet dropped by the kernel while the
// handshake still looked perfect.
//
// The log requirement is read from the veepin SERVER, not from the pinging
// container, because the claim is about what veepin did.
func TestInteropStrongswanClientVeepinServerIPTFS(t *testing.T) {
	runInteropRequiringLogFrom(t, "compose.iptfs-server.yml",
		"strongswan-client", "veepin-server", "10.10.10.1",
		"AGGFRAG (RFC 9347) negotiated")
}

// TestInteropIPTFSSelf proves both roles exist and that the aggregating data
// path survives a real socket and a real TUN. It proves nothing about
// correctness against a peer -- for as long as AGGFRAG existed in the tree, two
// veepin ends agreed about a notify strongSwan refuses outright.
func TestInteropIPTFSSelf(t *testing.T) {
	runInteropRequiringLog(t, "compose.iptfs-self.yml", "veepin-client", "10.10.10.1",
		"AGGFRAG (RFC 9347) negotiated")
}

// TestInteropIPTFSConstantRate is the only cell in the harness that measures a
// claim rather than proving a path, because the claim cannot be proved by a
// path: constant-rate transmission says the datagram stream does not depend on
// the traffic inside it, and a ping, a throughput run and an AGGFRAG log line
// are all equally true of a sender that pauses when idle.
//
// So the traffic is varied and the stream is watched for NOT changing, and the
// observer is the peer: strongSwan's own XFRM byte counters on the SA receiving
// from veepin. That is as independent as this harness gets -- veepin is not
// consulted about how much it sent.
//
// The peer receives a constant-rate stream perfectly without producing one. Pad
// blocks are ordinary AGGFRAG and a receiver needs no knowledge that the sender
// is pacing, which is what lets the half nothing else implements still have a
// real cross-implementation cell.
func TestInteropIPTFSConstantRate(t *testing.T) {
	const file = "compose.iptfs-constant.yml"
	// 1 250 000 B/s, matching IPTFS_RATE in the compose file.
	const wantBytesPerSec = 1250000

	runInteropRequiringLog(t, file, "veepin-client", "10.20.30.254",
		"AGGFRAG (RFC 9347) negotiated")

	idle := measureESPRate(t, file, 4*time.Second, nil)
	busy := measureESPRate(t, file, 4*time.Second, func() {
		// Saturate the tunnel for the whole window. -f floods, -w1 bounds it.
		_, _ = compose(t, file, "exec", "-T", "veepin-client",
			"ping", "-f", "-w", "4", "10.20.30.254")
	})

	t.Logf("ESP arriving at the peer: idle %.0f B/s, saturated %.0f B/s (configured %d)",
		idle, busy, wantBytesPerSec)

	if idle == 0 {
		t.Fatal("the peer received nothing while the tunnel was idle: the sender stops " +
			"when there is no traffic, which is the schedule constant-rate removes")
	}
	// Within 15% of the configured rate in both states. The tolerance is for
	// timer jitter and the four-second window, not for load: a stream that
	// tracked the traffic would differ by far more than this.
	for _, m := range []struct {
		name string
		rate float64
	}{{"idle", idle}, {"saturated", busy}} {
		if ratio := m.rate / wantBytesPerSec; ratio < 0.85 || ratio > 1.15 {
			t.Errorf("%s rate %.0f B/s is %.2f× the configured %d",
				m.name, m.rate, ratio, wantBytesPerSec)
		}
	}
	// And the two must agree with EACH OTHER, which is the claim itself.
	if ratio := busy / idle; ratio < 0.85 || ratio > 1.15 {
		t.Errorf("saturated/idle = %.2f: the datagram stream follows the offered load, "+
			"so it still carries the signal constant-rate transmission exists to remove",
			ratio)
	}
}

// measureESPRate reads the peer's XFRM byte counter for the SA receiving from
// veepin, before and after a window, and returns bytes per second. load, if
// given, runs for the duration of the window.
//
// The counter is the peer's, deliberately. Asking veepin how much it sent would
// test the sender against its own bookkeeping; asking the kernel that received
// it tests what actually crossed the wire.
func measureESPRate(t *testing.T, composeFile string, window time.Duration, load func()) float64 {
	t.Helper()
	before := espInBytes(t, composeFile)
	start := time.Now()
	if load != nil {
		load()
	}
	if elapsed := time.Since(start); elapsed < window {
		time.Sleep(window - elapsed)
	}
	elapsed := time.Since(start)
	after := espInBytes(t, composeFile)
	if after < before {
		t.Fatalf("the peer's ESP byte counter went backwards (%d -> %d): the SA was "+
			"rekeyed mid-measurement", before, after)
	}
	return float64(after-before) / elapsed.Seconds()
}

// espInBytes reads the inbound SA's lifetime byte count out of `ip -s xfrm
// state`.
//
// The awk is fussier than it looks and has to be. "dir in" precedes its own
// lifetime blocks, but there are two of them and the FIRST is `lifetime
// config`, whose "limit: soft (INF)(bytes)" line matches a naive search for
// "(bytes)" and parses as nothing. The counter wanted is under `lifetime
// current`.
func espInBytes(t *testing.T, composeFile string) uint64 {
	t.Helper()
	out, err := compose(t, composeFile, "exec", "-T", "strongswan-server",
		"sh", "-c", `ip -s xfrm state | awk '/dir in/{d=1} d && /lifetime current/{c=1; next} c && /\(bytes\)/{print $1; exit}'`)
	if err != nil {
		t.Fatalf("reading the peer's XFRM counters: %v\n%s", err, out)
	}
	field := strings.TrimSpace(out)
	if i := strings.IndexByte(field, '('); i >= 0 {
		field = field[:i]
	}
	n, err := strconv.ParseUint(strings.TrimSpace(field), 10, 64)
	if err != nil {
		t.Fatalf("the peer's XFRM byte counter did not parse: %q (%v)", out, err)
	}
	return n
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

// runInterop brings up the given compose file, then retries pinging every target
// from pingSvc across the tunnel until all succeed or pingDeadline elapses. A
// successful ping proves the full path: handshake, config-mode addressing, and
// bidirectional ESP. Passing both an IPv4 and an IPv6 target proves a dual-stack
// tunnel carries both families (ping auto-selects the family from the literal).
// The stack is always torn down; logs are dumped on failure.
func runInterop(t *testing.T, composeFile, pingSvc string, targets ...string) {
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

	for _, target := range targets {
		deadline := time.Now().Add(pingDeadline)
		var last string
		ok := false
		for time.Now().Before(deadline) {
			out, err := compose(t, composeFile, "exec", "-T", pingSvc,
				"ping", "-c2", "-W2", target)
			if err == nil && strings.Contains(out, "0% packet loss") {
				t.Logf("tunnel up: %s pinged %s across the tunnel", pingSvc, target)
				ok = true
				break
			}
			last = out
			time.Sleep(3 * time.Second)
		}
		if !ok {
			t.Fatalf("cross-tunnel ping %s -> %s never succeeded within %s:\n%s",
				pingSvc, target, pingDeadline, last)
		}
		pingLarge(t, composeFile, pingSvc, target)
	}
}

// largePingPayload is the ICMP payload of the second ping every cell now sends,
// after the small one has proved the tunnel is up.
//
// Every cell in this matrix used to ping with ping's default 56-octet payload
// and nothing else, which made the easy case the only case across the whole
// matrix. datapath_test.go sweeps {64, 576, 1400} in Go, but a length field one
// octet short, a buffer sized from a literal, a shaper that overshoots its
// target, or an MTU derived wrongly are all invisible to an 84-octet datagram
// and all of them break a real transfer immediately.
//
// 1000 is chosen against the smallest inner MTU in the tree -- nebula's 1300 --
// so it is a genuinely large packet on every protocol without becoming a test
// of path-MTU discovery, which is a different mechanism with its own cells. It
// is twelve times the packet the matrix used to settle for.
const largePingPayload = 1000

// pingLarge sends the large ping and fails if it does not cross.
//
// It is a fatal check rather than a warning: a tunnel that carries 84 octets and
// not 1028 is broken for every real use, and reporting that as a pass is exactly
// the shape of false green this matrix exists to catch. It retries, because the
// small ping succeeding does not mean every route and NAT rule has settled.
func pingLarge(t *testing.T, composeFile, pingSvc, target string) {
	t.Helper()
	deadline := time.Now().Add(pingDeadline)
	var last string
	for time.Now().Before(deadline) {
		out, err := compose(t, composeFile, "exec", "-T", pingSvc,
			"ping", "-c2", "-W2", "-s", strconv.Itoa(largePingPayload), target)
		if err == nil && strings.Contains(out, "0% packet loss") {
			t.Logf("%s pinged %s with a %d-octet payload", pingSvc, target, largePingPayload)
			return
		}
		last = out
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("%s -> %s carries a small ping but not a %d-octet one within %s; "+
		"something in the framing, the buffers or the MTU is sized for the easy case:\n%s",
		pingSvc, target, largePingPayload, pingDeadline, last)
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
// README-generation step.
//
// A failure is still swallowed rather than failing the interop test — the ping is
// the assertion, the rate is information (see runInteropBench). But it now logs a
// failed marker, so the table can show that this cell was measured and broke
// rather than leaving it indistinguishable from a cell iperf3 does not apply to.
func measureThroughput(t *testing.T, composeFile, serverSvc, clientSvc, target string) {
	t.Helper()

	// -s server, one-shot (-1: exit after a single client), detached. No -B, so
	// it listens on all interfaces including the tunnel one; the client reaches
	// it by the tunnel-internal target address.
	if out, err := compose(t, composeFile, "exec", "-d", serverSvc, "iperf3", "-s", "-1"); err != nil {
		t.Logf("throughput: iperf3 server did not start in %s: %v\n%s", serverSvc, err, out)
		t.Log(livingreadme.IperfFailedLine(t.Name()))
		return
	}
	time.Sleep(benchWarmup)

	// -J JSON, -t short measured window, -O omit the first second (TCP slow
	// start), bounded connect. -c takes the tunnel-internal server address.
	out, err := compose(t, composeFile, "exec", "-T", clientSvc,
		"iperf3", "-c", target, "-J", "-t", "4", "-O", "1", "--connect-timeout", "5000")
	if err != nil {
		t.Logf("throughput: iperf3 client %s -> %s failed: %v\n%s", clientSvc, target, err, out)
		t.Log(livingreadme.IperfFailedLine(t.Name()))
		return
	}
	bps, err := parseIperfBits(out)
	if err != nil {
		t.Logf("throughput: could not read iperf3 result: %v", err)
		t.Log(livingreadme.IperfFailedLine(t.Name()))
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
// Several wants may be given, and all must appear. That is how a cell states a
// precondition alongside its outcome: requiring only the outcome makes a
// legitimate degradation indistinguishable from a break, and the failure then
// points at the wrong thing (see the AnyConnect DTLS cell).
func runInteropRequiringLog(t *testing.T, composeFile, pingSvc, target string, wants ...string) {
	t.Helper()
	runInteropRequiringLogFrom(t, composeFile, pingSvc, pingSvc, target, wants...)
}

// runInteropRequiringLogFrom is runInteropRequiringLog where the service that
// must report the log line is not the one doing the pinging. The server
// direction needs this: the peer's client pings, but the claim being checked is
// about what the *veepin server* did.
func runInteropRequiringLogFrom(t *testing.T, composeFile, pingSvc, logSvc, target string, wants ...string) {
	t.Helper()
	if len(wants) == 0 {
		t.Fatal("runInteropRequiringLogFrom needs at least one required log line")
	}
	runInterop(t, composeFile, pingSvc, target)

	deadline := time.Now().Add(logDeadline)
	var logs string
	for time.Now().Before(deadline) {
		out, err := compose(t, composeFile, "logs", "--no-color", logSvc)
		if err == nil {
			logs = out
			missing := false
			for _, want := range wants {
				if !strings.Contains(logs, want) {
					missing = true
					break
				}
			}
			if !missing {
				t.Logf("%s reported %s", logSvc, quoteAll(wants))
				return
			}
		}
		time.Sleep(3 * time.Second)
	}

	var absent []string
	for _, want := range wants {
		if !strings.Contains(logs, want) {
			absent = append(absent, want)
		}
	}
	t.Fatalf("the tunnel came up but %s never appeared in %s's logs within %s:\n%s",
		quoteAll(absent), logSvc, logDeadline, logs)
}

// quoteAll renders a set of required log lines for a message: `"a" and "b"`.
func quoteAll(wants []string) string {
	quoted := make([]string, len(wants))
	for i, w := range wants {
		quoted[i] = strconv.Quote(w)
	}
	return strings.Join(quoted, " and ")
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

// composeTimeout bounds one `docker compose` invocation.
//
// Eight minutes is comfortably more than any cell needs once its images are
// present: the slowest shard builds veepin from a cold cache and still comes
// in under three.
//
// It was briefly raised to fifteen, to absorb a Docker Hub pull that stalled at
// 32 kB of a 2.8 MB layer. That did not work -- the pull was still stuck at
// fifteen -- and it was the wrong place to fix it anyway: a registry veepin
// does not control should not be spending a cell's budget at all, and a stall
// there reports as `compose up: signal: killed`, which reads as a veepin
// failure. The images a shard pulls are now declared in the interop manifest
// and fetched by a workflow step that retries and says whose fault it is. This
// cap is back to bounding what it can actually diagnose: a cell that hangs.
const composeTimeout = 8 * time.Minute

// compose runs `docker compose -f <file> <args...>` in the test's directory
// (which holds the compose files and their relative build contexts).
func compose(t *testing.T, file string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), composeTimeout)
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
