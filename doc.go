// Package veepin is a from-scratch userspace VPN implemented in pure Go, with
// golang.org/x/crypto its only dependency (WireGuard mandates ChaCha20-Poly1305
// and BLAKE2s, which the standard library does not ship).
//
// It speaks sixteen production protocols, as both an initiator and a responder
// for every one: IKEv2/ESP, WireGuard, OpenVPN, SSTP, SSH, L2TP/IPsec,
// L2TPv3 Ethernet pseudowire, AnyConnect, Nebula, MASQUE, Fortinet,
// GlobalProtect, Cisco IPsec, Ivanti Connect Secure, SoftEther VPN (SE-VPN)
// and AmneziaWG. Each is verified in Docker against a real third-party
// implementation, and against itself.
//
// The tree is arranged so a further protocol is a sibling rather than a rewrite:
//
//   - cmd/veepin — the command: connect, serve and probe subcommands.
//   - client — the protocol registry, and the Session/Result/Server contracts
//     every protocol produces.
//   - dataplane — TUN device, address pool, packet pump and client routing;
//     protocol-agnostic.
//   - internal/cryptoutil — the cryptographic primitives; protocol-agnostic.
//
// The public package for each protocol is its supported surface (Dial and
// NewServer, plus a typed Config); the implementation lives under internal:
//
//   - ikev2, internal/ikev2/... — IKEv2 with a userspace ESP data path.
//
//   - wireguard, internal/wireguard/... — Noise_IKpsk2 and the transport crypto.
//
//   - openvpn, internal/openvpn/... — the TLS control channel and P_DATA_V2.
//
//   - sstp, internal/sstp/... — SSTP over TLS, with PPP.
//
//   - ssh, internal/sshtun — tun@openssh.com channels.
//
//   - l2tp, internal/l2tp, internal/ikev1 — L2TP over an IKEv1-keyed ESP SA.
//
//   - anyconnect, internal/anyconnect, internal/dtls — CSTP over TLS, with a
//     from-scratch DTLS 1.2 PSK data channel.
//
//   - nebula, internal/nebula — a mesh overlay: Noise IX, CA-issued host
//     certificates, and lighthouse discovery.
//
//   - masque, internal/masque — IP (CONNECT-IP) and UDP (CONNECT-UDP) over
//     HTTP/3, on a from-scratch HTTP/3 layer over golang.org/x/net/quic.
//
//   - fortinet, internal/fortinet — the FortiOS SSL VPN: PPP over TLS, with a
//     certificate-based DTLS 1.2 channel alongside it.
//
//   - gp, internal/gp — the Palo Alto GlobalProtect SSL VPN: an HTTPS exchange
//     that hands out ESP keys directly, then RFC 4303 ESP over UDP, with a
//     framed layer-3 tunnel over TLS as the fallback.
//
//   - cisco, internal/cisco, internal/ikev1 — Cisco-style IPsec remote access:
//     IKEv1 Aggressive Mode with a group key, XAuth, Mode-Config, and a
//     tunnel-mode ESP SA.
//
//   - pulse, internal/pulse — Ivanti Connect Secure: IF-T/TLS framing with EAP
//     inside it, and either RFC 4303 ESP over UDP or that same connection for
//     data.
//
//   - softether, internal/softether — SoftEther VPN native protocol: Ethernet
//     frames over TLS, using the PACK key/value serialisation for control and
//     raw Ethernet on a TAP device for data.
//
//   - amneziawg — DPI-resistant WireGuard fork: the same Noise IK handshake
//     and ChaCha20-Poly1305 transport, with configurable message-type constants
//     and random padding to defeat packet-signature classification.
//
//   - l2tpv3, internal/l2tpv3 — L2TPv3 Ethernet pseudowire (RFC 3931 + 4719):
//     layer-2 Ethernet frames over UDP, with a static session and optional
//     cookie and sublayer. Uses a TAP device instead of TUN.
//
// Two packages are shared by the PPP-carrying protocols: internal/ppp (LCP,
// MS-CHAPv2, IPCP, both roles) and internal/mschap.
//
// # The example protocol
//
// toy and internal/toy implement TOY, which is NOT one of the sixteen above and
// PROVIDES NO SECURITY. It is a worked example of how a protocol is assembled
// here — a handshake producing a client.Result, a dataplane.Pump data path, both
// roles registered — with the cryptography replaced by deliberately worthless
// placeholders. internal/toy/SPEC.md documents the wire format and enumerates
// how and why it fails. Read it to learn the structure; never to carry traffic.
package veepin
