// Package veepin is a from-scratch userspace VPN implemented in pure Go, with
// golang.org/x/crypto its only dependency (WireGuard mandates ChaCha20-Poly1305
// and BLAKE2s, which the standard library does not ship).
//
// It speaks eight protocols, as both an initiator and a responder for every one:
// IKEv2/ESP, WireGuard, OpenVPN, SSTP, SSH, L2TP/IPsec, AnyConnect and Nebula.
// Each is verified in Docker against a real third-party implementation in both
// directions, and against itself.
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
//   - wireguard, internal/wireguard/... — Noise_IKpsk2 and the transport crypto.
//   - openvpn, internal/openvpn/... — the TLS control channel and P_DATA_V2.
//   - sstp, internal/sstp/... — SSTP over TLS, with PPP.
//   - ssh, internal/sshtun — tun@openssh.com channels.
//   - l2tp, internal/l2tp, internal/ikev1 — L2TP over an IKEv1-keyed ESP SA.
//   - anyconnect, internal/anyconnect, internal/dtls — CSTP over TLS, with a
//     from-scratch DTLS 1.2 PSK data channel.
//   - nebula, internal/nebula — a mesh overlay: Noise IX, CA-issued host
//     certificates, and lighthouse discovery.
//
// Two packages are shared by the PPP-carrying protocols: internal/ppp (LCP,
// MS-CHAPv2, IPCP, both roles) and internal/mschap.
//
// # The example protocol
//
// toy and internal/toy implement TOY, which is NOT one of the eight above and
// PROVIDES NO SECURITY. It is a worked example of how a protocol is assembled
// here — a handshake producing a client.Result, a dataplane.Pump data path, both
// roles registered — with the cryptography replaced by deliberately worthless
// placeholders. internal/toy/SPEC.md documents the wire format and enumerates
// how and why it fails. Read it to learn the structure; never to carry traffic.
package veepin
