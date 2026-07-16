// Package veepin is a from-scratch userspace VPN implemented in pure Go, with
// no dependencies beyond the standard library.
//
// IKEv2 (RFC 7296) is the first protocol, as both a responder and an initiator,
// with a userspace ESP data path. The tree is arranged so further protocols are
// siblings rather than rewrites:
//
//   - cmd/veepin — the command: connect, serve and probe subcommands.
//   - client — the protocol registry and the Session/Result contract every
//     protocol produces.
//   - ikev2 — the public IKEv2 entry point (Dial, NewServer).
//   - dataplane — TUN device, address pool, packet pump and client routing;
//     protocol-agnostic.
//   - internal/cryptoutil — the cryptographic primitives; protocol-agnostic.
//   - internal/ikev2/... — the IKEv2 protocol implementation.
package veepin
