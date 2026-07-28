# What veepin might speak next

Thirteen production protocols are in the tree as of v0.8.0. This page ranks what
could come next and says plainly what each is worth; the per-candidate plans it
links to carry the wire detail.

The ranking criterion is not "how many protocols" — it is **what a candidate
teaches the tree that nothing already in it does**. On that measure the SSL-VPN
seam is close to mined out: openconnect supports seven protocols and veepin
implements five of them, so the two that remain are the cheapest additions
available and also the least interesting.

| Candidate | New capability | Effort | Real peer, both roles? | Plan |
|---|---|---|---|---|
| **SoftEther native** *(landed, partial — no TAP data path)* | **Layer 2.** Every existing protocol is L3; this needs TAP, MAC learning and in-tunnel ARP | High | **Yes** — Apache-2.0 client *and* server | [softether-plan.md](softether-plan.md) |
| **Hybrid PQ IKEv2** (RFC 9370) *(landed, interop-verified)* | Post-quantum key exchange; `crypto/mlkem` is in the stdlib | Medium | Yes — strongSwan 6.x, already the IKEv2 peer | [pq-ikev2-plan.md](pq-ikev2-plan.md) |
| **AmneziaWG** *(landed, interop-verified)* | DPI/probe resistance — a class the tree has none of | Medium | Yes — `amneziawg-go` | [amneziawg-plan.md](amneziawg-plan.md) |
| **Rosenpass** | PQ handshake feeding WireGuard's PSK | Medium | Yes — Rust reference implementation | [rosenpass-plan.md](rosenpass-plan.md) |
| Juniper NC / Array / F5 | Nothing structural | Low | Client only | [openconnect-remainder-plan.md](openconnect-remainder-plan.md) |

## Recommendation

**If one:** SoftEther native. It is the only candidate that grows `dataplane`
rather than adding a sibling beside it, and the only one with an open-source
implementation of *both* roles — which is what the interop matrix is worth most
when it has.

**Best return on effort:** hybrid PQ IKEv2. It reuses `internal/ikev2` wholesale,
interops against a peer already in the harness, and closes the one gap a 2026 VPN
codebase is conspicuously missing. The dependency question that would have killed
it is settled: `crypto/mlkem` ships in the Go standard library as of 1.24, so it
costs no new module (verified on Go 1.25.0 — ML-KEM-768 round-trips, encapsulation
key 1184 octets, ciphertext 1088, shared key 32).

**Deliberately last:** the openconnect remainder. F5 is structurally a near-clone
of Fortinet, Array is a fourth variation on "HTTPS login, then framed packets",
and Juniper NC is Pulse's predecessor sharing most of its shape. They would each
add a row to the README and teach nothing. Worth doing only if completing the
openconnect column is itself the goal.

## Rosenpass is filed differently on purpose

It is excellent work — Classic McEliece plus Kyber, formally verified, with a
published whitepaper — but it is a key-exchange *daemon*, not a tunnel protocol.
It has no data path of its own; it feeds a key into WireGuard's pre-shared-key
slot every two minutes. Registering it as a fourteenth protocol would put
something in the registry that cannot answer `Dial`. The plan therefore describes
it as a **WireGuard option**, which is what it actually is.

## What was considered and rejected outright

- **tinc** — SPTPS ships only in Debian *experimental*, as a decade-old
  `1.1pre18`. The interop peer would be a source build of a perpetual
  pre-release.
- **ZeroTier** — VL1 alone drags in roots, a planet file and a controller, and
  VL2 adds Ethernet emulation on top. The surface is a product, not a protocol.
- **PPTP** — broken, and nothing to learn from implementing it correctly.
- **Proxy protocols** (Shadowsocks, VLESS, Trojan, Hysteria) — transport
  obfuscation for TCP/UDP flows, not layer-3 VPNs. MASQUE already covers the
  "tunnel IP over a web protocol" idea in a standardised form.
