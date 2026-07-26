# Downstream flow shaping

Status: **implemented for IKEv2/ESP and WireGuard, off by default.** The shaper
itself (`dataplane/shape.go`) is protocol-agnostic and drives any tunnel that
implements `dataplane.PaddingTunnel`; two do. Enabled with `-shape <bytes>` on
`veepin serve ikev2|wireguard`, or the `shape` key through the registry.

The interop cells that exercise a shaped server against **strongSwan** and
**wireguard-go** both pass, so two independent third-party receivers accept the
padding and trim it correctly. The default is still off, because those are Linux
userspace stacks and the clients this is meant to protect — Windows, macOS, iOS —
are untested. See [Risk](#the-risk-worth-naming).

## The problem

veepin's data path passes inner packet sizes through almost transparently: one
inner IP packet becomes one outer datagram whose size is the inner size plus a
fixed per-protocol overhead. Encryption hides the *contents* and changes none of
the *shape*.

That is enough to fingerprint what the tunnel carries. The attack is
[*Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes*][usenix24]
(Xue, Kallitsis, Houmansadr, Ensafi — USENIX Security 2024). It is
protocol-agnostic and indifferent to the tunnel's cryptography: when a tunnel
carries a user's TLS session, the **inner** handshake's sequence of packet sizes
and directions is recoverable through the outer encryption. Random padding and
multiple layers of encapsulation blur it; similarity-based classifiers recover
it anyway. It works against obfs4, Shadowsocks, VMess and Trojan, and it is why
"make the bytes look random" is not a long-term defence — the byte-level
obfuscation those designs invest in is not what gives them away.

Before this change veepin leaked the same signal, as badly as any of them.

[usenix24]: https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting

## Why a VPN can defend more cheaply than a proxy

Two structural properties, and both are why the work belongs here rather than in
a protocol package.

**The distinctive half of the fingerprint is downstream.** The multi-kilobyte
ServerHello-and-Certificate flight is the part a classifier keys on hardest, and
downstream is the direction the *server* controls. So the defence is server-side
and needs no client change at all. A stock Windows, macOS, iOS or Android IKEv2
client, or an official WireGuard app, gets the benefit unmodified — which
matters, because every probe-resistant transport that actually works (REALITY,
Shadow-TLS, obfs4) requires a custom client, and a VPN's users mostly do not
have one.

**The attack targets handshakes, which sit at the start of a flow.** So the
strongest available padding can be spent on the first few kilobytes of each
inner flow and switched off afterwards. The cost is O(number of flows), not
O(bytes): a bulk transfer pays once, at the beginning, and its steady-state
throughput is untouched. This is what makes "pad everything to the MTU" — the
strongest answer to size analysis, and normally an unaffordable one — affordable.

## The design

`dataplane.Shaper` answers one question per outbound packet: *what size should
this packet's plaintext be padded to?*

- Packets are keyed by inner 5-tuple into a bounded flow table.
- Each new flow gets a budget of `ShapeBytes` (default 16384, comfortably more
  than a TLS 1.2 handshake carrying a full certificate chain).
- While a flow has budget, the target is the **full inner MTU**. Quantising to a
  ladder of smaller size classes would be cheaper, but every class left standing
  is signal a classifier can still use.
- When the budget is spent, the target is zero and the flow costs nothing —
  one map lookup and a comparison — forever after.
- A flow idle for `ShapeIdle` (default 30s) has its budget re-armed, so a reused
  connection carrying a second handshake is shaped again.

The table is bounded the way `dataplane.PacketConn` bounds its peer-address map:
an amortised idle sweep plus a hard `MaxFlows` cap that drops the whole map on
overflow. Every entry is a cache the next packet rebuilds, so the worst outcome
of dropping it is that some flows are shaped from the start again.

### Where the padding goes

Padding has to live inside each protocol's own wire format, so the capability is
optional and discovered by type assertion — the idiom `Pump` already uses for
`SetPeerAddr`:

```go
type PaddingTunnel interface {
	Tunnel
	EncapsulatePadded(ipPacket []byte, minInner int) ([]byte, error)
}
```

A tunnel that does not implement it is sent unpadded. The shaper degrades to a
no-op rather than to an error, which is what lets shaping be switched on without
every protocol having a vehicle for it.

| Protocol | Vehicle | Peer support needed |
|---|---|---|
| **IKEv2/ESP** | Traffic-flow-confidentiality padding, [RFC 4303][rfc4303] §2.7 — filler inside the payload, before the ESP trailer | None |
| **WireGuard** | Trailing octets of the transport message, generalising the alignment padding the protocol paper §5.4.6 already mandates | None |

Neither needs negotiation, and that is not an accident: **in both protocols the
inner packet is delimited by its own IP header**, so filler appended past its end
is inert to any conforming receiver. `dataplane.TrimToIP` is the receiving half —
one implementation, shared by both, cutting a decapsulated plaintext back to the
length its header declares.

ESP's Pad Length field is a single octet, so the ESP *alignment* pad caps at 255
bytes and cannot carry this on its own; §2.7 padding going inside the payload is
both the specified mechanism and the one without a length ceiling. The trim for
ESP lives in `internal/ikev2/ike` rather than `internal/ikev2/esp`, because only
the former interprets the next-header value that says whether there is an inner
IP packet at all — a next-header of 59 is a pure filler packet and is dropped.

[rfc4303]: https://www.rfc-editor.org/rfc/rfc4303#section-2.7

### Cost

Padding costs no extra allocation. Both protocols already size a single output
buffer from the padded length and lay the plaintext down inside it, so the filler
is written into a buffer that had to exist anyway. `TestPaddedDataPathAllocations`
and `TestShaperAllocations` hold this.

The GSO egress path (`pump_gso_linux.go`) is naturally inert: the kernel only
hands up a TSO super-frame for bulk transfer, and its segments already arrive at
the MTU. A super-frame is never a handshake, so there is nothing to hide.

The measurable prediction is that the iperf3 numbers in the README's interop
matrix should be **essentially unchanged**, because a single long-lived flow
exhausts its budget within the first few packets. A visible regression there
means the flow gate is not working.

## What this does not defend against

Stated plainly, in the same spirit as [`security.md`](security.md), because each
is the kind of thing a reader might otherwise assume is covered.

- **Packet counts and inter-arrival times still leak.** Padding removes the size
  signal inside the shaped window; the *number* of downstream packets in a
  certificate flight, and their timing, are untouched. Closing that needs
  constant-rate shaping, which taxes exactly the moment that is most
  latency-sensitive — the handshake — and is deliberately out of scope. The
  shaper never delays or reorders a packet.
- **Upstream is unshaped unless the client is also veepin.** That is inherent to
  the stock-client constraint: the server cannot change what a client it did not
  write puts on the wire. `veepin connect -shape` covers the other direction
  when both ends are ours.
- **This is not probe resistance.** It does nothing about a censor that connects
  to the server and speaks the protocol. A stock client's first flight contains
  no secret, so a server that serves stock clients must answer an unauthenticated
  probe; no amount of shaping changes that.
- **Efficacy here is argued, not measured.** The design follows from the
  published attack's mechanism, and the padding is verified to do what it says
  by unit and round-trip tests. No classifier was built and no detection-rate
  reduction is claimed.

## The risk worth naming

RFC 4303 §2.7 specifies TFC padding and requires receivers to handle it, but
*"the RFC says MUST"* and *"this vendor's stack was tested against it"* are
different claims, and the second is the one that matters for a stock client.
WireGuard is the safer of the two — its receivers have always had to trim by the
inner header for the mandatory 16-octet alignment padding — but ESP receivers
vary.

Two receivers are now known good:
`TestInteropStrongswanClientVeepinServerShaped` and
`TestInteropWireguardClientVeepinServerShaped` both pass, and each proves more
than acceptance: the ping *reply* can only be produced by a receiver that
trimmed the filler by the inner IP header rather than by the payload length, so
a stack that merely tolerated the padding without stripping it would fail the
cell rather than pass it quietly.

What is still untested is the set of clients that motivated the whole design —
the Windows, macOS and iOS IPsec stacks. strongSwan is genuine independent
evidence, not veepin talking to itself, but it is not a vendor OS stack, and no
containerised one exists to test against. **Verifying those means a manual run
against a real device**, which is why the default stays off. If a vendor stack
rejects padded ESP, the honest outcome is that shaping stays opt-in for IKEv2 —
not that the padding is quietly weakened to something that no longer hides the
size pattern.

## Next

Ordered by value, not by ease:

1. **A manual check against a stock Windows / macOS / iOS client**, which is what
   would justify changing the default.
2. **Stream-carried protocols** (SSTP, AnyConnect, Fortinet, OpenVPN-TCP, SSH).
   Their observable is the TLS *record* size, not the datagram size, so the
   mechanism is different — coalescing writes and emitting discardable filler
   frames, for which each protocol already has a vehicle (PPP LCP Echo, CSTP
   keepalive, `SSH_MSG_IGNORE`, an unregistered MASQUE capsule type). Additive:
   `PaddingTunnel` does not fit them and they will want a sibling interface.
3. **Padding the handshake itself.** The shaper only sees packets on the data
   path, so the tunnel's *own* handshake — which has a fixed, per-protocol size
   signature of its own — is untouched by this work.

## Interaction with parallelisation

`Shaper` carries no lock. It is owned by the single goroutine that runs
`Pump.Run`, the same single-owner argument that leaves `groTable` unlocked.
[`scaling-the-data-path.md`](scaling-the-data-path.md) enumerates the assumptions
a naive parallelisation would break; this adds one. Splitting the egress path
across cores requires either a `Shaper` per worker — which weakens the flow
budget, since a flow's packets could then be counted twice — or sharding the flow
table by the same key the workers are dispatched on.
