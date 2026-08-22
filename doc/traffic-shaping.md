# Downstream flow shaping

Status: **implemented for IKEv2/ESP, WireGuard, OpenVPN, SSTP, Fortinet,
AnyConnect and L2TP/IPsec; off by default.** The shaper itself
(`dataplane/shape.go`) is protocol-agnostic. Enabled with `-shape <bytes>` on
`veepin serve`, or the `shape` key through the registry.

Seven interop cells exercise a shaped server against an independent receiver —
**strongSwan**, **wireguard-go**, **`openvpn`**, **sstpc/pppd**, **openconnect**
twice (its AnyConnect and Fortinet data paths) and **strongSwan + xl2tpd** — and
all pass, so every third-party stack tested accepts the padding and trims it
correctly. The default is still off, because those are all Linux userspace
stacks and the clients this is meant to protect — Windows, macOS, iOS — are
untested. See [Risk](#the-risk-worth-naming).

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
- The budget is charged what each packet **emits**, not what it carries, so
  `ShapeBytes` bounds what shaping costs and a flow gets `ShapeBytes/MTU` padded
  packets whatever sizes it is carrying. Charging the inner length instead — as
  this did originally — let a flow of small packets run far past the budget's
  apparent cost: at 60-octet packets a 16 KiB budget shaped 273 of them and put
  382 KiB on the wire, which made the affordability argument above untrue for
  exactly the traffic that needs shaping most. The bound is the budget plus at
  most one MTU, because a flow with any budget left shapes the next packet in
  full rather than refusing it.
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
| **SSTP**, **Fortinet**, **L2TP/IPsec** | The PPP Information field, [RFC 1661][rfc1661] §5.1 — "MAY be padded with an arbitrary number of octets up to the MRU" | None |
| **AnyConnect** | Trailing octets of the CSTP (or DTLS-channel) data payload, which the 16-bit length field already delimits | None |
| **OpenVPN** | Trailing octets of the data-channel payload; on the CBC channel the filler goes before the PKCS#7 trailer so the trailer stays valid | None |

None of them needs negotiation, and that is not an accident: **in every one the
inner packet is delimited by its own IP header**, so filler appended past its end
is inert to any conforming receiver. `dataplane.TrimToIP` is the receiving half —
one implementation, shared by all of them, cutting a decapsulated plaintext back
to the length its header declares.

RFC 1661 §5.1 makes this explicit for PPP: padding is allowed and "it is the
responsibility of each protocol to distinguish padding octets from real
information", which IP does with Total Length. CSTP has no such provision — its
length field simply says how many octets follow — so AnyConnect padding rests on
the receiver trimming by the IP header. That is not a gamble: every IP stack must
do it already, because Ethernet pads frames shorter than 60 octets and the IP
layer has always had to cut back to Total Length. The openconnect interop cell is
what turns that argument into a tested fact.

[rfc1661]: https://www.rfc-editor.org/rfc/rfc1661#section-5.1

L2TP/IPsec is the one stack with a choice of vehicle: it nests PPP inside L2TP
inside ESP, so either the PPP padding or ESP's own §2.7 TFC padding would work.
It uses the PPP one, because the shaper keys on the inner 5-tuple and that is
only visible above the L2TP wrapping — padding at the ESP layer would mean
either re-parsing the inner packet back out or shaping every flow identically.

### Datagram protocols and stream protocols take different routes

For the datagram protocols the shaper runs inside `dataplane.Pump`, which owns
the TUN reader and dispatches to a `Tunnel`. The stream protocols do not use
`Pump` — each is connection-oriented and runs its own TUN loop, one goroutine
serving every client — so each calls `Shaper.Target` there directly and hands the
target to its own framing (`ppp.EncapsulateIPPadded`, `anyconnect.padPayload`).
That single TUN goroutine is also what makes one unsynchronised `Shaper` per
server safe, the same argument as for `Pump`.

The observable differs too. For a datagram protocol the outer datagram size *is*
what a censor measures. For a TLS-carried protocol it is the TLS record size —
but each of these servers turns one inner packet into exactly one `Write` on the
`tls.Conn`, so one padded packet is one record of the padded size, and padding
the payload is sufficient. What is *not* implemented is coalescing several inner
packets into one record, which would additionally hide the packet count; that
remains open, below.

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
  certificate flight, and their timing, are untouched. The shaper never delays
  or reorders a packet.

  The count leak is worth stating precisely, because two plausible fixes do not
  work and the reason rules out a whole family of them. With shaping on, every
  downstream packet in the window emits exactly one MTU, so

  ```
  downstream_bytes = N × MTU        (N = downstream packet count)
  ```

  and an observer recovers `N = bytes / MTU` however those bytes are chunked
  into records or segments. **Coalescing several inner packets into one record
  therefore cannot hide the count** — it re-chunks the same total. Only emitting
  bytes that are not real packets breaks the relation, which means filler.

  But **appending filler does not hide the count either**, and this is the part
  that matters. "The flow has gone quiet" can only be *detected* by waiting, so
  any scheme that adds no latency necessarily emits its filler after a gap —
  and the gap marks exactly where the real packets stopped:

  ```
  real    t₀, t₀+ε, t₀+2ε, t₀+3ε, t₀+4ε      5 packets, back to back
  filler  t₀+250ms …                          7 packets, after the idle timer
          └─ observer counts 5 before the gap ─┘
  ```

  Emitting filler with no such gap means emitting on a schedule that does not
  reveal which packets were real — constant rate — which delays real packets to
  the tick boundary by construction.

  So **the count leak and the timing leak are one leak.** Neither can be closed
  without the other, and closing them costs handshake latency. That is a real
  option (a bounded constant-rate window, affordable because the budget already
  caps it at `ShapeBytes/MTU` packets) but it is not a free one, and it is the
  opposite of the trade this design has made everywhere else. See
  [Next](#next).

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
WireGuard is the safest — its receivers have always had to trim by the inner
header for the mandatory 16-octet alignment padding — and PPP is close behind,
since RFC 1661 §5.1 names padding outright. CSTP is the weakest of the four: it
specifies no padding at all, so AnyConnect leans entirely on the receiver
trimming by the IP header. ESP receivers, meanwhile, vary.

Seven receivers are now known good — strongSwan, wireguard-go, `openvpn`, pppd
(behind sstpc and again behind xl2tpd), and openconnect on both its AnyConnect
and its Fortinet data path.

Be precise about what a passing cell proves, because it is easy to overstate.
The ping *reply* proves the padded packet was **accepted and the inner packet
recovered intact end to end** — the peer did not reject the over-long frame,
truncate it, or mangle it. It does *not* prove the peer's own code did the
trimming: a receiver that passed all 1400 octets to its TUN would still work,
because the kernel's IP layer trims to Total Length on ingress anyway (the same
behaviour that has always been needed for Ethernet's 60-octet minimum frame).

That distinction does not matter operationally — either way the user's traffic
is correct — but it matters for knowing what has been tested. What the cells
rule out is the failure that would actually break a deployment: a peer that
refuses or corrupts a padded packet. What they cannot rule out is a peer whose
*own* trim is absent but whose kernel covers for it, which would surface only
on a stack that hands frames somewhere other than an IP interface.

What is still untested is the set of clients that motivated the whole design —
the Windows, macOS and iOS IPsec stacks, the Windows SSTP and L2TP clients,
FortiClient, Cisco's own AnyConnect. Every receiver above is genuine independent evidence,
not veepin talking to itself, but they are all Linux userspace, and no
containerised vendor stack exists to test against. **Verifying those means a
manual run against a real device**, which is why the default stays off.
[`verifying-shaping.md`](verifying-shaping.md) is the procedure — the server
invocation per client, and `scripts/verify-shaping.sh` to run on the device — so
that it is a twenty-minute job rather than an afternoon. If one
of them rejects padded packets, the honest outcome is that shaping stays opt-in
for that protocol — not that the padding is quietly weakened to something that
no longer hides the size pattern.

## Next

Ordered by value, not by ease:

1. **A manual check against a stock Windows / macOS / iOS client**, which is what
   would justify changing the default. This is now a scripted procedure rather
   than an open question: see [`verifying-shaping.md`](verifying-shaping.md). It
   is the highest-value item on this list by a distance, because until it is done
   the feature is off and everything else here is dormant.
2. **Every protocol is shaped now**, and the three that were outstanding each
   answered a different question.

   **MASQUE** did not need the vehicle this document proposed. The suggestion
   was a filler capsule of an unregistered type, which RFC 9297 requires
   receivers to skip. That would have tested aioquic's compliance with a MUST;
   what shipped pads *inside* the DATAGRAM capsule's value, because RFC 9484's
   context-0 payload is "context ID, then an IP packet" with no length of its
   own — so the receiver hands everything after the context ID to its TUN and
   the kernel delimits by Total Length, exactly as everything else here relies
   on. It works against a receiver that skips unknown capsules and one that does
   not, which is a strictly weaker requirement on the peer.

   **Nebula** forced the placement rather than offering a choice. Its 16-octet
   header is passed to the AEAD as additional data, so octets appended after the
   tag are unauthenticated and a conforming receiver rejects the datagram
   instead of trimming it. The filler goes inside the sealed payload.

   **SSH was the one this document was wrong about, twice.** The claim here used
   to be that "`SSH_MSG_IGNORE` exists for exactly this". The message exists in
   the protocol; it is not reachable through `x/crypto/ssh`'s public surface —
   `msgIgnore = 2` is unexported, there is no raw-packet write, and
   `Conn.SendRequest` sends a global request (message 80) instead. Same shape of
   rejection as the RFC 9221 MASQUE datagram finding in `protocol-roadmap.md`,
   and recorded rather than deleted because the next reader would otherwise
   spend the same afternoon on it.

   The correction after that was also wrong in the opposite direction: trailing
   filler was called "mostly plumbing", and it was not. An SSH channel is a byte
   stream with no packet delimiter, so `internal/sshtun`'s reader recovers
   boundaries from the IP length — which means filler after a packet is read as
   the *next* packet's address-family header, and the stream desynchronises from
   that point on. The symptom is a corrupt tunnel rather than a padding bug, and
   it only shows up on the second packet.

   The fix is a framing property rather than a protocol change: the family
   header is `00 00 00 02` or `00 00 00 0a`, so a whole zero word can only be
   filler. `ReadPacket` reads 4-octet words and discards the zero ones, which
   costs the unshaped case nothing and is why `EncodePadded` pads by whole
   words. A stock OpenSSH peer needs none of it — it writes each channel message
   to its tun in one call and the kernel trims — and
   `compose.ssh-server-shaped.yml` is what turned that argument into evidence.

   SoftEther was on this list and is not any more. It confirmed the "mostly
   plumbing" reading — the padding is trailing filler on the Ethernet frame,
   trimmed by the inner IP header's Total Length exactly as L2TPv3's is — with
   one thing worth carrying to the three that remain: **`ShapeableFrame` matters
   more on layer 2 than on layer 3.** ARP has no length field to trim by, so a
   layer-2 shaper that padded every frame rather than only the IP-bearing ones
   would corrupt the first exchange across the segment, before any IP packet
   existed to notice. `TestShapeFramePadsIPAndLeavesEverythingElse` is the
   guard, and `compose.softether-shaped.yml` is the cell.
3. **A bounded constant-rate window**, if the count and timing leaks are judged
   worth paying for. Within a flow's shaped window, emit one MTU-sized packet per
   tick — a real one when queued, discardable filler when not — so the two are
   indistinguishable. The budget already caps this at `ShapeBytes/MTU` packets, so
   the cost is bounded: one tick of added latency per packet during the window,
   and no more bandwidth than shaping already spends.

   Every protocol has a filler vehicle (OpenVPN's keepalive ping, AnyConnect's
   `typeKeepalive`, and for the PPP-carried protocols an IPv4 packet to
   192.0.2.0/24, which any non-forwarding host drops silently — unlike an LCP
   Echo or a closed port, which would draw a *reply* and put traffic on the
   upstream direction the server cannot shape).

   This is deliberately not built. It reverses the trade the rest of the design
   makes — never delay a packet — and it taxes the handshake, which is both the
   most latency-sensitive moment and the one the whole feature exists to protect.
   It should be a separate opt-in knob if it is built at all, not a change to
   what `-shape` means.
4. ~~**Padding the handshake itself.**~~ Investigated and dropped, for two
   independent reasons.

   It is *impossible* for WireGuard: handshake messages are exact-size checked
   (`internal/wireguard/wire/wire.go`, and identically in wireguard-go), so a
   padded initiation or response is dropped rather than tolerated. Unlike the
   data path, there is no self-delimiting inner packet to hide behind.

   And where it is possible it buys almost nothing, because **a censor
   identifies a handshake by structure, not by size**: WireGuard's type byte and
   fixed length, IKEv2's header version and exchange type on udp/500, OpenVPN's
   opcode byte — the primary feature in the USENIX '22 work — and the
   distinctive HTTP request lines of the TLS-carried protocols. Padding a size
   does not touch any of those. Worse, every one of them is emitted by the
   *stock client*, so they cannot be changed at all without giving up the
   constraint that makes this whole design worth having. See
   [`stock-client-constraint`](#what-this-does-not-defend-against).

   The general lesson, which is why it is recorded rather than deleted: size
   shaping helps where a protocol is *already* structurally indistinguishable
   and only its sizes give it away. That describes obfs4 and Shadowsocks. It
   does not describe a VPN speaking a published protocol to a stock client.

## Interaction with parallelisation

`Shaper` carries no lock. It is owned by the single goroutine that reads the TUN
— `Pump.Run` for the datagram protocols, each stream server's own TUN loop
otherwise — the same single-owner argument that leaves `groTable` unlocked.
[`scaling-the-data-path.md`](scaling-the-data-path.md) enumerates the assumptions
a naive parallelisation would break; this adds one. Splitting the egress path
across cores requires either a `Shaper` per worker — which weakens the flow
budget, since a flow's packets could then be counted twice — or sharding the flow
table by the same key the workers are dispatched on.
