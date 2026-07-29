# What veepin might speak next

Fifteen production protocols are in the tree. This page ranks what could come
next, says plainly what each is worth, and carries the implementation plan for
each — the wire detail, the reuse, the interop shape, and the honest caveats.

The ranking criterion is not "how many protocols" — it is **what a candidate
teaches the tree that nothing already in it does**. On that measure the SSL-VPN
seam is mined out: openconnect supports seven protocols and veepin implements
five, so the three that remain are the cheapest additions available and also the
least interesting.

## The ranking

| # | Candidate | Filed as | New capability | Effort | Real peer, both roles? |
|---|---|---|---|---|---|
| 1 | **L2TPv3 Ethernet pseudowire** (RFC 3931 + 4719) | **New row** | **Layer 2**, actually delivered — the gap SoftEther left open | Medium-high | **Yes** — the Linux kernel, both directions |
| 2 | **IP-TFS / AGGFRAG** (RFC 9347) | IKEv2 option | **Constant-rate traffic-flow confidentiality** — shapes packet *counts and timing*, which `dataplane/shape.go` explicitly does not | Medium | Partly — strongSwan 6.0.2+ does aggregation; **nobody open-source does the constant-rate half** |
| 3 | **Nebula relays** | Nebula option | Relay fallback when hole punching fails | Low | Yes — `nebula`, already pinned and green |
| 4 | **RFC 9329** (TCP encapsulation of IKE and IPsec) | IKEv2 option | IPsec through a UDP-hostile network; brings **libreswan** in as a new peer | Low | Yes — libreswan 4.0+, both roles |
| 5 | **Rosenpass** | WireGuard option | PQ handshake feeding WireGuard's PSK | Medium | Yes — Rust reference implementation |
| 6 | Juniper NC / Array / F5 | New rows | Nothing structural | Low | Client only |
| — | **Tailscale** (ts2021 / DISCO / DERP) | — | Coordinated mesh with relay fallback | Very high | **No — fails the "both roles" rule** |

**If one: L2TPv3.** It is the only candidate that grows `dataplane` rather than
adding a sibling beside it, and its interop peer is the Linux kernel — no daemon,
no vendor binary, no version to pin, nothing that can rot.

**Best return on effort: Nebula relays.** ~600–800 LOC to close a gap the tree
already admits in writing, against a peer already in the harness.

**Most interesting: IP-TFS.** It is the only candidate where veepin can implement
*more* than the reference implementation does and still have a peer for the
shared subset.

## A note on filing

Three candidates here are filed as options on an existing protocol rather than
as registry rows. That is a deliberate convention, not a hedge:

> **A capability that cannot answer `Dial` on its own is an option on the
> protocol that carries it**, because the registry's count is a claim about what
> veepin speaks.

Rosenpass is a key-exchange daemon with no data path — it feeds a key into
WireGuard's PSK slot. IP-TFS is IKEv2 negotiating `USE_AGGFRAG` and putting a
different payload inside the same ESP SA. RFC 9329 is IKEv2 over a different
socket. Registering any of them would put an entry in the registry that is
something-else-wearing-a-hat, and `docs_test.go`'s spelled-out counts would then
overstate what veepin actually does.

---

# 1. L2TPv3 Ethernet pseudowire — a new registry row

## Why this is first

`doc/softether-plan.md` says it plainly: *"veepin has no layer 2."* SoftEther was
supposed to close that and landed partial — the learning bridge that plan
specifies as `internal/softether/switch.go` is still unwritten, and
`dataplane/tun_linux.go:86` has a working `OpenTAP` (`cIFF_TAP | cIFF_NO_PI` at
:96) that nothing in the tree calls.

L2TPv3 closes the gap on better terms, for one reason: **the peer is the Linux
kernel.** `ip l2tp add tunnel` / `ip l2tp add session` configures a static
L2TPv3 Ethernet pseudowire in both directions with no daemon and no vendor
binary. Of every candidate on this page it has the most durable interop peer.

It is also, unlike SoftEther, a protocol whose *entire content* is the layer-2
data path. There is no login flow, no TLS, no config channel to build first. The
L2 work cannot be deferred, which is why it will actually get done.

## The wire format

RFC 3931 (L2TPv3) and RFC 4719 (Ethernet pseudowire). A data packet over UDP:

```
 0                   1                   2                   3
 +-------------------------------+-------------------------------+
 | T=0, flags, Ver=3             | Reserved                      |
 +---------------------------------------------------------------+
 | Session ID (32 bits)                                          |
 +---------------------------------------------------------------+
 | Cookie (0, 4 or 8 octets, chosen by the RECEIVER)             |
 +---------------------------------------------------------------+
 | Default L2-Specific Sublayer (0 or 4 octets: S bit + 24b seq) |
 +---------------------------------------------------------------+
 | Ethernet frame                                                |
 +---------------------------------------------------------------+
```

Four facts that decide the implementation:

- **Session ID is a single 32-bit value**, replacing v2's tunnel-ID/session-ID
  pair. It is the demux key, at **offset 4** over UDP (offset 0 over IP protocol
  115).
- **The cookie is chosen by the receiver** and advertised to the sender. The two
  directions may use different cookies, or one may use none while the other does.
  This is the asymmetry that a from-scratch implementation gets backwards.
- **The kernel emits an all-zeros sublayer even when sequencing is off.** A
  receiver that treats a zero sublayer as "absent" mis-parses every frame the
  kernel sends. Presence is a session property agreed out of band (static) or
  negotiated (dynamic) — **never inferred from content.**
- **Pseudowire type 5 = Ethernet** (4 is Ethernet VLAN). Encapsulate over
  UDP/1701; IP protocol 115 is out of scope.

**Before writing the encoder**, read `net/l2tp/l2tp_core.c`'s
`l2tp_build_l2tpv3_header()` and take a `tcpdump -xx` golden vector off a live
kernel-to-kernel pseudowire. Commit the hex as a fixture. This step is what the
Pulse work skipped, and the cipher identifiers in that plan were wrong as a
result.

## Phase 0 — `client.Result.Layer2`, and a live bug it fixes

`client.Result.Validate` (`client/client.go:113`) requires `TUNName` and reasons
about `AssignedIP`/`Netmask`/`Gateway` as tunnel-internal addressing. A layer-2
tunnel assigns **no L3 address at all** — the address comes from DHCP or ARP
*inside* the bridged segment, after the interface is up.

`softether/softether.go:98` already returns a `Result` with `TUNName` and no
address, so this is an existing bug, not a new requirement:

```go
// Layer2 marks a tunnel whose interface carries Ethernet frames, not IP
// packets. Such a tunnel assigns no address of its own -- the interface joins a
// bridged segment and gets its address from DHCP or ARP inside it -- so the
// addressing checks below do not apply. The Gateway check still does: an outer
// address is an outer address whatever the tunnel carries.
Layer2 bool
```

Set it in `softether/softether.go` in the same commit, with a test asserting a
bare `{TUNName, Layer2}` result validates clean.

## Phase 1 — `internal/l2tpv3/`, codecs first

**A new package, not a version switch inside `internal/l2tp`.** The AmneziaWG
precedent: a protocol that differs on the wire gets its own package even when it
shares ancestry. v2 is PPP-over-L2TP with a 16-bit tunnel/session pair; v3 is a
pseudowire with a 32-bit session ID. They share the AVP encoding and nothing
else, and threading a version flag through `internal/l2tp`'s 2,113 lines would
make both harder to read.

Copy the ~120 lines of `avpBuilder`/`parseAVPs`/`findAVP`/`findUint16` from
`internal/l2tp/message.go:171-259` and extend for v3's 32-bit AVPs. Copying is
right here; the alternative is a shared package that exists to serve two callers
with divergent needs.

- `frame.go` — data-packet encode/decode, returning **subslices** (hard rule).
  Cookie length and sublayer presence are per-session config, passed in.
- `message.go` — the AVP builder/parser.
- `session.go` — local/remote Session ID, both cookies, both sublayer flags,
  peer address.
- `frame_test.go` — the reject-every-truncation loop over every prefix of a
  valid packet, plus the kernel golden vector.

Two tests that are claims, both guarding a mutually-consistent bug:

- **`TestCookieIsChosenByTheReceiver`**, written from the kernel's point of
  view: given the cookie the kernel was told to expect on *its* receive side,
  assert veepin puts that cookie on its *send* side. Wire it backwards at both
  ends and veepin↔veepin passes perfectly — this is the `internal/pulse`
  key-direction bug in a different costume.
- **`TestSublayerZeroIsStillPresent`**, so a tidy-up cannot "fix" the all-zeros
  sublayer into an absent one.

## Phase 2 — the data path, and why it does not use `dataplane.Pump`

**`dataplane.Pump` must not carry Ethernet frames.** `Pump.routeOutbound`
(`dataplane/pump.go:388`) calls `innerDest` (:457), which reads the first nibble
of the buffer as an IP version. An Ethernet frame's first nibble is the top
nibble of the destination MAC. That does not fail cleanly — it **occasionally
succeeds by accident**, on frames whose destination MAC happens to start `0x4`
or `0x6`, which is the worst available failure mode.

So: `internal/l2tpv3/pump.go`, a small L2-specific pump. Reused unchanged:

- **`dataplane.Demux`** (`dataplane/pump.go:70`) — Session ID at offset 4 is a
  `uint32`, structurally identical to `SPIDemux` (:73).
- **`dataplane.PacketConn`** / `batchconn.go` — recvmmsg batching.
- **`dataplane.OpenTAP`** — finally called by something.

Not reused: **GRO/GSO**. Both parse IP and TCP headers at fixed offsets, and
neither offset means anything in an Ethernet frame. Do not wire them.

**MTU.** 1500 outer, less 20 IPv4, 8 UDP, 4 L2TPv3 header, 4 sublayer, 14
Ethernet header, and the cookie: **1446 with no cookie, 1438 with an 8-octet
cookie.** Pin both numbers in a test.

## Phase 3 — shaping, with a limit stated rather than hidden

`dataplane/shape.go`'s `flowKeyOf` (:213) parses an IP header. Add
`flowKeyOfFrame`, reading the 14-octet Ethernet header, which **shapes only
EtherType 0x0800 and 0x86DD** and falls through to unshaped for everything else.

The reason is structural. **Ethernet has no length field.**
`dataplane.TrimToIP` (:278) works because an IP header carries its own Total
Length, so a receiver trims padding with nothing negotiated. A padded ARP frame
has nothing to trim by. Shaping IP-inside-Ethernet is safe because the trim
still happens off the inner IP header; shaping ARP or STP is not. State it in
`internal/l2tpv3/README.md`'s caveats section.

## Phase 4 — facade, CLI, docs

`l2tpv3/` with `Config`, `Opt*`, `Dial`, `NewServer`, and both
`client.Register` and `client.RegisterServer`. Options: `gateway`, `port`
(1701), `session-id`, `peer-session-id`, `cookie`, `peer-cookie`, `tap`,
`shape`. `Dial` returns `Result{TUNName, Layer2: true, Gateway: <outer>}` — no
address. Implement `client.Prober`: a pseudowire is silent by construction.

Then the mechanical guards, each of which fails loudly and by name:

- **The blank import in `doc.go` goes in first.** Forget it and the count check
  passes against a registry that has not heard of the protocol.
- README: protocol table row, usage-runbook row, and **every** spelled-out
  count — fifteen becomes **sixteen**, and TOY becomes the **seventeenth**
  registered protocol.
- `cmd/veepin/connect.go` + `serve.go`; `main_test.go` and `flags_test.go`
  enforce both, and `flags_test.go` perturbs each bound flag and requires the
  option map to change.
- `doc/usage/l2tpv3.md`, `internal/l2tpv3/README.md`, and a `doc/security.md`
  section. **L2TPv3 alone is unauthenticated and unencrypted** — say so as
  bluntly as the existing bare-L2TP section does.
- `datapath_test.go` — `AllocsPerRun` guard and `Benchmark*` over
  `{64, 576, 1400}`.
- `fuzz_test.go` + the `TARGETS` heredoc in `.github/workflows/ci.yml` +
  `expected=N`.
- NM: `nmconfig.go`, `nm/Makefile`, the `FieldDef` table and `PROTO` row in
  `nm/editor/veepin-editor.c`, and the blank import in
  `nm/cmd/nm-veepin-service/main.go`.

## Phase 5 — interop, static first

**Verify the harness before writing the compose file.** The cell depends on
`l2tp_eth`, `l2tp_core` and `l2tp_netlink` being loadable on a GitHub runner.
Check `modprobe l2tp_eth` in the target image *first*; if the modules are absent
the peer story collapses and this plan needs rethinking before any code is
written, not after.

Cells: `compose.l2tpv3.yml` (veepin client ↔ kernel),
`compose.l2tpv3-server.yml` (kernel client ↔ veepin server),
`compose.l2tpv3-self.yml`, `compose.l2tpv3-cookie.yml` (asymmetric 8-octet
cookies — the only real test of the direction bug), `compose.l2tpv3-shaped.yml`.
`runInteropBench` on the first test of the cell so the throughput table fills.
An `interopRow` in `internal/livingreadme/interop.go` — **a test absent from the
matrix runs in no CI shard and therefore never runs.** And `l2tpv3/` added to
**both** path-filter lists in `.github/workflows/interop.yml`.

The L2 cell must assert something no L3 cell can: **an ARP exchange completes
inside the tunnel**, and a second host on the bridge is reachable. Two
statically-addressed endpoints pinging each other proves nothing about layer 2.

**Dynamic control plane is a second commit**, gated on the static cell being
green: SCCRQ/SCCRP/SCCCN, ICRQ/ICRP/ICCN, Hello, StopCCN and the v3 AVPs, with
`ql2tpd` as the peer. It is what makes `serve` useful against an unmodified
peer, but it is not what proves layer 2 works.

## Cost

~1,400 LOC including tests, ~32 files, for the static pseudowire. +900 for the
dynamic control plane.

---

# 2. IP-TFS / AGGFRAG (RFC 9347) — an IKEv2 option

## Why this is the most interesting candidate

The README's "Scope and limitations" says veepin's shaping *"does not shape
packet counts or timing"*. `doc/traffic-shaping.md` names the attack it does
defend against — Xue et al., USENIX Security 2024 — and observes that it works
against obfs4, Shadowsocks, VMess and Trojan, "which is why 'make the bytes look
random' is not a long-term defence".

**Constant-rate IP-TFS closes exactly that gap.** Fixed-size packets at a fixed
interval regardless of load, aggregating small packets and fragmenting large
ones to fill each one, padding when there is nothing to send. Packet counts and
timing become independent of the traffic inside.

And there is a genuine novelty claim available. strongSwan 6.0.2+ speaks
IP-TFS, but strongSwan and the Linux kernel implement **only the aggregation and
fragmentation half** — the constant-rate transmission that actually delivers
traffic-flow confidentiality is unimplemented in the kernel data path. veepin
does ESP in userspace and is not bound by that. This is the rare case where
veepin can implement the more complete thing *and* still have a peer for the
shared subset.

## The wire format

- **`USE_AGGFRAG` notify, status type 16442**, exchanged in the
  CREATE_CHILD_SA / IKE_AUTH SA negotiation. Both ends must send it.
- **ESP Next Header 144** replaces 4/41. The payload is an AGGFRAG packet.
- **Sub-Type 0** (non-congestion-controlled) header, 4 octets:
  `[Sub-Type=0][Reserved][BlockOffset 16b]`.
- **Sub-Type 1** (congestion-controlled) header, 24 octets: Sub-Type, Reserved
  (6 bits) + P + E, BlockOffset(16), LossEventRate(32), RTT(22), Echo Delay(21),
  Transmit Delay(21), TVal(32), TEcho(32).
- **BlockOffset** is the offset to the start of the *next* data block. Non-zero
  means the leading bytes belong to a block still being reassembled from the
  previous packet.
- **DataBlock type nibble**: `0x0` = pad, `0x4` = IPv4, `0x6` = IPv6. RFC 9347
  chose these to coincide with the IP version field, so the first nibble is
  simultaneously the block type *and* the inner IP version, and the block's
  length comes from the inner IP header. There is no separate length field.
  `TestBlockTypeIsTheInnerIPVersion` should pin this — it looks like an accident
  and is not.

## Shape of the work

All inside `internal/ikev2`. No new registry entry, no count change.

- **`internal/ikev2/aggfrag/`** — the codec. `pack(pkts [][]byte, mtu int)` and
  a stateful `Reassembler`, since a fragmented block spans packets. Tests:
  truncation rejection over every prefix; a block split across three packets
  reassembling byte-identically; a pad block dropped before it reaches the TUN.
- **`internal/ikev2/payload/const.go`** — `UseAggFrag NotifyType = 16442`,
  beside `InitialContact = 16384`.
- **`internal/ikev2/ike/datapath.go:122`** — `espTunnel.Decapsulate` already
  switches on `nextHeader` (case 59 dummy, case 4/41 tunnel-mode trim at :127).
  Add case 144. One AGGFRAG payload can yield zero, one or several inner
  packets, so it needs a second method — `DecapsulateMulti`, used only on
  AGGFRAG tunnels — leaving the single-packet fast path allocation-free and
  untouched.
- **`internal/ikev2/ike/aggfrag_sender.go`** — the constant-rate sender, which
  does not fit `Pump.Run`'s read-encapsulate-send loop. It needs an outbound
  queue and a ticker: every tick, drain up to `mtu` bytes into one AGGFRAG
  payload, pad if short, fragment if the head packet does not fit, send. Keep it
  here rather than growing `dataplane` until a second protocol wants it.
- `esp.SA.Encapsulate` (`internal/ikev2/esp/esp.go:102`) already takes the
  next-header value as a parameter, so passing 144 needs no change to the ESP
  codec.
- Options: `OptIPTFS = "iptfs"` and `OptIPTFSRate = "iptfs-rate"` (bytes/sec;
  0 = aggregation only) in `ikev2/client.go` beside `OptPQ` at :136, mirrored in
  `ikev2/server.go`.

## Interop

strongSwan 6.0.2+ is required, and `tests/interop/strongswan/` is
`debian:bookworm-slim` (5.9). The precedent is already in the tree:
`tests/interop/strongswan-pq/Dockerfile` is `debian:sid-slim`, added because RFC
9370 arrived in strongSwan 6.0, with a comment explaining the deliberate choice
not to move the other cells. Reuse `strongswan-pq` if its snapshot carries
6.0.2+; otherwise add `strongswan-iptfs/` on the same pattern and carry that
comment's reasoning across.

Cells: `compose.iptfs.yml` (veepin client ↔ strongSwan `child.mode=iptfs`),
`compose.iptfs-server.yml`, `compose.iptfs-self.yml`, and
`compose.iptfs-constant.yml` (veepin↔veepin only, since no peer implements it).

**Every cell uses `runInteropRequiringLog`**, requiring a log line naming
AGGFRAG as negotiated. A bare ping passes just as happily if AGGFRAG silently
fell back to plain ESP, which is the exact false green that hid the Pulse bug.

The constant-rate cell needs an assertion no other cell has: **capture the
outbound stream and assert inter-packet timing and size are independent of the
offered load**, idle versus saturated. That is the whole claim of the feature,
and a ping does not test it.

## Docs

`doc/traffic-shaping.md` gains a section on what IP-TFS does that per-flow byte
shaping cannot. The README's "does not shape packet counts or timing" sentence
gets qualified rather than deleted — it stays true for the other protocols.
`doc/security.md` carries the counterpart: constant-rate transmission costs
bandwidth continuously and is off by default.

## Cost

~900 LOC including tests. No count change, so **the docs must be updated by hand
and deliberately** — no mechanical guard will remind you.

---

# 3. Nebula relays — a Nebula option

## The cheapest useful thing on this page

`internal/nebula/lighthouse.go:20` says it in the tree's own words:

> Not implemented: relays (forwarding traffic through a third host when hole
> punching fails), and multi-lighthouse consensus. Both are additive.

Hole punching is already there — `metaHostPunchNotification = 5` at
`lighthouse.go:61`, dispatched at :319, `func (h *Host) punch` at :402. What is
missing is the fallback for when it fails, which in real networks (symmetric
NAT, CGNAT) is often. It is a documented gap, in a protocol already in the tree,
against a peer already pinned and already green.

## Shape of the work

~600–800 LOC across 12–15 files: the relay meta messages, relay-through-host
state on the `Host`, forwarding on the relay's own data path, and the
lighthouse-side advertisement of which hosts will relay.

Three interop cells, **all three using `runInteropRequiringLog`**. Force the
relay by blocking direct UDP between the two peers with an iptables rule, then
require a log line naming the relay host. A ping over a working direct path and
a ping over a working relay are indistinguishable unless you demand the log
line — a relay cell that silently went direct is precisely the false green the
interop matrix exists to catch.

No count change, so again the docs move by hand: the README's Nebula row gains a
note, `internal/nebula/README.md`'s caveats section loses the relay sentence,
and `lighthouse.go:20` is **amended rather than deleted** — multi-lighthouse
consensus stays unimplemented and should keep saying so.

---

# 4. RFC 9329 — TCP encapsulation, an IKEv2 option

## Honest position

The cheapest of the IPsec candidates and the one that teaches least. It is worth
doing because it brings a **new interop peer** into the harness — libreswan,
which no cell currently uses — and because "IPsec through a network that blocks
UDP" is a real deployment need with a standards-track answer.

- **libreswan 4.0+ implements both roles**, stating the intent explicitly: *"It
  was ensured that the MUSTs in the RFC are implemented, so that Libreswan could
  be used as a client or a server."* Config is `enable-tcp = no | yes |
  fallback`.
- **strongSwan does not implement it**, which is why the peer must be libreswan.
- Wire format: TCP port 4500. A stream prefix `"IKETCP"` on connect, then every
  message framed as `[16-bit big-endian length][payload]`. An IKE message is
  prefixed with the 4-octet non-ESP marker inside that framing; an ESP packet is
  not — the same disambiguation `internal/ikev2/ike/transport.go:12` already
  implements for UDP 4500, inside a length-delimited stream instead of a
  datagram.

## Shape of the work

The reason this is cheap is visible in `internal/ikev2/ike/transport.go`: the
`transport` struct (:26) already abstracts "two sockets, IKE here, ESP there",
with `sendIKE` (:35), `sendESP` (:50) and `serve` (:60) as the entire surface
the rest of the package uses. RFC 9329 is a **third implementation of that
surface**.

- Make `transport` an interface, the existing type `udpTransport`, and add
  `tcpTransport`. That is the whole design; everything else follows.
- `tcpTransport` owns a `net.Conn`, a write mutex (a stream has one writer), and
  a read loop doing length-prefix reassembly. A stream reassembler legitimately
  needs one buffer it slides within, but it must not copy per message.
- **Suppress IKE retransmission when the transport is reliable** — a
  `Reliable() bool` on the interface. IKE's timers assume an unreliable
  transport; over TCP a retransmit queues behind the stall it was meant to
  recover from.
- **Keep ESP replay protection.** TCP delivers in order, but a rekey or a
  reconnect can still replay. Do not "optimise" `replayWindow` away.
- `OptTCP = "tcp"` in `ikev2/client.go` and `ikev2/server.go`, spelled
  `no | yes | fallback` to match libreswan so the docs read side by side.

## Interop

New peer image `tests/interop/libreswan/`. Cells: `compose.ikev2-tcp.yml`,
`compose.ikev2-tcp-server.yml`, `compose.ikev2-tcp-self.yml`, and
`compose.ikev2-tcp-fallback.yml` with UDP blocked by an iptables rule in the
peer container. The fallback cell **must** use `runInteropRequiringLog` — a
fallback cell that silently used UDP is the textbook false green.

Land a plain libreswan-over-UDP cell first, proving the peer image works at all,
before asserting anything about TCP. Debugging a new peer and a new transport at
once is how a day disappears.

## Cost

~500 LOC including tests, plus the peer image. No count change.

---

# 5. Rosenpass — a WireGuard option

Excellent work — Classic McEliece plus Kyber, formally verified, with a
published whitepaper — but it is a key-exchange *daemon*, not a tunnel protocol.
It has no data path; it feeds a key into WireGuard's pre-shared-key slot every
two minutes. Registering it as a protocol would put something in the registry
that cannot answer `Dial`.

It is ranked below IP-TFS because veepin already has post-quantum key exchange
in IKEv2 via `crypto/mlkem`, so Rosenpass extends PQ coverage to a second
protocol rather than opening a new capability. The Rust reference implementation
is a real peer for both roles, which is the argument in its favour.

The wire detail is in [rosenpass-plan.md](rosenpass-plan.md).

---

# 6. Juniper NC / Array / F5 — deliberately last

Three rows that would teach nothing structural. F5 is PPP over TLS with a DTLS
data channel, which is what `internal/fortinet` already is. Juniper NC is
Pulse's predecessor, sharing the ESP data path and key-block handling that
`internal/pulse` was shaped by. Array is a fourth variation on "HTTPS login
yields a cookie, then a second connection becomes a framed packet tunnel".

Worth doing only if completing the openconnect column is itself the goal — a
legitimate goal, and "veepin speaks every protocol openconnect does, in both
directions" is a claim worth being able to make. Do them expecting to learn
nothing.

All three get **`—†` in the client column** — none has an open-source server.
F5 is the exception worth noting: `gof5` gives the client direction a real peer,
so F5 alone could have a genuine ✓/✓/✓, which is the opposite of the argument
that rejected it on novelty grounds when GlobalProtect was chosen over it.

The per-protocol detail is in
[openconnect-remainder-plan.md](openconnect-remainder-plan.md).

---

# What was considered and rejected outright

- **Tailscale (ts2021 / DISCO / DERP)** — **fails the "both roles" rule, and not
  on a technicality.** Its server role is a *coordination* server: it hands out
  keys, maps peers and brokers NAT traversal. It has no TUN, no `TUNName`, no
  `Gateway`, no `Network`, and cannot satisfy `client.Result`. `veepin serve
  tailscale` would be either a lie or a second, differently-shaped thing bolted
  into the registry. The data path is plain WireGuard, which the tree already
  has; what Tailscale adds is a control plane. And `tailcfg.CapabilityVersion`
  is an ever-incrementing integer gating server behaviour, so a from-scratch
  implementation signs up to track a vendor's internal API version forever —
  against a control server (headscale) that is itself chasing those changes.
  4,500–6,000 LOC at roughly 10% reuse. **Nebula relays deliver the one
  capability it would bring that the tree lacks, at an eighth of the cost.**
- **MASQUE QUIC DATAGRAM (RFC 9221)** — would fix the documented
  single-reliable-stream weakness in `internal/masque`, but `x/net/quic` does
  not export it. Verified by reading `x/net@v0.56.0/quic/dgram.go` directly: it
  contains only `type datagram struct`, `type ecnBits byte`, `newDatagram()` and
  `(m *datagram) recycle()` — all lowercase, an internal UDP buffer type, not
  RFC 9221. Recorded here so nobody re-searches it; recheck when `x/net` bumps.
- **NordWhisper / Proton Stealth** — proprietary servers, no open-source peer,
  so no interop cell can be built. Same shape of rejection as ZeroTier.
- **tinc** — SPTPS ships only in Debian *experimental*, as a decade-old
  `1.1pre18`. The interop peer would be a source build of a perpetual
  pre-release.
- **ZeroTier** — VL1 alone drags in roots, a planet file and a controller, and
  VL2 adds Ethernet emulation on top. The surface is a product, not a protocol.
- **PPTP** — broken, and nothing to learn from implementing it correctly.
- **Proxy protocols** (Shadowsocks, VLESS, Trojan, Hysteria) — transport
  obfuscation for TCP/UDP flows, not layer-3 VPNs. MASQUE already covers the
  "tunnel IP over a web protocol" idea in a standardised form.

---

# Sequencing

These serialise. Every one of them touches `doc.go`, the README protocol table,
or the spelled-out counts, and **this repo's workflows only trigger on pull
requests whose base is `main`** — a PR stacked on another branch gets no checks
at all. Branch each off the previous, merge in order, and rebase onto `main`
before expecting CI.

1. **`client.Result.Layer2`** — small, fixes SoftEther's existing spurious
   `Validate` failure, unblocks L2TPv3. Independently defensible.
2. **L2TPv3 static pseudowire** — the new row. Verify `modprobe l2tp_eth` on a
   runner *before* writing code.
3. **L2TPv3 dynamic control plane** — gated on 2 being green.
4. **IP-TFS aggregation + fragmentation** — interops against strongSwan.
5. **IP-TFS constant-rate** — a separate commit, so the interop-verified half is
   not held hostage to the half no peer can check.
6. **RFC 9329** — plus a plain libreswan-over-UDP cell first, proving the new
   peer image before asserting anything about TCP.
7. **Nebula relays** — independent of all of the above, and the smallest useful
   thing on this page if a short slot opens up.

# Verification

Per commit, the full gate from `AGENTS.md`:

```sh
gofmt -l .                                   # must print nothing
go build ./... && go vet ./...
go test -race ./...
go test ./...                                # again: AllocsPerRun guards skip under -race
golangci-lint run
go mod tidy && git diff --exit-code go.mod go.sum
cd nm && go build ./... && go test -race ./... && cd ..
```

Interop, per cell, tearing down between runs because `docker compose` reuses a
running container when only a bind-mounted file changed:

```sh
cd tests/interop
docker compose -f compose.<cell>.yml down -v --remove-orphans
go test -tags interop -run 'TestInterop<Name>' -v -timeout 15m ./...
```

## The assertions that are not optional

Each of these exists because a passing ping would otherwise prove nothing:

| Cell | What it must assert beyond a ping |
|---|---|
| L2TPv3 | An **ARP exchange completes inside the tunnel**, and a second host on the bridge is reachable |
| L2TPv3 cookies | **Asymmetric 8-octet cookies**, so a both-ends-backwards direction bug cannot pass |
| IP-TFS (all) | `runInteropRequiringLog` naming AGGFRAG as negotiated — silent fallback to plain ESP pings perfectly |
| IP-TFS constant-rate | Packet timing and size **independent of offered load**, idle versus saturated |
| RFC 9329 fallback | UDP blocked by iptables, with a log line proving TCP carried the session |
| Nebula relays | Direct UDP blocked, with a log line **naming the relay host** |
