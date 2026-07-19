# Consolidation plan: what to fix before the next protocol

Written after shipping Nebula (protocol #8) and TOY (the example protocol), and
before deciding on MASQUE or anything else. The question this answers is not
"what could be tidier" but **"what is currently wrong, or likely to make the next
thing wrong."**

Everything below is grounded in the tree as it stands; the survey commands are
included so the findings can be re-checked rather than taken on trust.

## Summary

| # | Item | Value | Risk | Verdict |
|---|------|-------|------|---------|
| 1 | `client.Result` contract is underspecified | High | Very low | **Do first** |
| 2 | No PMTU / ICMP handling anywhere | High | Low (additive) | **Do** |
| 3 | Servers reply from the wrong source address when multi-homed | High | Medium | **Do, with care** |
| 4 | MTU constants scattered, none derived | Medium | Low | Do |
| 5 | `doc.go` describes two of nine protocols | Low | None | Do (trivial) |
| 6 | Seven replay-window implementations | Low | **High** | **Mostly don't** |
| 7 | Duplicated logger/conn plumbing | Very low → **High** | Low | Done — and it was not cosmetic |

The ordering is deliberate: items 1–3 are defects, 4–5 are hygiene, and 6–7 are
the ones that *look* most like obvious wins and are the least worth doing.

**Item 7 disproved that last claim.** It was ranked lowest in the table — a
duplicated logger and an adapter that "would be subsumed". Pulling on the
adapter showed *why* it existed: nebula's socket interface used method names
`dataplane.PacketConn` does not have, so nebula could not adopt the wrapper and
was the one UDP server in the tree still replying from a kernel-chosen source
address. The cosmetic framing was wrong. A private adapter is worth asking about
precisely because it is where a shared fix silently fails to reach.

Part 2 covers what a separate pass found when asking a different question — not
"what is untidy" but **"what is structurally absent across the whole tree"**. Two
of those findings outrank everything in the table above.

| # | Item | Value | Risk | Verdict |
|---|------|-------|------|---------|
| 8 | No fuzzing of any protocol parser | **Very high** | Low | **Do before anything else** |
| 9 | Every server accepts unbounded half-open state | **Very high** | Medium | **Do** |
| 10 | ~~Nebula has no rekeying~~ — claim was wrong; real gap is idle expiry | Medium | Low | Done, premise corrected |
| 11 | Credential comparison timing is inconsistent | Medium | Very low | Do |
| 12 | Keys are never zeroed | Low | — | Done — documented in the README |
| 13 | Single-threaded data path | Low | — | Not a flaw |

## 1. The `client.Result` contract is underspecified

`client.Result.Gateway` is documented in full as:

```go
// Gateway is the server's outer (public) IP.
Gateway net.IP
```

That single line is load-bearing: `dataplane.ClientRouter` pins a host route to
it through the physical interface, so encapsulated packets are not routed back
into the tunnel. Get it wrong and the failure is silent and total — the handshake
succeeds and every packet leaves by the wrong door.

**I got this wrong twice in one session**, in two different ways:

- **Nebula** — a mesh has no single outer address to pin, and filling in the
  host's own overlay address would have installed a route sending that address
  out the physical interface. Correct answer: leave it nil.
- **TOY** — I filled in the *inner* gateway from the protocol's own WELCOME
  message. Handshake succeeded; the ping never crossed. Correct answer: the
  server's outer address.

Two bugs from one under-documented field, found only by running the interop
cells, is a contract problem rather than two coincidences.

**Proposed:**

- Expand the doc comment for every `Result` field to say what the caller *does*
  with it, not just what it is. `Gateway` in particular should state that it is
  the address a host route is pinned to, that it is the outer address, and that
  nil is legitimate and means "no host route" (which is what a mesh wants).
- Add a `Result.Validate()` returning a descriptive error for the combinations
  that cannot be right — notably a `Gateway` inside the same subnet as
  `AssignedIP`/`Netmask`, which is exactly the TOY bug and is mechanically
  detectable.
- Call it from `cmd/veepin` after `Dial` and log a warning rather than failing:
  a protocol may have a reason, and this is a guard rail, not a gate.

**Risk:** near zero. Documentation plus one advisory check.

## 2. There is no PMTU or ICMP handling anywhere

```sh
grep -rn "icmp\|ICMP\|DontFragment\|IP_MTU" --include=*.go internal/ dataplane/
# (no matches)
```

MTU black-holing is the most common real-world VPN failure: the tunnel comes up,
small packets work, and anything large disappears. veepin can currently neither
detect this nor signal it to the host.

Two halves, both worth having:

- **Inbound:** when the TUN hands us a packet too large for the tunnel with DF
  set, reply with ICMP "fragmentation needed" carrying the correct next-hop MTU,
  so the local stack learns. Without this, a host behind a veepin tunnel keeps
  retransmitting packets that can never fit.
- **Outbound:** set DF on the outer datagram and listen for ICMP
  "fragmentation needed" about the path, so the effective MTU can be lowered
  rather than guessed.

**Does this need `x/net`?** No. `x/net/icmp` would do it, but the two message
types that matter are a few dozen lines to encode and parse by hand, which is how
this tree does everything else — and `x/sys/unix` (already an indirect dependency)
provides the socket options. Adding `x/net` for this would be the tail wagging
the dog.

**Risk:** low. Purely additive; nothing currently depends on the absence.

## 3. Servers reply from the wrong source address when multi-homed

Every UDP server defaults to binding the wildcard:

```sh
grep -rn '"0.0.0.0"' --include=*.go */*.go   # ikev2, l2tp, openvpn, sstp, toy, ...
```

A socket bound to `0.0.0.0` picks its source address by route lookup when
replying, which on a multi-homed host is often not the address the client sent
to. The client sees a reply from an unexpected address and drops it. This affects
**every UDP protocol in the tree** and is invisible on a single-homed test host,
which is exactly why the interop matrix has never caught it.

**Proposed:** enable `IP_PKTINFO` / `IPV6_PKTINFO`, read the destination address
from the out-of-band control message on receive, and set it as the source on the
corresponding reply. Wrap it once in `dataplane` as a small `PacketConn` so each
protocol adopts it by changing a constructor rather than its read loop.

Also `x/sys/unix`, not `x/net`.

**Risk:** medium, and the highest of anything here. It changes socket setup for
every UDP protocol, and control-message handling differs across platforms. Do it
behind the `dataplane` wrapper so a single implementation is exercised by all 34
interop cells at once, and land it on its own so a regression is attributable.

## 4. MTU constants are scattered and none are derived

```
openvpn      1500      nebula     1300      toy       1400
wireguard    1420      dtls       1200      anyconnect 1400
```

Six values, each a literal, none showing its arithmetic. Some are protocol
defaults (WireGuard's 1420 is from the paper); others are guesses that happen to
work. Once item 2 exists, the effective MTU should be *derived* — path MTU minus
that protocol's outer header, UDP header and tag — with the literal kept only as
a floor.

**Risk:** low, but it should follow item 2 rather than precede it, since PMTU is
what makes derivation meaningful.

## 5. `doc.go` describes two of nine protocols

The root package doc still says IKEv2 "is the first protocol" and WireGuard "is
the second", and lists neither OpenVPN, SSTP, SSH, L2TP, AnyConnect, Nebula nor
TOY. It has been stale for six protocols and I deliberately left it alone during
the Nebula and TOY work rather than widen those PRs.

**Risk:** none. It is a doc comment.

## 6. Seven replay-window implementations — mostly leave them alone

```sh
grep -rn "type replayWindow\|type replayFilter" --include=*.go internal/
# internal/nebula/replay.go        internal/dtls/record.go
# internal/ikev2/esp/esp.go        internal/openvpn/tlswrap/tlswrap.go
# internal/openvpn/data/data.go    internal/wireguard/transport/replay.go
# (plus internal/toy/session.go, inline on Session)
```

Seven implementations of one sliding-window algorithm is the most obviously
duplicated thing in the tree, and it is the item I am most confident should
*not* be consolidated wholesale.

They are not the same algorithm wearing different names. ESP's window is
RFC 4303's with its mandated size and sequence handling; DTLS's is per-epoch;
WireGuard's follows the protocol paper; the two OpenVPN variants differ from each
other. Each is currently correct and verified by interop cells against a real
third-party peer. Replacing six working, independently-verified implementations
with one shared abstraction trades a real risk of subtle breakage for an
aesthetic gain, and the parameterisation needed to cover all of them would end up
more complex than any one of them.

**What is worth doing:** `internal/nebula/replay.go` and the inline window in
`internal/toy/session.go` are genuinely identical — I wrote the same code twice
in one session, including the same fiddly "clear the slots the window slides
past" step that is easy to get subtly wrong. Extracting *those two* into a shared
`internal/replay` package, with the tests from both, is a real win and touches
nothing that interops with a third party.

**Verdict:** extract for the two that are duplicates; leave the five
protocol-specific ones exactly where they are, with a comment in the shared
package saying why they were not migrated, so this is not "cleaned up" later by
someone who only counts the duplication.

## 7. Duplicated logger and conn plumbing

`internal/toy` has `type discard struct{}`; `internal/nebula` has
`type nopLogger struct{}`; `nebula/nebula.go` has a `udpConn` adapter that
item 3's `dataplane` wrapper would subsume.

Not worth a change of its own. If items 2–4 produce a natural home for a small
shared helper, fold these in then; otherwise leave them.

---

# Part 2: architectural gaps

Part 1 asks what is untidy. This part asks what is *absent* — capabilities the
tree never acquired, rather than places where it drifted. The first two are, in
my judgement, more important than anything in Part 1.

## 8. No protocol parser has ever been fuzzed

```sh
grep -rln "func Fuzz" --include=*_test.go .   # (no matches)
```

Nine protocols, each with a wire codec that parses **attacker-controlled bytes
before anything is authenticated**. Not one fuzz target, in a language with
native fuzzing built into the toolchain.

Every parser in the tree is hand-bounds-checked and tested with hand-written
truncation cases. I wrote two of them this session and did exactly that — TOY's
tests feed every prefix of every message to every parser, and Nebula's reject
malformed protobuf. But hand-written cases only cover the malformations I thought
of, and the interesting ones are definitionally the ones nobody thought of.

This is the highest-value single addition available to this codebase. It is also
cheap: `go test -fuzz` needs a corpus and about fifteen lines per target, and the
existing table-driven tests already provide seed corpora.

Targets, in order of exposure — these all parse pre-authentication input:

- `internal/nebula`: certificate protobuf, handshake payload, lighthouse meta
- `internal/toy`: header and all message bodies
- `internal/dtls`: record layer, handshake reassembly, ClientHello peeking
- `internal/ikev2/payload` and `internal/ikev1`: the payload chains
- `internal/openvpn/wire`, `internal/wireguard/wire`, `internal/sstp/wire`
- `internal/ppp`: LCP/IPCP option parsing

The DTLS reassembler and the IKE payload chains are where I would expect
something to fall out first: both do offset arithmetic on attacker-supplied
lengths, which is the classic shape.

**Risk:** low. Fuzz targets are additive; a crash found is a bug that was already
there. CI runs a short fuzz budget per target; long campaigns run out of band.

## 9. Every server accepts unbounded half-open state

```sh
grep -rn "COOKIE\|cookie" --include=*.go internal/ikev2/      # (no matches)
grep -rn "maxHalfOpen\|maxPending\|rate.*limit" internal/     # (no matches)
```

No server in the tree limits how much state an unauthenticated peer can cause it
to allocate. Concretely, a single host sending handshake initiations at line rate
will make every veepin server allocate — session IDs, address-pool entries,
Diffie-Hellman state, handshake buffers — until something runs out.

Two specifics:

- **IKEv2 does not implement the cookie mechanism** (RFC 7296 §2.6), which exists
  *precisely* for this and is the spec's own answer. A responder under load is
  supposed to demand a returned cookie before doing any expensive work; veepin
  performs the DH exchange for anyone who asks.
- **TOY's expiry bounds duration, not rate.** I added pending-handshake expiry
  because I thought of it, and it is genuinely necessary — but a 60-second
  timeout against a peer sending thousands of handshakes per second still
  accumulates state, it just accumulates a bounded-in-time amount of it. The same
  is true anywhere else expiry was added.

This is the gap I would most expect a security reviewer to lead with, because
every server is affected and the mitigation is well-known per protocol.

**Proposed:** a shared admission-control helper in `dataplane` — a cap on
concurrent half-open handshakes and a per-source token bucket — adopted by each
server, plus IKEv2's cookie mechanism specifically, since it is the standardised
answer and interoperates with real peers under load.

**Risk:** medium. Admission control that is too aggressive breaks legitimate
clients on a busy server, so the defaults need to be generous and the rejection
path needs to be visible in logs rather than silent.

## 10. Rekeying is inconsistent — but the Nebula claim here was wrong

Present: IKEv2 (CHILD_SA rekey), WireGuard (`rekeyAfterTime`, verified by a
dedicated interop cell), OpenVPN (key renegotiation).

Absent: **Nebula**, AnyConnect's DTLS channel, L2TP, SSTP, SSH, TOY.

For most of that list it is defensible — SSH and SSTP inherit their transport's
rekeying, and TOY is an example.

**The claim originally made here about Nebula was wrong, and checking it before
implementing is what caught it.** This section asserted that "real nebula
rotates" and that veepin's lack of rekeying was a divergence from the protocol
as specified. It is not. Nebula v1.9.7's `tryRehandshake` re-keys in exactly one
circumstance:

```go
if bytes.Equal(hostinfo.ConnectionState.myCert.Signature, certState.Certificate.Signature) {
    return
}
// "local certificate is not current" -> re-handshake
```

There is no time-based or counter-based rotation, and the message counter is
64-bit with an explicit TODO where a duplicate-counter check would go. A
continuously busy nebula tunnel keeps one key.

What actually bounds a tunnel's key lifetime in nebula is a **ten-minute
inactivity timeout**: an idle tunnel is dropped and the next packet builds a
fresh one. veepin had no such timeout, so it held every tunnel it ever
established, forever — which is both an unbounded key lifetime *and* a leak in
the host map.

**Done:** an inactivity timeout matching nebula's, so key lifetime is bounded the
same way and the host map stops growing. Implementing periodic rotation instead
would have made veepin *diverge* from the reference rather than converge with it,
which is the outcome the original wording would have produced.

## 11. Credential comparison timing is inconsistent

The same secret-comparison, hardened in one protocol and not in another:

```go
// internal/ppp/chap.go:108 — the PPP server verifying MS-CHAPv2
return want == ntResponse                                          // variable-time

// internal/ikev2/eap/server.go:138 — the same check, same secret
subtle.ConstantTimeCompare(expected[:], fields.NTResponse[:]) != 1 // constant-time
```

The PPP path is what the **L2TP and SSTP servers** authenticate with. Whether 24
bytes of `memequal` short-circuiting is remotely exploitable over a network is
genuinely arguable — but it is not an argument worth having when the fix is one
line and the codebase already made the opposite choice elsewhere.

The architectural point is not the line: it is that **there is no shared helper
for "compare a secret"**, so every site decides independently, and one of them
decided differently. A `cryptoutil.SecretEqual` that every credential path calls
makes the next site correct by default.

## 12. Keys are never zeroed — document, don't chase

No key material is wiped after use. In a language with a moving, copying garbage
collector this is substantially harder to do meaningfully than in C, and a
partial job invites more confidence than it earns.

**Proposed:** state the position explicitly in the README's security section
rather than quietly leaving it. "Key material is not zeroed; Go's memory model
makes this unreliable, and veepin does not claim protection against an attacker
who can read process memory" is an honest boundary. Half-implementing it would be
worse than either.

## 13. Single-threaded data path — noted, not a flaw

`dataplane.Pump` reads the TUN from one goroutine, so per-tunnel throughput is
bounded by a single core. That is a scaling ceiling rather than a defect, and
changing it means reordering risk and lock contention for a benefit nothing here
is currently asking for. Worth knowing; not worth doing now.

## Explicitly out of scope

- **MASQUE, and the `x/net` question generally.** Nothing above needs `x/net`;
  the two items that looked like they might (2 and 3) are better served by
  `x/sys/unix`, already present as an indirect dependency. The `x/net` decision
  should be made on MASQUE's own merits, after this work, and if taken should be
  a separate module in the shape of `nm/` — build tags do not isolate a
  dependency, only compilation.
- **Nebula's ACL engine, relays, and v2 certificates.** Real gaps, but additive
  feature work rather than consolidation.
- **Rewriting any protocol's crypto or state machine.** Everything in the tree is
  interop-verified against a third-party peer; none of it is asking to be
  rearchitected.

## Sequencing

Each step lands on its own so a regression is attributable, and each is green
before the next starts. The order is by value and by what de-risks what — not by
the order the items were found.

1. **Item 8 — fuzz every parser.** First, because it is the cheapest way to find
   out whether anything below is standing on a broken foundation, and because
   anything it turns up should be fixed before the code is touched for other
   reasons. Additive, so nothing can regress.
2. **Item 11 + item 1 + item 5** — the constant-time fix, the `Result` contract
   documentation and check, and `doc.go`. All small, all near-zero risk; grouped
   so one PR clears the cheap correctness-and-clarity work.
3. **Item 9 — admission control**, plus IKEv2's cookie mechanism. The largest
   genuinely-missing capability, and it wants to land alone and generously
   configured.
4. **Item 3 — source address selection**, behind a `dataplane` wrapper so one
   implementation is exercised by all 34 interop cells at once. Highest
   regression risk in Part 1.
5. **Item 10 — Nebula rekeying**, with an interop cell watching a rotation.
6. **Item 2 — PMTU and ICMP**, then **item 4** to derive MTUs from it.
7. **Item 6 (partial)** — extract the one genuine duplicate pair. Optional.
8. **Item 12** — write the key-zeroization boundary into the README.

If only two things happen, they should be **8 and 9**: fuzzing, because nine
unfuzzed parsers is the gap most likely to be hiding something concrete, and
admission control, because it is the one a reviewer would lead with and it
affects every server in the tree.

Everything in Part 1 could be dropped without much loss. Item 10 is the only one
that is a divergence from a protocol as specified rather than a general
weakness — so it is the one with a correctness argument rather than a
defence-in-depth argument.
