# Claims and reach: what is asserted but unproven, and what is documented as missing

Written after [`operability-plan.md`](operability-plan.md) executed in full — all
fifteen items plus the one it did not think to have — and after the interop
matrix went green in every cell that can be green.

[`consolidation-plan.md`](consolidation-plan.md) asked what was *wrong*.
[`operability-plan.md`](operability-plan.md) asked what stopped a person
*running* it. Both questions are answered. This one asks the question that is
left:

> **What does veepin claim that nothing checks, and what does it already admit in
> writing that it does not reach?**

The two halves are not the same kind of work. The first half is defects hiding
behind passing tests — the failure mode this tree keeps rediscovering in a new
costume, most recently as thirteen protocols that never said a password was
wrong. The second half is honest gaps, already named in a README or a caveats
section, that nobody has closed.

Everything below is grounded in the tree at `b51ef43`, with the survey command
included so each finding can be re-checked rather than taken on trust.

Part 0 is a prerequisite that arrived after the rest was written: Go 1.27 shipped
`crypto/mldsa`, the toolchain moved, and the floor has to move with it. Parts 1
through 4 are the plan proper. [The longer horizon](#the-longer-horizon) at the
end is the menu behind it — twelve larger items that are not scheduled, so that
whatever comes after this plan is chosen from something written down.

## What has landed, and what has not

The first branch off this plan (`feat/claims-and-reach`) executed **Part 0,
items 1, 2, 6 and 10, and H1, H2 and H9** — nine of the twenty-six rows below.
Item 8 was resolved as a *don't*, which is an outcome rather than an omission.

What remains, and why each stopped where it did:

- **Item 3 (ql2tpd)** and **item 4 (the fixture survey)** are investigations
  rather than changes, and item 4 should run before Part 2 adds cells that could
  inherit the same blind spot.
- **Item 5 (SSH shaping)** came back with a harder answer than the plan
  predicted, and the prediction is in *Where this plan is probably wrong* below.
  The vehicle the docs named does not exist, and the fallback is not plumbing
  either: `internal/sshtun` recovers packet boundaries from the IP length on a
  byte stream, so filler after a packet is read as the next packet's
  address-family header. A stock OpenSSH peer tolerates it; veepin's own reader
  does not. Closing that is a framing decision, and the correction to
  `doc/traffic-shaping.md` landed without it.
- **Item 7 (MASQUE)** is unblocked and unstarted.
- **Item 9 (RFC 9329)**, **item 11 (macOS pf)** and **item 12 (`slog`)** are
  unstarted; 11 is still gated on somebody running the macOS client on hardware.
- **The horizon list** past H1, H2 and H9 is unstarted by design. H3 is the one
  whose gate moved: Go 1.27 supplies `crypto/mldsa` and the floor is now raised,
  so H3a is reachable in a way it was not when this page was written.

## Summary

### Part 0 — the toolchain floor

| # | Item | Value | Risk | Verdict | Status |
|---|------|-------|------|---------|--------|
| 0a | Raise the `go.mod` floor to 1.27 across both modules, CI and the image | Prerequisite | Low | **Do first — everything else assumes it** | ✅ landed |
| 0b | `cryptocustomrand` silently disarms nebula's ephemeral-key test seam | **High** | Low | **Do with 0a — it is what 0a breaks** | ✅ landed |

### Part 1 — claims the tests do not check

| # | Item | Value | Risk | Verdict | Status |
|---|------|-------|------|---------|--------|
| 1 | IKEv2 never fragments its own output, and the reason it gives is false | **High** | Low | **Do first** | ✅ landed |
| 2 | The cert cell mints the smallest certificate that exists | **High** | None | **Do — it is item 1's guard** | ✅ landed |
| 3 | The L2TPv3 control connection is unit-tested only, and the tree says so | Medium | **Medium** | Do, timeboxed | ✅ landed — upstream bug, located |
| 4 | Which other fixtures make the easy case the only case? | Medium | Low | Do (survey) | ✅ landed |

### Part 2 — shaping reaches thirteen of sixteen (now all sixteen)

| # | Item | Value | Risk | Verdict | Status |
|---|------|-------|------|---------|--------|
| 5 | SSH is unshaped — and the vehicle the docs name does not exist | Medium | Low | **Do** | ✅ landed |
| 6 | Nebula is unshaped | Medium | Low | Do | ✅ landed |
| 7 | MASQUE is unshaped | Medium | Low | Do | ✅ landed |

### Part 3 — the next capability

| # | Item | Value | Risk | Verdict | Status |
|---|------|-------|------|---------|--------|
| 8 | Rosenpass — PQ keys for WireGuard | Medium | **Blocked** | **Don't — its own plan says so, and the escape hatch already landed** | ☐ |
| 9 | RFC 9329 — TCP encapsulation of IKE and IPsec | Medium | **High** | **Do — it is the next capability by default** | ☐ |

### Part 4 — operability hardening

| # | Item | Value | Risk | Verdict | Status |
|---|------|-------|------|---------|--------|
| 10 | An abandoned listener leaks its pump goroutine and its TUN fd | **High** | Low | **Do** | ✅ landed (visibility half) |
| 11 | No kill switch on macOS | Medium | **Medium** | Decided: **no** — see below | ✅ resolved |
| 12 | `-log-level` gates the stream, not the call site | Low | Medium | Do last | ☐ |

**If only three things happen: 1, 2 and 10.** One and two are a defect that
every passing test agrees is fine; ten is a resource leak that compounds with
each restart of a wedged listener. The rest is reach, and reach can wait for
correctness.

---

# Part 0: the toolchain floor

Written last and sequenced first. Go 1.27 (August 2026) shipped `crypto/mldsa`,
which is what makes [H3](#h3-post-quantum-authentication--unblocked-by-go-127-three-weeks-after-this-page-said-it-wasnt)
possible at all, and the local toolchain has already moved. The `go.mod` floor
has not. Everything below was verified by making the change, running the gate,
and reverting.

## 0a. Raise the floor to 1.27

`crypto/mldsa` builds and runs under a `go 1.25.0` directive — only `go vet`
objects, reporting that `mldsa.GenerateKey` "requires go1.27 or later (file is
go1.25)". `go vet ./...` is in the gate, so this is a hard prerequisite rather
than a tidy-up.

### What to change

1. **`go.mod`** — `go 1.25.0` → `go 1.27.0`.
2. **`nm/go.mod`** — the same. It is a separate module and fails outright
   otherwise, with `go: updates to go.mod needed` on both `build` and `vet`.
3. **`go mod tidy`** — it reflows the two `require` blocks into one, and
   `git diff --exit-code go.mod go.sum` is in the gate.
4. **Thirteen workflow pins** — twelve `go-version: "1.25"` across
   `benchmark`, `ci`, `e2e`, `interop`, `nm` and `release`, plus the
   `go: ["1.25", "1.x"]` matrix at `ci.yml:32`, which becomes
   `["1.27", "1.x"]`. The two legs collapse onto one release until 1.28 ships;
   that is the cost, and the matrix regains its point on its own.
5. **`Dockerfile:12`** — `FROM golang:1.25-bookworm` → `1.27`. Without it the
   build still succeeds, `GOTOOLCHAIN=auto` fetching 1.27 mid-build, at the cost
   of a network round trip in every interop image build.
6. **`README.md:261`** — "Requires Go 1.21+ (developed against Go 1.26)."

### What must not change

- **`ci.yml:129`'s `go-version: "1.26.6"`.** That is the govulncheck pin, and
  the twelve-line comment above it explains why it is deliberately pinned and
  bumped on its own schedule. Sweeping it up with the others silently reverts a
  decision somebody already wrote down.
- **The four peer Dockerfiles** — `amneziawg` and `wireguard` at 1.24,
  `nebula` and `ql2tpd` at 1.25. They build the *other* implementation. Their Go
  version is part of what veepin is being tested against.

## 0b. `cryptocustomrand` disarms a test seam, and the one-line fix is wrong

At the 1.27 floor the whole tree passes, with and without `-race`, except one
test:

```
--- FAIL: TestNoiseIXKnownAnswer   internal/nebula/noise_test.go:86
     got: 25d2cf03…7b4e909bbe7ffe44…
    want: 7b0d47d9…7b4e909bbe7ffe44…
             ^ the first 32 octets — the ephemeral public key — and nothing else
```

Not an ML-DSA problem and not a nebula bug. **Go 1.26 added the
`cryptocustomrand` GODEBUG, which defaults to `0` for a `go.mod` at 1.26 or later
and makes most `crypto/…` APIs ignore the `io.Reader` passed to them.**
`internal/nebula/noise.go:240` is `ecdh.X25519().GenerateKey(rand)`, so the
ephemeral key stops coming from the test's `fixedReader`. Proved, not inferred:

```sh
GODEBUG=cryptocustomrand=1 go test ./internal/nebula/ -run TestNoiseIXKnownAnswer
# ok    — at the same 1.27 floor
```

Scope is one call site. Every other crypto call in the tree passes
`crypto/rand.Reader`, and ignoring a reader that was already the system source
changes nothing:

```sh
grep -rn 'GenerateKey(\|SignASN1(\|SignPKCS1v15(\|CreateCertificate(\|\.Sign(' --include=*.go .
# every hit is rand.Reader, except internal/nebula/noise.go:240
```

Production is unaffected either way — `handshakeConfig.randReader()` returns the
real source. What broke is the seam.

### What to build

`go.mod` accepts a `godebug cryptocustomrand=1` line that makes the failure
disappear in one edit. **Do not.** It opts the whole program out of a
security-motivated standard-library change in order to keep a test green, and it
does so invisibly from the test that benefits — the same trade
`doc/security.md` refuses when it declines to fake key zeroing.

The parameter has become a lie. `WriteMessage1(payload, rand io.Reader)`
advertises control over ephemeral key generation that the runtime no longer
grants, and the comment at `noise.go:237` describes something that does not
happen. **Move the seam from the entropy to the key**: `generateEphemeral` takes
an optional `*ecdh.PrivateKey`, nil in production. The test file already builds
fixed X25519 keys that way for the statics (`mustX25519`), so the vectors are
unchanged and the fixture gets shorter.

### The assertions that are not optional

- **The known-answer vectors do not change.** If a vector has to be edited to
  make this pass, the fix is wrong — the seam moved, the cryptography did not.
- **`grep -rn 'godebug' go.mod nm/go.mod` stays empty**, and a comment on the
  new parameter says why the reader is gone rather than leaving the next reader
  to rediscover `cryptocustomrand`.
- **Production still uses `crypto/rand`.** A seam that lets a caller inject a
  key is a seam that lets a caller inject a *bad* key; the nil-means-generate
  path is what keeps that from being a footgun, and it needs a test.

### Cost

Half a day for both, most of it in the thirteen workflow pins.

---

# Part 1: claims the tests do not check

## 1. IKEv2 never fragments its own output, and the reason it gives is false

```sh
sed -n '19,22p' internal/ikev2/ike/fragment.go
# veepin negotiates support (so a peer configured to always fragment
# interoperates) and reassembles inbound fragments, but never fragments its own
# output: its messages — PSK/EAP auth, no certificates — are always small
# enough to send whole, and advertising support while sending unfragmented

grep -n 'func ' internal/ikev2/ike/fragment.go
# 44:  findFragSupported      <- inbound
# 57:  addFragSupported       <- negotiation
# 72:  decryptSKF             <- inbound
# 126: (*fragReassembler).add <- inbound
# 177: (*fragReassembler).reset
```

There is no encoder. Every function in the file is negotiation or reassembly,
which matches the comment exactly — and the comment's justification names a
premise that stopped being true when certificate authentication landed.

**Both roles emit a certificate chain, and neither checks a size.**

```sh
grep -rn 'TypeCERT,' internal/ikev2/ike/*.go | grep -v _test
# internal/ikev2/ike/client.go:576     <- initiator, inside `for _, der := range c.certCred.chain`
# internal/ikev2/ike/ike_auth.go:152   <- responder

grep -rn 'MTU\|1500\|1280\|len(msg)' internal/ikev2/ike/client.go internal/ikev2/ike/ike_auth.go
# (nothing)
```

`buildCertAuthInner` (`internal/ikev2/ike/client.go:568`) assembles IDi, **one
CERT payload per chain element, leaf first**, a CERTREQ, the signed AUTH, then
CP, SA, TSi, TSr and the MOBIKE notify. With ECDSA P-256 that lands near a
kilobyte and fits. With RSA-2048 — which is what the overwhelming majority of
enterprise IKEv2 PKI actually is — a leaf at roughly 1.1 KB, one intermediate at
roughly the same, and a 256-octet signature put IKE_AUTH between 2.5 and 3.5 KB
before the ESP proposal is counted.

veepin sends that as one UDP datagram. The kernel IP-fragments it. A
fragmentation-hostile middlebox drops the fragments, and **RFC 7383 exists for
precisely this case** — which veepin advertises support for and then does not
use.

RFC 7383 §2.5.1 does permit advertising support while sending unfragmented
messages, so this is not a conformance violation. It is a capability that is
negotiated, needed, and not exercised, behind a comment asserting it is never
needed.

### What to build

- **`fragment.go` gains an encoder.** `encryptSKF` is the mirror of the existing
  `decryptSKF` (`:72`): each fragment is an independent unit with its own IV,
  its own RFC 7296 padding and its own ICV, so the split is on the *plaintext*
  inner payloads and each chunk is encrypted separately. The first fragment
  carries the type of the first inner payload; the rest carry zero. The existing
  reassembler is the specification — write the encoder so that
  `reassemble(fragment(x)) == x` is a property test over generated messages.
- **A fragmentation threshold derived, not a literal.** `dataplane/mtu.go`
  already exists for this reason (`consolidation-plan.md` item 4 — "MTU
  constants scattered, none derived"). The IKE payload budget is the path MTU
  less the IP and UDP headers, less the non-ESP marker on 4500, and it differs
  by outer family. Do not write 1400 in two files.
- **Fragment only when the peer negotiated it.** `findFragSupported` already
  records the peer's notify. If the peer did not advertise support and the
  message is oversized, send it whole — that is the only behaviour available,
  and a log line saying so is what turns a silent path-MTU black hole into a
  diagnosable one.
- **Both roles.** The responder's IKE_AUTH (`ike_auth.go:152`) carries the same
  chain and has the same problem. A fix on the initiator alone leaves a veepin
  server unable to answer a strongSwan client with an RSA CA.
- `maxFragments = 64` and `maxReassembledBytes = 64 KiB` (`fragment.go:31`)
  bound the receiver. The sender needs its own refusal above that bound rather
  than emitting a 65th fragment the peer will reject.

### The assertions that are not optional

- **A round-trip property test**: a message of every size from just-fits to
  many-fragments, fragmented and reassembled, byte-identical.
- **A test that a peer which did not negotiate fragmentation gets one whole
  message**, oversized or not. Fragmenting at a peer that never asked is worse
  than the bug being fixed.
- **The interop assertion belongs to item 2**, because a cell that mints a small
  certificate proves nothing about this either way.

### Cost

~350 LOC including tests. No count change, no new registry row, no docs guard
that will notice — so the README's "RFC 7383 … it negotiates and reassembles
inbound SKF fragments but never fragments its own output" sentence and the
comment at `fragment.go:19` **must both be edited by hand**.

---

## 2. The cert cell mints the smallest certificate that exists

```sh
grep -n 'pki --gen' tests/interop/strongswan/server-entrypoint-cert.sh
# 14:    pki --gen --type ecdsa --size 256 ...   <- CA
# 18:    pki --gen --type ecdsa --size 256 ...   <- server
# 24:    pki --gen --type ecdsa --size 256 ...   <- client
```

ECDSA P-256 throughout. The cert cell is green, has always been green, and has
never once put an IKE_AUTH near the path MTU. It is the fixture, not the code,
that makes item 1 invisible.

This is the same shape as the two failures this tree has already written down:
the Pulse cell that passed on a silent fallback, and the rejection tests that
asserted a login failed without asserting *which* failure. A cell whose fixture
only exercises the easy case is a test of the easy case, however real its peer
is.

### What to build

A second cert cell — `compose.ikev2-cert-rsa.yml` — with an RSA-2048 CA and an
RSA-2048 leaf, so the chain veepin sends and the chain strongSwan sends are both
past the MTU in both directions.

Keep the ECDSA cell. It is not redundant: it is the case where fragmentation
must *not* happen, and an implementation that fragments unconditionally would
still pass a cell that only ever sends large messages.

### The assertions that are not optional

- **`runInteropRequiringLog`, naming the fragment count.** A cell that only pings
  passes identically whether veepin fragmented at the IKE layer or let the kernel
  fragment at the IP layer, because Docker's bridge happily reassembles IP
  fragments. The whole point is which layer did the splitting, and only a log
  line can tell you.
- **Block IP fragments in the peer container** with an `ip6tables`/`iptables`
  rule on the fragment bit, so the kernel path is not merely unused but
  unavailable. Without that, the cell proves veepin *can* fragment, not that it
  *must*.

That second assertion is the one worth arguing about, so it is stated
explicitly: a cell where the fallback still works is a cell that cannot fail for
the reason it was written.

### Cost

~120 lines of compose and entrypoint, no Go beyond the test functions and the
`interopRow` entry.

---

## 3. The L2TPv3 control connection is unit-tested only, and the tree says so

```sh
sed -n '64,87p' tests/interop/l2tpv3_test.go
# TestPendingQl2tpdKeepalive is a REPRODUCTION, not a passing cell. …
#   ql2tpd -> veepin  ccid=1100 ns=0 nr=0  HELLO
#   veepin -> ql2tpd  ccid=2200 ns=0 nr=1  ACK      <- correct: nr=1 acks ns=0
#   ql2tpd -> veepin  ccid=1100 ns=0 nr=0  HELLO    <- retransmit anyway
#   ... x3, then "transmit of avpMsgTypeHello failed after 3 retry attempts"
```

`internal/l2tpv3/README.md` states the consequence plainly: the control
connection is covered by unit tests only, *"which by this repo's own standard
means it is not proven correct."* That sentence is the most honest thing in the
tree and also the one open admission of its kind.

The observation is specific and reproducible, which is what makes this worth a
timebox rather than a shrug. Three hypotheses worth testing in order, cheapest
first:

- **go-l2tp discards our ACK before it reaches `processAckQueue`.** An ACK
  (Message-Type 20) does not consume a sequence number, so it carries the Ns
  that the *next* real message will use. If go-l2tp runs its duplicate check on
  Ns before its acknowledgement handling, our `ns=0` looks like a replay of a
  packet it has not received yet. This fits the evidence exactly: when veepin
  also sends HELLOs — which *do* consume Ns — ql2tpd acknowledges each one and
  advances its Nr, because those messages survive the duplicate check.
- **The Control Connection ID is being read from the wrong side.** In L2TPv3 the
  header's CCID is the *recipient's*, not the sender's. veepin→ql2tpd carrying
  `ccid=2200` is consistent with ql2tpd having advertised 2200, but this is
  exactly the class of both-ends-agree asymmetry that
  `TestKeyBlocksNameTheirOwnInboundDirection` was written for in
  `internal/pulse`. Confirm it against
  go-l2tp's source rather than against our own encoder.
- **It is go-l2tp's bug.** Possible, and the README already leans this way. If
  the answer turns out to be this, the deliverable is not a code change: it is a
  minimal reproduction and an upstream issue, plus the README updated from "not
  understood" to "understood, and it is theirs".

**Read go-l2tp's source, do not reason about it.** That is the lesson recorded
in `AGENTS.md` from the Pulse work, and this is a case where a summary would
lose exactly the ordering that decides between hypothesis one and hypothesis
three.

### The assertions that are not optional

If the cell can be made to pass, it becomes `TestInteropL2TPv3Keepalive` and
joins the matrix. If it cannot, `TestPendingQl2tpdKeepalive` stays skipped and
its comment is **extended with what was ruled out**, so the next person starts
where this one stopped rather than at the beginning.

### Cost

Timebox it at one day. The outcome is either a fix, or an upstream issue plus a
sharper comment — and both are acceptable outcomes, which is what makes the
timebox honest rather than a way of giving up early.

---

## 4. Which other fixtures make the easy case the only case? *(surveyed)*

The survey ran. Four categories were checked; one was a real finding, two were
already covered, and one was fixed by item 2.

### The finding: every cell in the matrix pinged 84 octets, and nothing else

```sh
grep -n '"ping", "-c2", "-W2"' tests/interop/interop_test.go
# the one shared helper every cell goes through -- ping's default 56-octet
# payload, an 84-octet IP packet, and no other size anywhere
```

`datapath_test.go` sweeps `{64, 576, 1400}` in Go, and the matrix settled for
one small packet on every protocol, in every direction. A length field one octet
short, a buffer sized from a literal, a shaper that overshoots its target, or an
MTU derived wrongly are all invisible to an 84-octet datagram — and every one of
them breaks a real transfer immediately.

`runInterop` now sends a second ping with a 1000-octet payload after the small
one has proved the tunnel is up, and fails if it does not cross. 1000 is chosen
against the smallest inner MTU in the tree (nebula's 1300), so it is a genuinely
large packet on every protocol without becoming a test of path-MTU discovery,
which is a different mechanism with its own cells.

**It found no bug**, which is worth stating plainly rather than dressed up: every
cell passed on the first run. That is a real result — the framing across sixteen
protocols is not sized for the easy case — and the guard is what keeps it true.

### Already covered

- **Cookie asymmetry.** L2TPv3 mints asymmetric 8-octet cookies precisely so a
  both-ends-backwards bug cannot pass, and the matrix label says so.
- **Key direction on ESP-carrying protocols.** `internal/pulse` has
  `TestKeyBlocksNameTheirOwnInboundDirection`, written from the peer's point of
  view, which is the model the roadmap names.

### Fixed by item 2

- **Certificate size.** Before this branch every fixture in the tree minted
  ECDSA P-256 or `openssl req -newkey ec`, except SoftEther's RSA-2048 server
  key. The RSA cert cells are the fix; the survey is what confirms nothing else
  was hiding behind the same assumption.

### Cost

Half a day, most of it waiting for sixteen protocols' worth of Docker.

# Part 2: shaping reaches thirteen of sixteen

The README says it: `-shape` covers thirteen of the sixteen protocols, and *"the
three still unshaped are SSH, MASQUE and Nebula; each has a plausible vehicle
and none has been plumbed."* `doc/traffic-shaping.md:290` calls it "mostly
plumbing rather than design".

That is true for two of the three. It is not true for SSH, and the reason is
worth recording before the work starts.

## 5. SSH is unshaped — and the vehicle the docs name does not exist

`doc/traffic-shaping.md:291` names `SSH_MSG_IGNORE` as SSH's vehicle: *"exists
for exactly this"*. It does exist, in the protocol. It is not reachable from
`x/crypto/ssh`.

```sh
grep -rn 'msgIgnore' $(go env GOMODCACHE)/golang.org/x/crypto@v0.54.0/ssh/*.go | grep -v _test
# handshake.go:248, handshake.go:472, messages.go:22, transport.go:129
# messages.go:22:  msgIgnore = 2      <- lower-case: unexported

grep -n 'SendRequest' $(go env GOMODCACHE)/golang.org/x/crypto@v0.54.0/ssh/connection.go
# 56:  SendRequest(name string, wantReply bool, payload []byte) (…)
```

`msgIgnore` is an unexported constant, `x/crypto/ssh` exposes no raw-packet
write, and `Conn.SendRequest` sends a *global request* (message 80), not an
ignore. This is the same shape of finding as the MASQUE RFC 9221 rejection
already recorded in `protocol-roadmap.md`: the standards-track answer exists and
the library does not surface it.

**The real vehicle is the one L2TPv3 and SoftEther already use.**
`internal/sshtun`'s framing is a 4-octet address-family prefix and nothing else
— its README says so: *"There is no length field inside the channel — SSH
channel messages already delimit — so `Decode` just validates and strips the
4-byte family."* So trailing filler appended after the inner IP packet is
trimmed by that packet's own Total Length, exactly as it is on an L2TPv3
pseudowire, and a conforming receiver writes the whole thing to its tun device
where the IP stack ignores everything past Total Length.

This changes nothing about the cost and everything about the design section, so:
**`doc/traffic-shaping.md`'s SSH entry is corrected as part of this item**, with
the reason kept rather than the sentence deleted — the same treatment the
"padding the handshake itself" entry got.

### The assertions that are not optional

- The cell runs against real OpenSSH `sshd` with `PermitTunnel`, padded, and
  proves the ping still round-trips. If OpenSSH rejects or mis-handles trailing
  octets on a `tun@openssh.com` channel frame, the honest outcome is that SSH
  stays unshaped and the doc says why — **not** that the padding is weakened to
  something that no longer hides the size pattern.
- A unit test named for the claim: `TestPadIsTrimmedByTheInnerTotalLength`.

## 6. Nebula is unshaped

```sh
sed -n '27,40p' internal/nebula/header.go
# headerLen = 16 — fixed, no options, no variable-length fields
# Overhead = headerLen + tagSize
```

A fixed 16-octet header, the inner IP packet as the payload, an AEAD tag. No
length field, so trailing filler is trimmed by the inner Total Length — the same
mechanism again.

One trap, and it is the one SoftEther already taught: **pad only the data
messages.** Nebula's header carries a Type nibble, and handshake, `recv_error`
and lighthouse messages travel through the same socket with the same header. A
shaper that padded by header presence rather than by message type would corrupt
the handshake before any data packet existed to notice — which is exactly the
ARP problem `TestShapeFramePadsIPAndLeavesEverythingElse` was written for.

Note also that the header is passed to the AEAD as additional data, so padding
must go *inside* the sealed payload, not appended after the tag. Appending after
the tag would be stripped by the peer's length arithmetic at best and fail
authentication at worst.

### The assertions that are not optional

- `TestShapePadsDataMessagesOnly` — a handshake message through the shaper comes
  out byte-identical.
- The cell is `compose.nebula-shaped.yml` against real `nebula`, which must
  accept the padded packets and trim them.

## 7. MASQUE is unshaped

The vehicle here is genuinely clean, and — unusually — half of it is already
built.

```sh
grep -n 'Capsule.*= 0x' internal/masque/capsule.go
# CapsuleDatagram 0x00 / AddressAssign 0x01 / AddressRequest 0x02 / RouteAdvertisement 0x03

grep -n 'switch capsule.Type\|capsule.Type != CapsuleDatagram' internal/masque/client.go internal/masque/server.go
# client.go:188  switch capsule.Type { … }        <- no default: unknown types fall through
# server.go:258  if capsule.Type != CapsuleDatagram { … }
# server.go:351  if capsule.Type != CapsuleDatagram { … }
```

RFC 9297 requires an endpoint to skip a capsule whose type it does not
recognise, and veepin already does — the `switch` has no default and the server
guards on type. So a padding capsule is inert to veepin in both directions
today, and the only open question is whether **aioquic** skips it too. That is
what the cell is for, and it is a real question rather than a formality: a
receiver that errors on an unknown capsule type would be non-conforming, and
finding that out is worth the cell either way.

Pick an unregistered type from the greased/private space rather than an
adjacent small integer, so a future RFC assignment cannot collide with it.

### Cost, all three

~450 LOC including tests, plus three interop cells. No count change. The README
sentence naming SSH, MASQUE and Nebula as unshaped, and
`doc/traffic-shaping.md`'s "Next" list item 2, are both edited by hand — again,
no guard will notice.

---

# Part 3: the next capability

`protocol-roadmap.md` ranks RFC 9329 fourth and Rosenpass fifth, and that
ranking stands. An earlier draft of this plan inverted it on the strength of
Rosenpass's *shape* — additive, no data path, a real peer in both roles. That
draft had not read `rosenpass-plan.md` to its recommendation, which is the one
section that matters.

## 8. Rosenpass — PQ keys for WireGuard *(don't — and the plan that says so is already in the tree)*

```sh
grep -n -i 'mceliece\|kyber\|dependency' doc/rosenpass-plan.md
ls "$(go env GOROOT)/src/crypto"            # mlkem yes; no mldsa, no mceliece
ls "$(go env GOMODCACHE)/golang.org/x/crypto@v0.54.0"   # neither
```

[`rosenpass-plan.md`](rosenpass-plan.md) reaches a verdict this plan should have
carried forward rather than re-derived:

> **Rosenpass cannot be implemented interoperably under the current dependency
> policy.**

Two primitives, neither reachable. **Classic McEliece** `mceliece460896` exists
in no permitted package — not the standard library, not `x/crypto` — and a
correct constant-time implementation of a KEM with a 524 KB public key is weeks
of work whose failure mode is silent. And Rosenpass specifies **round-3
Kyber-512**, which is *not* `crypto/mlkem`: ML-KEM is the FIPS 203 variant, and
the two do not interoperate. So neither of the standard library's PQ primitives
helps: `crypto/mlkem` does not cover the half it looks like it covers, and Go
1.27's `crypto/mldsa` is a signature scheme, not a KEM.

That plan offers two escape hatches. The first — implement the idea with
`crypto/mlkem` alone, veepin on both ends — it then argues against itself, and
correctly: a cryptographic protocol whose only evidence is a veepin↔veepin cell
is the exact situation that hid the Pulse ESP key-direction bug. The second is
to pursue post-quantum IKEv2 instead, *"strictly better on every axis this
project cares about"* — and **that one has already landed**, ML-KEM-768 over
RFC 9370 + RFC 9242, green against strongSwan in both directions.

So Part 3 has one item in it, not two.

**What would change the verdict**, and the only thing that would: upstream
Rosenpass migrating its ephemeral KEM from round-3 Kyber to ML-KEM. That closes
half the gap and leaves only McEliece. Worth a re-read of the spec once a year
rather than a watch — and it does nothing about the static KEM, which is the
half that carries authenticity.

## 9. RFC 9329 — TCP encapsulation *(the next capability, knowing what it is)*

The roadmap's re-survey (`protocol-roadmap.md:564`) already did the work of
disproving its own estimate, and it should be read before this is started rather
than after:

```sh
grep -c "net.UDPConn\|net.UDPAddr" internal/ikev2/ike/client.go ikev2/client.go dataplane/pump.go
# internal/ikev2/ike/client.go:11   ikev2/client.go:5   dataplane/pump.go:11

grep -n "type Sender" dataplane/pump.go
# 76:type Sender func(pkt []byte, to *net.UDPAddr)
```

The responder's `transport` seam makes the control plane look like a ~500 LOC
job, and it is. The rest is not: `Client.DataConn()` returns a concrete
`*net.UDPConn`, `dataplane.Sender` takes a `*net.UDPAddr`, and RFC 9329 carries
**ESP on the same TCP stream** — so a control-plane-only version is useless,
because the entire point is a network that blocks UDP. The batching and GSO work
does not carry over; a stream data path starts again from a length-prefixed
reassembler.

What it buys is real and should not be undersold: **libreswan enters the harness
as a new peer**, and `apk add libreswan` on Alpine 3.20 gives version 5.0, so
the peer image is three lines rather than the cached source build the original
estimate budgeted for.

Do it after Rosenpass, and land **a plain libreswan-over-UDP cell first** — a
new peer and a new transport debugged simultaneously is how a day disappears.

---

# Part 4: operability hardening

## 10. An abandoned listener leaks its pump goroutine and its TUN fd

```sh
grep -n 'stopGrace\|abandoned' internal/supervisor/manager.go
# 734: const stopGrace = 5 * time.Second
# 795: var abandoned bool
# 806: "Close did not return within %s; abandoning the listener …"
```

`internal/supervisor/README.md` states the consequence and does not soften it:
past the bound the listener *"is logged and abandoned, which **leaks its pump
goroutine and TUN fd until the process exits**. Repeatedly restarting a
genuinely wedged listener accumulates both."*

The bound itself is right — an unbounded wait freezes every other listener's
status behind one wedged protocol, which is worse. The original cause is also
already fixed: `dataplane` holds the TUN fd non-blocking and polls it against a
wake eventfd, so a `Close` waiting on an idle pump unblocks. What remains is
every *other* blocking path a protocol owns: a wedged control connection, a peer
that never answers.

This is the highest-value item in Part 4 because it is the only one that gets
*worse over time* rather than merely staying missing. A fleet that restarts a
broken listener on a timer accumulates a goroutine and a file descriptor per
attempt until the process dies.

### What to build

Two independent halves, and the first is worth more than the second:

- **Make abandonment cost nothing.** Give the listener handle a context that
  `Close` failing cancels, and make the pump's read loop select on it, so an
  abandoned listener's goroutine exits even though its `Close` never returned.
  The fd follows the goroutine.
- **Count what was abandoned, and expose it.** `/api/metrics` already exists from
  operability item 8. An `abandoned_listeners` gauge that only ever goes up is
  the difference between an operator noticing this and not.

### The assertion that is not optional

A test with a `client.Server` whose `Close` blocks forever, asserting the
goroutine count and the open-fd count return to baseline. `runtime.NumGoroutine`
alone is flaky; read `/proc/self/fd` for the fd half.

## 11. No kill switch on macOS

`dataplane/client_killswitch_other.go` refuses, and its comment is a complete
design document for why: the Linux implementation needs blackhole routes *with
per-route metrics* so the switch can sit inert behind the tunnel's own route and
take over with no window. macOS has `route -n add -blackhole` and no metric, so
arming it while healthy is impossible and arming it on teardown leaves the
teardown's own duration as plaintext — which is exactly the mechanism error
operability item 3 already corrected once on Linux.

The honest answer named in that comment is a pf anchor. Building it means veepin
owns firewall state on the user's host, which is a larger promise than the Linux
implementation makes and one that file explicitly declines.

**So this is a decision, not a task.** It should be taken deliberately:

- A pf anchor (`veepin`) loaded and flushed by veepin, blocking all traffic on
  the physical interfaces except to the server's outer address, armed while the
  tunnel is healthy.
- The failure mode that must be designed for first: **veepin dying without
  flushing the anchor leaves the user's network broken.** `RecoveryCommand()`
  exists on the Linux type for exactly this reason and returns empty on the
  stub; the pf version must return a real, copy-pasteable `pfctl` invocation,
  and the error message must print it.

Gated on item 10 only by preference — they touch nothing in common. Gated on
somebody running `doc/verifying-macos.md` on real hardware in a stronger sense:
**the macOS client is written and has never been run.** Building a second macOS
feature on top of an unverified first one is how two bugs become one
indistinguishable failure.

## 12. `-log-level` gates the stream, not the call site

```sh
grep -rn '\*log\.Logger' --include='*.go' . | grep -v _test | wc -l
# 130
grep -rn 'log/slog' --include='*.go' . | wc -l
# 4
```

`operability-plan.md`'s "What is owed next" already scoped this: making `warn`
mean something *within* the stream is a `slog` migration of several hundred call
sites. 130 `*log.Logger` fields and parameters is the structural count; the call
sites behind them are the real number.

It is last because it is the only item here that is pure refactor — no
capability, no defect, and a large diff across every package including the ones
with allocation guards. Two things make it worth doing eventually: the drop path
on every data path uses pre-built sentinels so a flood of bad packets allocates
nothing, and `slog`'s attribute API allocates unless used carefully. That
interaction is the whole risk, and it is why this should not be attempted in the
same window as anything in Part 1.

If it happens, it happens as a mechanical pass with `slog.Logger` behind the
same field name, one package per commit, with the `AllocsPerRun` guards run
without `-race` after each.

---

# The longer horizon

The twelve items above are one plan's worth of work. This section is the list
behind them: things too large, too speculative, or too dependent on somebody
else's release to sequence yet, recorded so the choice of what comes after is
made from a written menu rather than from whatever is most recently annoying.

Nothing here is scheduled. Each entry says what it is worth, what it costs, and
what would have to be true before starting it.

Where an entry depends on the toolchain it was surveyed against **go1.26.5**,
with `go.mod` at `go 1.25.0`. That already dated once while this page was being
written: H3 was drafted as permanently blocked and **Go 1.27 unblocked it**, so
each toolchain-dependent claim below carries the version it is true of rather
than a bare assertion.

| # | Item | Value | Cost | Gate |
|---|------|-------|------|------|
| H1 | Every TLS 1.3 protocol already does hybrid PQ key exchange, and nothing says so | **High** | Low | ✅ landed |
| H2 | OpenVPN's server caps TLS at 1.2, which forecloses H1 for it | Medium | Low | ✅ landed — the hypothesis held |
| H3 | PQ **authentication** — unblocked by Go 1.27's `crypto/mldsa` | **High** | Medium | ✅ H3a landed; H3b still gated on the IKEv2 interop survey |
| H4 | Inner IPv6 reaches one protocol of sixteen | **High** | **High** | pick two protocols, not all fifteen |
| H5 | GSO/GRO are IPv4-only, and IKEv2 now carries inner v6 | Medium | Medium | ✅ surveyed: there is no slow path, only an absent optimisation |
| H6 | `scaling-the-data-path.md` Option 2 — parallelism with per-tunnel affinity | Medium | **High** | a profile showing the ceiling actually binds |
| H7 | Site-to-site: multi-SA, subnet selectors, no config-mode assignment | **High** | **High** | a decision that veepin is for more than road warriors |
| H8 | Record the peer, replay it offline | **High** | Medium | none — the cheapest leverage on this page |
| H9 | Memory hygiene that can actually hold, instead of zeroing that cannot | Medium | Low | ✅ landed |
| H10 | The management panel's authentication ceiling | Medium | Medium | ✅ decided: one operator, permanently |
| H11 | Windows — and the README names the wrong obstacle first | Low | **High** | somebody who wants it enough to argue it |
| H12 | Signed releases, SBOM, continuous fuzzing | Low | Low | ✅ signing + SBOM landed; OSS-Fuzz is an application, not code |

**If only two things happen from this page: H1 and H8.** H1 is a claim veepin has
already earned and cannot currently make. H8 makes every future claim cheaper to
keep. H3a is the natural third and follows H1 directly — same protocols, same
cells, the other half of the same handshake — but it costs a `go.mod` floor bump
that deserves its own decision.

---

## H1. Every TLS 1.3 protocol already does hybrid post-quantum key exchange, and nothing anywhere says so

```sh
grep -rn 'CurvePreferences' --include=*.go .
# (nothing — not one call site pins the curve list)

grep -n 'From Go 1.24' "$(go env GOROOT)/src/crypto/tls/common.go"
# 805:  // From Go 1.24, the default includes the [X25519MLKEM768] hybrid

grep -rn 'MinVersion\|MaxVersion' --include=*.go . | grep -v _test | grep -v /dtls/
# masque × 3:   MinVersion: tls.VersionTLS13
# eight others: MinVersion: tls.VersionTLS12
# openvpn/server.go:677:  MaxVersion: tls.VersionTLS12      <- see H2
```

veepin pins no `CurvePreferences` anywhere, so every `tls.Config` in the tree
takes `defaultCurvePreferences()`, and from Go 1.24 that list leads with
`X25519MLKEM768` (CurveID 4588). `go.mod` says `go 1.25.0`. The conclusion
follows without a line of new code:

> **MASQUE's key exchange is post-quantum today**, unconditionally — all three
> of its configs are TLS 1.3-only. AnyConnect, Fortinet, GlobalProtect, Ivanti,
> SSTP, SoftEther and the OpenVPN *client* are post-quantum whenever the peer
> negotiates TLS 1.3, which every current one does.

That is a considerably better post-quantum story than the tree tells. `README.md`
credits PQ to IKEv2 alone and `doc/security.md` has one PQ section, about IKEv2.
Nine more protocols have the property and nobody wrote it down — and, more to the
point, **nothing asserts it**, so a future `CurvePreferences` added for a vendor
workaround would silently take it away. That is this plan's own subject matter,
one part later.

### What to build

`tls.ConnectionState.CurveID` reports the negotiated mechanism, so the assertion
is direct: after each protocol's TLS handshake in its `e2e_test.go`, require
`X25519MLKEM768`. Then a paragraph in `doc/security.md` beside the IKEv2 one, and
a corrected sentence in the README.

Go 1.27 adds `MLKEM1024` as a further option, but **not to the default** — it
has to be named in `Config.CurvePreferences` explicitly. Nothing below changes;
`X25519MLKEM768` is still what the default negotiates, and still what to assert.

### The assertions that are not optional

- **Assert the negotiated `CurveID`, not the config.** A test that reads back
  `cfg.CurvePreferences == nil` proves nothing about what two peers agreed on.
- **Assert it in the TLS-1.2-floor protocols too**, where it is conditional on
  the peer. Those are the ones a workaround would break first.
- **One interop cell must carry it**, not only the veepin↔veepin path — the
  standing rule on this page. openconnect and the `openvpn` binary both link
  OpenSSL 3.5+, which offers ML-KEM; the cell should log the negotiated group and
  `runInteropRequiringLog` should require it.
- **State the limit in the same breath.** This is key exchange only. It says
  nothing about authentication (H3), and nothing about the DTLS data channels —
  `internal/dtls` is a from-scratch DTLS 1.2 with two fixed suites and no PQ path
  at all, so AnyConnect's and Fortinet's *data* channels stay classical even
  when their control channels do not.

**Cost:** a day, most of it in the interop cell and the prose.

---

## H2. OpenVPN's server caps TLS at 1.2, which forecloses H1 for it

```sh
sed -n '670,680p' openvpn/server.go
# MaxVersion: tls.VersionTLS12
# "TLS 1.3's post-handshake NewSessionTicket messages do not fit that
#  half-duplex request/response model cleanly, stalling some clients"
```

The reason is real and specific, which is the good kind of comment. But it was
written about a stall, not about cryptography, and it now also costs the server
half of OpenVPN the property H1 gives everything else.

The hypothesis worth one afternoon: the stall is `NewSessionTicket`, and
`SessionTicketsDisabled: true` suppresses exactly that message without giving up
TLS 1.3. If that holds, the cap lifts and OpenVPN joins H1. If it does not — Go's
client also sends post-handshake messages of its own — then the cap is correct
and the comment should gain a sentence saying what it costs, so the next reader
does not have to rediscover it.

Either outcome is worth having, and the `openvpn` binary in the existing interop
cell is the judge, not a unit test.

**Cost:** half a day, and it is genuinely half a day either way.

---

## H3. Post-quantum authentication — unblocked by Go 1.27, three weeks after this page said it wasn't

```sh
ls "$(go env GOROOT)/src/crypto"     # under go1.26.5, the toolchain this was surveyed on
# aes boring cipher crypto.go des dsa ecdh ecdsa ed25519 elliptic fips140
# hkdf hmac hpke internal md5 mlkem pbkdf2 rand rc4 rsa sha1 sha256 sha3
# sha512 subtle tls x509
#   ^ mlkem yes. No mldsa. No slhdsa.

ls "$(go env GOMODCACHE)/golang.org/x/crypto@v0.54.0"
#   ^ neither
```

That survey is what this entry was originally written from, and its conclusion —
*not closable by effort, watch and do not build* — was correct for about as long
as it took to write down. **Go 1.27 (August 2026) ships `crypto/mldsa`**, and it
did not arrive alone:

- `crypto/mldsa` implements **ML-DSA (FIPS 204)**.
- `crypto/x509` *"now supports ML-DSA private keys, public keys, and
  signatures"* — the certificate half, which is the half that usually lags.
- `crypto/tls` *"now supports ML-DSA signatures in TLS 1.3"*, as the
  `MLDSA44` / `MLDSA65` / `MLDSA87` `SignatureScheme` values.
- Separately, `MLKEM1024` is now available as a key exchange, though **not by
  default** — it must be named in `Config.CurvePreferences`. H1's conclusion is
  unaffected; the default still leads with `X25519MLKEM768`.

So the gap `doc/security.md` names — *"Authentication remains classical … a
quantum adversary attacking the authentication live can forge credentials"* — is
now closable inside the dependency policy, with no new module. It splits into two
jobs of very different size.

### H3a. The TLS family gets post-quantum authentication nearly free

`crypto/x509` parsing ML-DSA keys plus `crypto/tls` offering `MLDSA65` means a
veepin server can present an **ML-DSA certificate** and a veepin client can
verify one, across every TLS 1.3 path in the tree, without protocol work. Paired
with H1's key exchange, that is a fully post-quantum handshake — both halves —
for MASQUE unconditionally and for the SSL-VPN family whenever the peer keeps
up.

The interop question is the whole question, and it is answerable: OpenSSL 3.5
implements ML-DSA, so the `openvpn` binary and openconnect are the judges rather
than a veepin↔veepin cell. Expect the answer to be partial — a vendor client that
verifies an ML-DSA chain is a different thing from one that offers the signature
algorithm — and expect that partial answer to be worth publishing either way.

### H3b. IKEv2 post-quantum authentication is real protocol work

This is the one that closes `security.md`'s stated gap, since IKEv2 is where the
PQ key exchange already lives and the mismatch is therefore sharpest: ML-KEM-768
protecting a key exchange whose authentication is an RSA or ECDSA signature.

The machinery is mostly present — RFC 7427 Digital Signature (AUTH method 14)
already carries an algorithm identifier rather than a fixed scheme, which is
precisely the extension point this needs, and `certauth.go` already builds and
verifies that payload. What is *not* established is the wire identifier and
whether a peer speaks it. **Survey before scoping:** find the current IETF
document for ML-DSA in IKEv2 auth, and check whether strongSwan 6.x implements
it. If it does not, this ships with a veepin↔veepin cell as its only evidence —
the position item 8 was rejected for — and should wait.

### The prerequisite, measured rather than guessed

Raising `go.mod`'s floor from 1.25 to 1.27 was surveyed by doing it — bump,
run the gate, revert. It is six mechanical changes and one real finding.

```sh
sed -i 's/^go 1\.25\.0$/go 1.27.0/' go.mod
go build ./... && go vet ./... && go test ./...
```

**The mechanical part.** `crypto/mldsa` *builds and runs* under a `go 1.25.0`
directive — only `go vet` objects, reporting that `mldsa.GenerateKey` "requires
go1.27 or later (file is go1.25)". Since `go vet ./...` is in the gate, the bump is
required rather than advisory, and it lands in six places:

1. `go.mod` — `go 1.25.0` → `go 1.27.0`.
2. `nm/go.mod` — the same. `nm` is a separate module and breaks outright
   otherwise: *"go: updates to go.mod needed"* on both `build` and `vet`.
3. `go mod tidy` — it reflows the two `require` blocks into one, and
   `git diff --exit-code go.mod go.sum` is in the gate.
4. Thirteen version pins across the workflows — twelve `go-version: "1.25"`
   plus the `go: ["1.25", "1.x"]` matrix in `ci.yml:32`. **Leave
   `ci.yml:129`'s `"1.26.6"` alone**; that is the govulncheck pin, and the
   twelve-line comment above it explains why it is bumped on its own schedule.
5. `Dockerfile:12` — `FROM golang:1.25-bookworm`. It would otherwise still
   work, `GOTOOLCHAIN=auto` fetching 1.27 mid-build, at the cost of a network
   round trip in every interop image build. The four *peer* Dockerfiles
   (`amneziawg` and `wireguard` at 1.24, `nebula` and `ql2tpd` at 1.25) build
   the other implementation and must not be touched — their Go version is part
   of what is being tested against.
6. `README.md:261` — *"Requires Go 1.21+ (developed against Go 1.26)."*

And the decision named above is `ci.yml:32`. `["1.27", "1.x"]` keeps the
pinned-plus-latest shape and regains its point when 1.28 ships.

### The finding: one test fails, and the reason is not the one it looks like

At the 1.27 floor the entire tree passes with and without `-race` **except**:

```
--- FAIL: TestNoiseIXKnownAnswer   internal/nebula/noise_test.go:86
    message 1 diverges from the reference
     got: 25d2cf03…7b4e909bbe7ffe44…7061796c6f61642d6f6e65
    want: 7b0d47d9…7b4e909bbe7ffe44…7061796c6f61642d6f6e65
             ^ the first 32 octets — the ephemeral public key — and nothing else
```

Not an ML-DSA problem, and not a nebula bug. **Go 1.26 added the
`cryptocustomrand` GODEBUG, which defaults to `0` for a `go.mod` at 1.26 or
later and makes most `crypto/…` APIs *ignore the `io.Reader` passed to them*.**
`internal/nebula/noise.go:240` is `ecdh.X25519().GenerateKey(rand)`, so the
ephemeral key stops coming from the test's `fixedReader` and starts coming from
the system CSPRNG. Proved rather than inferred:

```sh
GODEBUG=cryptocustomrand=1 go test ./internal/nebula/ -run TestNoiseIXKnownAnswer
# ok    — at the same 1.27 floor
```

**Scope is one package, and the survey is worth keeping.** Every other crypto
call site in the tree passes `crypto/rand.Reader`, which is unaffected — ignoring
a reader that was already the system source changes nothing:

```sh
grep -rn 'GenerateKey(\|SignASN1(\|SignPKCS1v15(\|CreateCertificate(\|\.Sign(' --include=*.go .
# every hit is rand.Reader, except internal/nebula/noise.go:240
```

Production is fine either way: `handshakeConfig.randReader()` returns the real
source. What breaks is the *test seam*.

### Why the obvious fix is the wrong one

`go.mod` accepts a `godebug cryptocustomrand=1` line, which makes the failure go
away in one edit. **Don't.** That opts the entire program out of a
security-motivated change to the standard library in order to keep a test
passing — the same trade `doc/security.md` refuses when it declines to fake key
zeroing, and worse here because it is invisible from the test that benefits.

The honest reading is that the parameter has become a lie.
`WriteMessage1(payload, rand io.Reader)` advertises control over ephemeral key
generation that the runtime no longer grants it, and the comment at
`noise.go:237` — *"It is a parameter so tests can substitute…"* — now describes
something that does not happen. **Move the seam from the entropy to the key**:
have `generateEphemeral` take an optional `*ecdh.PrivateKey`, nil in production.
The test file already builds fixed X25519 keys that way for the statics
(`mustX25519`), so the vectors are unchanged and the fixture gets shorter.

That this surfaced as a loud known-answer failure is luck. A seam that silently
stops being deterministic is this plan's subject matter exactly, and it is worth
noting that **no guard in the tree would have caught it** — it took a KAT that
happened to exist. Item 4's fixture survey should add a question to its list:
*which test seams depend on runtime behaviour that a toolchain bump can remove?*

**Verdict: no longer "watch." H3a is a week and produces a publishable result
either way. H3b is gated on the interop survey above, and should stay gated.**

Also worth noting, since the original survey turned it up: `crypto/hpke` is in
the standard library as of 1.26. Not post-quantum, and nothing in the tree needs
it today, but it is the primitive Encrypted Client Hello is built on, and ECH is
the kind of thing a VPN that cares about fingerprinting eventually looks at.

---

## H4. Inner IPv6 reaches one protocol of sixteen

```sh
grep -rn 'Pool6\|AddrPool6' --include=*.go . | grep -v dataplane/ | grep -v _test
# ikev2/server.go × 8
# client/server.go:48 × 1   <- a comment
```

`dataplane.AddrPool6` has exactly one consumer. Fifteen protocols assign a v4
address and nothing else, so a client on a v6-only inner network gets a tunnel
that carries half the internet.

The README is accurate — dual-stack is claimed under the IKEv2 bullet and
nowhere else — but it is accurate in the way item 1's fragmentation sentence was
accurate: true when read exactly, and easy to read as general. This is the same
*shape* of finding as "shaping reaches thirteen of sixteen," at a far worse
ratio and without a doc that frames it as outstanding work.

The **underlay** is in better condition and should not be confused with it: every
socket in the tree is opened family-agnostic (`"udp"`, `"tcp"`) except `toy` and
`nebula`, which use `"udp4"` — and nebula's upstream does the same.

### Why the cost is high, and how to make it not be

Fifteen protocols is not the unit of work. Each needs its own config-mode
extension — OpenVPN has `ifconfig-ipv6-push`, WireGuard has `AllowedIPs` and
needs no negotiation at all, SSTP and L2TP inherit IPCP's v6 sibling IPV6CP, and
MASQUE's CONNECT-IP is address-family agnostic by construction. They are four
different jobs, not one.

**Do two, not fifteen.** WireGuard (nearly free — the address is configuration,
not negotiation) and OpenVPN (a real config-mode extension against a real peer)
would establish the pattern and the interop shape. Whether the other thirteen
follow is then a decision with evidence behind it.

**Cost:** a week for those two, honestly. Unknown for the rest, deliberately.

---

## H5. GSO and GRO are IPv4-only, and IKEv2 now carries inner v6

`doc/scaling-the-data-path.md` lists *"TSO6/USO (IPv4-only tree)"* among what is
not built. The parenthetical was true when written. It is not any more: IKEv2
assigns an `INTERNAL_IP6_ADDRESS` by default, so every IKEv2 server already
carries inner v6 traffic — down the slow path, silently, while the v4 traffic
beside it takes the offload.

Nothing is broken; it is a performance cliff nobody has measured. **Measure
before building.** Extend the existing `Benchmark*` sweep with a v6 inner flow
and compare. If the gap is small, the honest action is to correct the
parenthetical in the doc and stop. If it is large, TSO6 is a bounded change to
`offload_linux.go` and `gro_linux.go` rather than a new mechanism.

**Cost:** a day to measure. The build is only worth scoping after that.

---

## H6. `scaling-the-data-path.md` Option 2 — parallelism with per-tunnel affinity

The largest designed-but-unbuilt item in the tree, and the design doc has already
done the hard part: it enumerates the single-goroutine assumptions a naive
parallelization breaks, which is exactly the list that makes this
survivable.

Two things keep it off the near-term plan. It binds only the single-socket class
(IKEv2, WireGuard, OpenVPN, Nebula, L2TP) — the connection-per-client protocols
already scale for free on the Go runtime. And the doc's own instruction is
**profile before choosing**, which nobody has done since Option 1 landed. Option
1 may well have moved the ceiling far enough that the answer is "not yet," and
that is a result worth having for the cost of an afternoon.

**Gate: a profile showing the ceiling actually binds.** Without it this is
speculative work on the most correctness-sensitive code in the repository.

---

## H7. Site-to-site: multiple SAs, subnet selectors, no config-mode assignment

The README names this as a boundary in one clause — *"one IKE SA per Child,
sufficient for road-warrior clients rather than a site-to-site multi-SA
gateway."* It is the single largest capability gap between veepin and the thing
it is measured against, and it is bigger than any remaining protocol row by a
wide margin.

What it actually means: traffic selectors that are subnets rather than a single
assigned host address, several Child SAs under one IKE SA with different
selectors, no config mode at all (both ends have their own addressing), and a
`client.Result` shape that describes a route set rather than an interface
address. That last part is a `client` contract change, which is why this is a
program and not a task.

The peer is strongSwan in both roles, so the evidence is available — this is not
one of the candidates that would ship with a `—†`.

**Gate: a decision that veepin is for more than road warriors.** That is a
product question and it should be answered on purpose. If the answer is no, the
README clause should say "deliberately" rather than "sufficient," and this entry
becomes a permanent boundary in `doc/security.md` instead of a horizon item.

---

## H8. Record the peer, replay it offline

The interop matrix is the load-bearing evidence in this project — the whole
argument of `AGENTS.md` rests on it — and it is also the slowest, heaviest thing
here. It needs Docker, network, pinned peer images and fifteen-minute timeouts,
which means the evidence that matters most is the evidence a developer checks
least often.

Capture it once and replay it forever. For each cell, record the peer's side of
the exchange — handshake messages, ESP/data frames, the lot — and commit it as a
golden corpus. Then a `go test` with no build tag replays the recording against
the live parser and asserts the same bytes come back out. A regression against a
real strongSwan then fails in **seconds, on a laptop, offline** — instead of in a
CI shard that only runs when a path filter says so.

Two further returns, both large. The fuzz corpora currently start from nothing,
and real peer traffic is the best seed corpus that exists. And a recorded
exchange is a far better bug report than a log excerpt: item 3's ql2tpd trace on
this very page is a hand-transcribed four-line summary of something that should
have been a file.

### The assertion that is not optional

**A replay corpus is not a substitute for the live cell, and the doc must say
so where somebody will read it.** A recording pins the peer *as it was on the
day it was captured*. Trusting it as current is precisely the false-green
pattern this plan exists to interrupt — it would be the most sophisticated
instance of it yet. The live cells stay; the replay is what makes them cheap to
have confidence in between runs.

**Cost:** two weeks for the machinery and two or three cells. Then roughly a day
per cell after.

---

## H9. Memory hygiene that can actually hold, instead of zeroing that cannot

`doc/security.md` opens by refusing to zero key material, and the reasoning is
right: Go's collector copies, so wiping the reachable copy clears one of several
and produces code that *looks* like it wipes keys. The doc then names where the
boundary should be defended instead — *"process isolation, disabled core dumps,
encrypted swap"* — and hands all three to the operator.

Two of those three, veepin can take itself, on Linux, through `x/sys/unix`, with
no new dependency and no cgo:

- **`mlockall(MCL_CURRENT|MCL_FUTURE)`** — keys never reach swap, which closes
  the attacker-reads-the-disk-later case entirely.
- **`prctl(PR_SET_DUMPABLE, 0)`** — a crash stops carrying session keys into a
  core file, and it also stops a same-uid `ptrace`.

```sh
grep -rn 'Mlock\|PR_SET_DUMPABLE\|RLIMIT_CORE' --include=*.go .
# (nothing)
```

Opt-in flags on `serve`, and they must **fail loudly** when they cannot be
applied — `mlockall` needs `RLIMIT_MEMLOCK` headroom or `CAP_IPC_LOCK`, and a
hardening flag that silently does nothing is worse than no flag, for the same
reason the doc gives about fake wiping.

Honest about what is still not covered: a debugger with `CAP_SYS_PTRACE`, a
hypervisor, or anyone with code execution in the process. The boundary moves; it
does not close.

**Cost:** two days including the failure paths and the docs.

---

## H10. The management panel's authentication ceiling

`doc/security.md` is unusually direct here: the management plane binds to
localhost, the panel is unauthenticated, and `mgmt.RequireHost` is what makes
that safe. For a single operator on one box that is a correct design and the
Playwright suite already pins the `Host` check that holds it up.

It is also a hard ceiling on everything past that box, and the tree contains the
pieces of the other answer — `internal/userdb`, `internal/otp`, `internal/profile`
are all there for the VPN's own users.

The horizon item is a **decision**: is veepin's management plane for one operator
or for several? If several, it needs real authentication and the localhost bind
stops being the security boundary — a change that touches every `mgmt` handler
and deserves its own plan. If one, the doc should say **permanently** rather than
describing a state of affairs, because as written it reads like an omission
somebody will eventually "fix" by adding a login form in front of a design that
never assumed one.

---

## H11. Windows — and the README names the wrong obstacle first

The README's position is *"wintun is a DLL, which costs both the 'no runtime
dependencies' and the pure-Go claims; it is a trade worth making only for someone
who wants it enough to argue it."* That is an invitation, so the argument is
worth stating accurately.

**Half of it is wrong.** wintun is loaded at runtime through
`x/sys/windows` `LoadLibrary`, not linked — wireguard-go on Windows does exactly
this and remains pure Go with no cgo. The pure-Go claim survives intact.

What is genuinely true is the rest: shipping and trusting a signed third-party
DLL is a real runtime dependency and a real supply-chain surface, and the TUN is
only the visible half of the port. The other half is `internal/hostnet`, which
speaks `iptables` and `sysctl`, and would need a whole second backend in `netsh`
or WFP. That is the expensive part, and the README does not mention it.

**Still not recommended**, and for a fourth reason that outranks all of the
above: the macOS client compiles, is shipped, and *has never been run by anyone*.
Adding a second unverified platform before verifying the first turns two bugs
into one indistinguishable failure — the same argument that gates item 11.

---

## H12. Signed releases, SBOM, continuous fuzzing

The lowest-value entry here, listed because its cost is near zero and it only
gets more expensive to add under pressure.

GoReleaser already builds the releases, so cosign signatures and an SBOM are
configuration rather than work. The fuzz targets already exist and already run as
a CI smoke; OSS-Fuzz would run the same targets for hours a day instead of
seconds, against a codebase that is almost entirely parsers of hostile input —
which is the profile OSS-Fuzz exists for.

**Cost:** a day for signing and SBOM. The OSS-Fuzz application is mostly waiting.

---

## On adding more protocol rows

Worth saying plainly, since "what protocol next" is the most natural question to
ask a project whose headline is a count.

`protocol-roadmap.md` already answered it: *"the SSL-VPN seam is mined out."*
Every structurally interesting candidate is rejected there with a stated reason —
Tailscale fails the both-roles rule, ZeroTier is a product rather than a
protocol, tinc's peer is a decade-old pre-release, NordWhisper and Proton Stealth
have no open-source peer to test against. What remains is Juniper NC, Array and
F5: client-only, no new capability, ranked last by the roadmap's own criterion of
what a candidate *teaches* the tree.

**Every capability on this page is worth more than any of those three.** Adding
them would raise the count and lower the average value of a row, which is the
opposite of the claim the README actually makes.

---

# Explicitly out of scope

- **A seventeenth protocol row.** Juniper NC, Array and F5 are ranked last in
  `protocol-roadmap.md` for a reason it states plainly — they teach the tree
  nothing structural. Everything in Parts 1, 2 and 4 is worth more.
- **Windows.** Unchanged from `operability-plan.md` item 10. The TUN story needs
  a driver and the pure-Go, no-cgo constraint is load-bearing.
- **Rewriting any data path.** Item 9 is the exception and is flagged as such;
  it is the reason it is ranked second rather than first.
- **The L2TPv3 dynamic control plane.** Section 1 of `protocol-roadmap.md`
  establishes that no open-source peer implements it — `ql2tpd`, `go-l2tp` and
  `xl2tpd` each ruled out with the source quoted — so it would ship with `—†` in
  both real-peer columns. Item 3 here is about the *existing* quiescent control
  connection, which is a different and much smaller thing.
- **Anything gated on hardware nobody has.** Running
  `doc/verifying-macos.md` on a Mac and `doc/verifying-shaping.md` against stock
  vendor clients are both still owed, and both need a person with a device
  rather than more code. They are named in the docs that own them.

---

# Sequencing

Each lands on its own so a regression is attributable, and each is green before
the next starts. These do **not** all serialise the way protocol rows do —
Part 1 and Part 4 touch disjoint trees — but Part 2 touches the README's shaping
sentence and Part 3 touches the roadmap, so those two do.

0. **Part 0 — the toolchain floor**, alone in its own commit. Everything after
   it is written against a 1.27 `go.mod`, and a bump entangled with a protocol
   change is a bump nobody can revert.
1. **Item 1 + item 2 together.** The fix and the cell that would have caught it,
   in one branch, because landing the fix behind a fixture that cannot fail is
   the thing this plan exists to stop.
2. **Item 10 — the abandoned-listener leak.** Independent of everything, and the
   only item that compounds.
3. **Item 3 — the ql2tpd timebox.** One day, either outcome acceptable.
4. **Item 4 — the fixture survey.** Cheap, and it should run before Part 2 adds
   three more cells that could inherit the same blind spot.
5. **Items 5, 6, 7 — shaping**, in that order. SSH first because it is the one
   with a design correction attached, and getting that wrong quietly would
   propagate into the other two.
6. **Item 11 — the macOS pf kill switch**, if and only if somebody has run the
   macOS client on real hardware by then.
7. **Item 9 — RFC 9329**, plain libreswan-over-UDP cell first. (Item 8 is a
   *don't*; there is nothing to sequence.)
8. **Item 12 — `slog`**, in a quiet window, one package per commit.

Then the horizon list below, which is deliberately not sequenced — it is a
menu with costs attached, and which items get picked depends on what veepin is
being asked to *be* by the time this plan is done.

---

# Where this plan is probably wrong

Recorded up front, because a plan that is never contradicted was not specific
enough to be useful. The previous two both have this section and both earned it.

- **Item 1's cost is the least trustworthy number here.** "The encoder is the
  mirror of the decoder" is true of the codec and says nothing about the call
  sites. The initiator and responder build their messages through different
  paths (`client.go` and `ike_auth.go`), retransmission holds the encoded message
  and must now hold a *set* of them, and the message-ID window reasons about one
  message per ID. Any of those three could double the estimate.
- **Item 1's size estimate was too high, and item 2's blocking mechanism did not
  work.** Both were found by building it. An RSA-2048 certificate is 765 octets
  of DER, so leaf + intermediate + a 256-octet signature is ~2 KB rather than the
  2.5–3.5 KB claimed above — still over the 1500-octet path MTU, so the
  conclusion held, but the number was guessed and should have been measured.
  Worse, the cell's `iptables -A INPUT -f -j DROP` blocked nothing: netfilter's
  connection-tracking defragmenter runs at priority −400, ahead of both the raw
  (−300) and filter tables, so by the time any rule sees the datagram it has been
  reassembled and `-f` matches nothing. The first version of the cell passed with
  outbound fragmentation deliberately switched off — a fixture that could not
  fail, in the commit written to stop exactly that. The shipped version drops any
  IKE datagram over 1400 octets by length, and was verified by sabotage: with the
  fragmentation call short-circuited, the ping itself fails.
- **H5's premise was wrong, and in the reassuring direction.** This page said
  IKEv2's inner v6 "already carries inner v6 traffic — down the slow path,
  silently". There is no slow path: `TUNSETOFFLOAD` negotiates TSO4 only, so the
  kernel never produces a v6 super-frame and v6 takes the ordinary path
  everything took before GSO existed. An absent optimisation, not a degradation.
  The real risk was the opposite one — somebody adding `TUN_F_TSO6` because "we
  carry v6 now" without writing the segmenter — and that now fails a test.
- **Item 3 was not a veepin bug, and the recorded hypothesis was wrong.** It was
  not the Ns duplicate check: the acknowledgement path (`processAckQueue`,
  reached through `nrChan`) never consults that check at all, which reading the
  source settles in a few minutes. The real cause is two lines of go-l2tp
  v0.1.8 interacting — an ACK whose `Ns` is ahead of the peer's `Nr` is
  classified as neither in-sequence nor stale and therefore never dequeued, and
  `dequeueRxMessage` inspects `rxQueue[0]` inside a loop over `i` so it cannot
  look past a stuck head. veepin's only change is a comment and a test, which is
  the outcome this plan said would be acceptable.
- **Item 5 assumes OpenSSH tolerates trailing octets on a tun channel frame.**
  The argument is sound and identical to the one L2TPv3 and SoftEther already
  proved, but it is an argument, not a capture. If the cell says otherwise, SSH
  stays unshaped and the doc records why — and the docs would then be wrong in
  the *other* direction from how they are wrong today, which is worth noting as
  its own small lesson.
- **Item 7 assumes aioquic skips unknown capsules.** RFC 9297 requires it.
  Requirements and implementations are exactly what this project's interop
  matrix exists to distinguish, so the cell is the answer and the assumption is
  only a prediction.
- **Item 11 is scoped as a decision and may come back "no".** That is a real
  outcome, not a failure to plan — the Linux file already declined the same
  trade once, in writing.
- **It was already wrong about item 8, and that is the useful lesson here.** The
  first draft recommended Rosenpass on the strength of its shape without reading
  `rosenpass-plan.md` to its recommendation, which is *do not build this* — for a
  dependency reason no amount of effort removes. A plan in a tree that already
  contains a plan for the same thing should read that one first. Nothing
  guarantees the horizon list below has not made the same mistake somewhere; each
  entry names the doc it is arguing with, so the check is at least possible.

---

# Verification

Per commit, the full gate from [`AGENTS.md`](../AGENTS.md):

```sh
gofmt -l .                                   # must print nothing
go build ./... && go vet ./...
go test -race ./...                          # correctness
go test ./...                                # again: the AllocsPerRun guards skip under -race
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

Each of these exists because the obvious version of the test would pass for the
wrong reason:

| Item | What it must assert beyond the obvious |
|---|---|
| 1 — IKE fragmentation | `reassemble(fragment(x)) == x` over generated sizes, **and** that a peer which did not negotiate gets one whole message |
| 2 — RSA cert cell | `runInteropRequiringLog` naming the fragment count, with **IP fragmentation blocked in the peer container** so the kernel path is unavailable rather than merely unused |
| 3 — ql2tpd | If it cannot pass, the skipped test's comment gains what was **ruled out** |
| 5 — SSH shaping | Real `sshd` with `PermitTunnel`, padded, round-tripping — and `TestPadIsTrimmedByTheInnerTotalLength` |
| 6 — Nebula shaping | A handshake message through the shaper comes out **byte-identical**; padding goes inside the AEAD, not after the tag |
| 7 — MASQUE shaping | Real aioquic **skipping** the padding capsule, not veepin skipping its own |
| 10 — abandoned listener | A `Close` that blocks forever, with goroutine count **and** `/proc/self/fd` returning to baseline |
| 11 — macOS pf | `RecoveryCommand()` returns a real `pfctl` invocation, and the error path prints it |
