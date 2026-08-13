# Operability plan: what to fix before the next protocol

Written after the management plane, the client-config generator and the panel's
browser suite landed (#76–#80), and before deciding what protocol comes next.
[`consolidation-plan.md`](consolidation-plan.md) asked what was *wrong* in the
tree. This asks a different question: **what stops a person actually running
this on their own machine and their own server.**

The answer is not that a protocol is missing. Sixteen is more than any of the
implementations veepin is tested against speaks, and
[`protocol-roadmap.md`](protocol-roadmap.md) is honest that the SSL-VPN seam is
mined out. The answer is that the tree is protocol-complete and
operability-incomplete: the handshakes are verified against real peers, and
almost everything *around* the handshake — DNS, reconnection, more than one
user, knowing whether a byte moved — is either absent or built and unreachable.

Everything below is grounded in the tree as it stands, with the survey command
included so each finding can be re-checked rather than taken on trust.

## Summary

### Part 1 — the client cannot be lived with

| # | Item | Value | Risk | Verdict |
|---|------|-------|------|---------|
| 1 | DNS is negotiated and then discarded | **High** | Low | **Do first** |
| 2 | Nothing re-dials, though the machinery for it exists | **High** | Low | **Do** |
| 3 | No kill switch: a dead tunnel fails open | Medium | Medium | Do, after 2 |
| 4 | Split tunnel has no way to name a route | Medium | Low | Do |
| 5 | `veepin probe` covers one protocol of seventeen | Low | None | Do (trivial) |

### Part 2 — the server cannot be deployed

| # | Item | Value | Risk | Verdict |
|---|------|-------|------|---------|
| 6 | Seven facades accept exactly one user each — the engines don't | **High** | Low | **Do first** |
| 7 | Secrets arrive as flags, so they are in `ps` | Medium | Low | Do |
| 8 | Nothing anywhere counts a byte | **High** | Low | **Do** |

### Part 3 — structure and reach

| # | Item | Value | Risk | Verdict |
|---|------|-------|------|---------|
| 9 | 1,200 lines of flag switch restating the OptSpec tables | High | Medium | **Do** |
| 10 | Sixteen protocols, one operating system | **Very high** | Medium | Do (macOS); don't (Windows) |
| 11 | Logging has no level and no shape | Low | Low | Fold into 9 |
| 12 | `client_route.go` has no build tag and shells out to `ip` | Low | Low | Fold into 10 |

### Part 4 — claims that have drifted

| # | Item | Value | Risk | Verdict |
|---|------|-------|------|---------|
| 13 | Two protocols do not meet the sentence at the top of the README | High | Low | **Do** |
| 14 | Three protocol counts the docs guard cannot see | Low | None | Do (trivial) |
| 15 | Two comments describing a tree that no longer exists | Low | None | Do (trivial) |

The ordering within each part is by value. Across parts, items 1, 2, 6 and 8 are
the ones that change whether the software can be used; everything else is
sharpening.

---

# Part 1: the client cannot be lived with

## 1. DNS is negotiated and then discarded

```sh
grep -rn "DNS" dataplane/client_route.go
# dataplane/client_route.go:21:  DNS []net.IP // informational; resolv.conf changes are left to the caller
```

Every protocol here that can learn DNS servers from the server does learn them.
`client.Result.DNS` carries them, `cmd/veepin/connect.go:223` passes them into
`ClientNetConfig`, and `ClientRouter.Apply` never reads the field. The comment
says the caller will do it; `cmd/veepin` **is** the caller, and it does not.

So the default invocation — `veepin connect <proto>`, full tunnel — sends every
packet through the VPN while resolving names through whatever resolver the host
had before the tunnel came up. Two consequences, and the second is the one that
matters:

- Names that only exist inside the tunnel do not resolve. The tunnel looks
  broken to anyone who reaches their internal hosts by name, which is most
  people who run a VPN at all.
- **Every query leaks.** The observer the tunnel exists to defeat still sees the
  full list of names, in plaintext, from the host's real address. A full-tunnel
  VPN that leaks DNS by default is worse than no tunnel in one specific way: the
  user believes otherwise.

**Proposed.** Apply DNS in `ClientRouter.Apply`, revert it in `Revert`, beside
the routes it already owns — the two have identical lifetimes and identical
failure modes, and splitting them across two components is what produced this.
Two backends, chosen by what the host runs:

- `systemd-resolved` present (`/run/systemd/resolve/` exists): `resolvectl dns
  <tun> …` and `resolvectl domain <tun> ~.` for a full tunnel. This is the only
  correct answer on a modern desktop, because resolved will otherwise keep
  answering from the other link's servers no matter what `/etc/resolv.conf`
  says.
- Otherwise: rewrite `/etc/resolv.conf`, having copied the original aside, and
  restore it on teardown. Detect a file that is a symlink into `/run` and refuse
  rather than clobber it.

**The alternative not taken** is a `-dns` flag that makes it opt-in. That keeps
the leak as the default, which is exactly the shape of bug this tree calls
silent: the tunnel comes up, traffic flows, and the thing the user wanted did
not happen. Opt out (`-no-dns`) for the person who manages their own resolver.

**Risk:** low, and contained. It touches one file, and the revert path is
already exercised by the same defer that reverts routes.

## 2. Nothing re-dials, though the machinery for it exists

```sh
grep -rn "reconnect\|backoff" --include=*.go client/ cmd/veepin/
# client/liveness.go:32:  (or a supervising reconnect loop) can re-dial. …
```

That comment describes a caller that does not exist. `client.Dial` attaches a
liveness monitor to every protocol that implements `client.Prober`, the monitor
detects a dead peer and ends the session — and `dialConnect`
(`cmd/veepin/connect.go:250`) logs why the session ended and returns to the
shell.

The result is that the cross-protocol liveness work, which the README describes
at length as a feature, currently converts a recoverable event into a permanent
one. A laptop that changes Wi-Fi networks, a phone tether that drops for four
seconds, a server that restarts — each ends the tunnel for good, and the user
finds out later.

**Proposed.** A retry loop around the dial in `dialConnect`: exponential
backoff, jittered, capped (1s → 60s), reset on a session that stayed up past
some threshold. Two flags, `-retry` (default **on** — see below) and
`-retry-max` for a bounded attempt count in scripts and CI.

Three details that decide whether this is any good:

- **`client.ErrAuth` must not be retried.** A wrong password retried with
  backoff is a lockout on any server that counts failures, and the error type
  that distinguishes it already exists precisely so callers can tell.
- **Routes come down between attempts, unless item 3 lands.** Leaving a default
  route pointed at a dead TUN blackholes the host, which is a worse failure than
  the one being recovered from — and is *also* the correct behaviour once there
  is a kill switch to make it deliberate. Sequence 3 after 2 for that reason.
- **Default on.** A VPN client that gives up on the first blip is not a VPN
  client. `-retry=false` for the person scripting it.

**Risk:** low. Additive around an existing call, and the failure it introduces
(retrying something that should have stopped) is visible in the log rather than
silent.

## 3. No kill switch: a dead tunnel fails open

When the session ends, `Revert` restores the pre-VPN default route and traffic
resumes in plaintext. That is the right behaviour for `Ctrl-C` and the wrong one
for a tunnel that died on its own: the user asked for their traffic to go
through the VPN, and it silently stopped doing so.

**Proposed.** `-kill-switch`: on an *unintended* teardown, replace the tunnel's
default with a blackhole route rather than restoring the physical one, and hold
it until either a re-dial succeeds or the process exits cleanly. The distinction
between intended and unintended teardown is already in hand — `dialConnect`
separates `context.Canceled` from everything else to write its log line.

Off by default: a kill switch that engages when the user did not ask for one
strands a machine they may only be able to reach over the network they just
blackholed. On, it must be reverted by a `defer` that runs even on panic.

**The alternative not taken** is firewall rules (nftables/iptables) scoping
egress to the tunnel interface. That is what a mature client does and it is
strictly better — it also covers processes that bind a source address — but it
means owning firewall state on the user's host, which is a much larger promise
than owning two `/1` routes. A blackhole route is the honest version of what
this tree already does.

**Risk:** medium, and it is the risk of stranding a host. It wants a loud log
line and a documented recovery command.

## 4. Split tunnel has no way to name a route

```
-full-tunnel=false   only bring up the interface/address; add your own routes
```

There is no flag with which to add any. `-full-tunnel=false` brings up the
interface and leaves the user at a shell with `ip route` — which is a reasonable
thing to offer an operator and not a feature. Meanwhile the protocols that
*have* a native answer (WireGuard's `allowed-ips`) express it per-protocol, so
there is no one way to say "route these prefixes and nothing else".

**Proposed.** `-route <cidr>` and `-exclude <cidr>`, both repeatable, applied by
`ClientRouter` alongside the routes it already installs. `-route` implies
`-full-tunnel=false`. `-exclude` installs a more-specific route via the physical
gateway, which is the same mechanism as the existing server host route and
should share its code.

**Risk:** low. The trie in `dataplane/routes.go` already does longest-prefix
matching for the inbound side; this is host routing table state, added and
reverted the same way the two `/1` halves are.

## 5. `veepin probe` covers one protocol of seventeen

```go
// cmd/veepin/probe.go:18
if protocol != "ikev2" {
    return fmt.Errorf("unknown protocol %q (available: ikev2)", protocol)
}
```

`main.go`'s usage block and the README both present `probe` as a subcommand that
takes a protocol, in the same shape as `connect` and `serve`, which are generic
over the registry. It is a diagnostic that answers "does the handshake work
without touching my routing table", and that question is worth answering for the
other sixteen.

**Proposed.** Implement it over the registry: `client.Dial`, log the `Result`,
close. That is `dialConnect` with routing skipped, which `-no-route` already
does — so the honest version of this item may be that `probe` should become an
alias for `connect -no-route -probe-once` rather than a third code path. Decide
that when writing it; either way it should stop naming one protocol.

**Risk:** none. Worst case it stays ikev2-only and the usage text says so.

---

# Part 2: the server cannot be deployed

## 6. Seven facades accept exactly one user each — the engines don't

```sh
grep -rn "cfg.Users = map\[string\]string{" --include=*.go . | grep -v internal/
# l2tp/server.go:204   cisco/server.go:257   gp/server.go:275
# anyconnect/server.go:263   pulse/server.go:278   fortinet/server.go:296
# (plus sstp/server.go:577, which fills the same map one key at a time)
```

Every one of those engines takes a `Users map[string]string` and looks the
username up in it. `internal/gp/server.go:156` even refuses to start with an
empty map. The multi-user server is written, tested, and interop-verified — and
then each facade collapses it to a single pair on the way in, because the only
thing the option surface can express is `-user` and `-pass`.

The consequence is that veepin's password protocols serve exactly one person.
Not "one person by default": one person, with no way to say otherwise short of
running a second listener on a second port. For the SSL-VPN protocols
(AnyConnect, Fortinet, GlobalProtect, Ivanti) that is the entire deployment
model those protocols exist for.

**Proposed.** A `users` option beside the existing pair. `wireguard`'s
`OptServerPeers` is the precedent for a repeated entity in this option surface —
one string holding a JSON array, written and rewritten by the client-config
generator — and it is the precedent for the *plumbing* rather than the format:
the panel, the profile store, `RegisterServerOpts` and the PATCH path all carry
it with machinery that exists. A password file wants the opposite of an inline
value, though, because the whole point of item 7 is to keep credentials out of
the option map. So: a path to a file of `username:secret` lines, `Secret: true`
because it is a path to key material, read at startup. Keep `-user`/`-pass` as
the one-user shorthand; they are what every runbook and interop cell passes.

Store a hash rather than the password wherever the protocol permits it.
AnyConnect, Fortinet and GlobalProtect compare a plaintext password and can hold
a bcrypt/scrypt verifier instead. MSCHAPv2 (SSTP, L2TP) and SoftEther cannot —
the response is computed *from* the password — and `doc/security.md` should say
which protocols are in which class rather than leaving the reader to infer it
from a file format.

**Risk:** low. Additive; the single-user path stays exactly as it is and every
interop cell keeps passing unchanged.

## 7. Secrets arrive as flags, so they are in `ps`

`veepin serve gp -user alice -pass hunter2` puts the password in the process
table for every local user, in the shell history, and in
`/etc/veepin/<name>.conf` where the systemd unit reads it. The listener JSON the
supervisor writes is at least 0600 and redacted on the API
(`internal/confstore/confstore.go:206`, `client.Redact`) — the flag path has
neither protection.

**Proposed.** A `-pass-file`/`…-file` companion for every option a spec marks
`Secret`, read at startup. Because `Secret` is already declared in the OptSpec
tables, this is one generic rule rather than seventeen flags — **and it is
nearly free once item 9 generates the flag set from those specs.** Sequence it
after 9 for that reason; doing it before means writing the same companion flag
by hand in seven `case` blocks that are about to be deleted.

**Risk:** low.

## 8. Nothing anywhere counts a byte

```sh
grep -rn "RxBytes\|TxBytes\|BytesIn\|BytesOut\|/metrics" --include=*.go . | wc -l
# 0
```

`client.PeerInfo` (`client/server.go:117`) carries ID, address, state and last
handshake. The management panel can therefore tell an operator that a peer
handshook and nothing about whether it has moved a packet since. The one
question every VPN operator asks — *is this thing actually carrying traffic* —
has no answer anywhere in the tree, including in the logs.

This is also the missing half of the shaping and throughput work: `bench.sh` and
the interop iperf3 table measure the data path in a lab, and a running server
reports nothing.

**Proposed, in two layers:**

- **Per-tunnel counters in `dataplane.Pump`** — packets and bytes each way, plus
  drops by reason (the pre-built sentinels on the drop path already enumerate
  the reasons). `atomic.Uint64` incremented on a path that is currently
  allocation-free, so the `AllocsPerRun` guards in each `datapath_test.go` are
  the check that this stayed free.
- **`PeerInfo.RxBytes`/`TxBytes`/`LastSeen`**, rendered by the panel, plus
  `GET /api/metrics` in Prometheus text format. Stdlib only — the format is a
  dozen lines to emit and `internal/mgmt`'s dependency contract already forbids
  the client library.

**Risk:** low, with one thing to watch: counters on the hot path are exactly
where a careless `map[string]uint64` lookup per packet would undo the
allocation-free inbound path. Per-tunnel struct fields, not a keyed map.

---

# Part 3: structure and reach

## 9. 1,200 lines of flag switch restating the OptSpec tables

```sh
awk '/^func connectFlags/,/^}$/' cmd/veepin/connect.go | wc -l   # 584
awk '/^func serveFlags/,/^}$/'   cmd/veepin/serve.go   | wc -l   # 616
```

Both functions are one `case` per protocol, each binding flags whose name, type,
default and help text are already declared — in the OptSpec tables the same
protocol registers through `RegisterClientOpts`/`RegisterServerOpts`, which
additionally carry `Required` and `Secret` that the flags do not.

The tell is in AGENTS.md's own guard table. **Four of the mechanical guards
exist solely to hold these two copies against each other**:
`TestClientOptSpecsMatchTheKeysTheProtocolReads`,
`TestRequiredClientOptsAreTheOnesTheParseRejects`,
`TestSecretFlagsAgreeAcrossBothTables`, and
`TestEveryOptConstIsDescribedByAnOptSpec` — the last written because the two
flag-driven guards were blind to an option the parse read that no flag emitted.
Guards that check two hand-maintained copies agree are evidence of the
duplication, not a remedy for it, and this one has already leaked bugs through:
the `-set` key check in `applyOverrides` exists because
`-set server=…` was accepted, changed nothing, and dialled the old gateway.

**Proposed.** Generate the flag set from the specs. `OptSpec` gains one field:

```go
// Flag is the command-line spelling when it differs from Key. ikev2's key is
// "gateway" and its flag has always been -server; renaming either would break
// every runbook or every profile on disk, so the mapping is declared instead of
// inferred.
Flag string
```

`connectFlags`/`serveFlags` become one function each, walking
`ClientOptsFor(protocol)` and binding by `Kind`. What this buys, in order of
value: step 4 of "Adding a protocol" disappears; the four sync guards collapse
to one that has nothing left to disagree with; `-h` becomes uniform across
seventeen protocols instead of seventeen hand-written prose styles; and item 7
becomes a rule rather than seven flags.

**The alternative not taken** is leaving it and tightening the guards further.
That is where the last two rounds went, and the result was a fourth guard.

**Risk:** medium — this is the CLI's entire surface. It de-risks itself: the
existing `flags_test.go` perturbs every bound flag and requires the option map
to change, so it holds the *current* behaviour against the generated one. Land
it one subcommand at a time (`connect`, then `serve`), and diff `-h` output
before and after for all seventeen.

## 10. Sixteen protocols, one operating system

```sh
head -1 dataplane/tun_other.go        # //go:build !linux  → every entry point errors
```

Sixteen protocols, both roles, all of them usable only on Linux. For the server
that is a defensible scope. For the client it is the difference between a VPN
people use and a VPN people read about: the machines that dial a VPN are laptops,
and most laptops are not Linux.

The seam is already isolated — `dataplane/tun_other.go` is the whole of the
device abstraction off Linux, and it is small.

- **macOS is reachable and keeps the thesis.** `utun` is `socket(AF_SYSTEM,
  SOCK_DGRAM, SYSPROTO_CONTROL)` plus a `ctl_info` ioctl, all of which
  `x/sys/unix` already exposes. Packets carry a 4-octet AF header, which is the
  same shape as the `IFF_NO_PI` flag this tree already reasons about. No cgo, no
  new dependency. Routing is `route` and `scutil`/`networksetup` for DNS, which
  is the same shelling-out `client_route.go` already does.
- **FreeBSD/OpenBSD are nearly free** once the AF-header handling from macOS
  exists.
- **Windows is not.** wintun is a DLL, so it costs the "no runtime dependencies"
  claim and the pure-Go one in spirit. Out of scope until someone wants it
  enough to argue the trade.

**Risk:** medium, and mostly in what cannot be tested here — the interop harness
is Docker, so a macOS data path is verified by a person with a Mac, in the shape
`doc/verifying-shaping.md` already describes for vendor clients. Write that
procedure alongside the code.

## 11. Logging has no level and no shape

```sh
grep -rn "log-level\|\"verbose\"\|slog" --include=*.go . | wc -l   # 0
```

One `*log.Logger` at `LstdFlags|Lmicroseconds` everywhere, no level, no
structure, and one ad-hoc per-protocol escape hatch (`VEEPIN_SSTP_DEBUG`,
`sstp/sstp.go:105`) that exists because someone needed exactly this and there
was nowhere to put it. The supervisor's log ring
(`internal/mgmt/logring.go`) then serves those lines to the panel as free text.

**Proposed.** `-log-level` and `-log-format json`, on `log/slog` (stdlib, so the
dependency contract is untouched). Fold into item 9: both are the CLI's flag
surface, and doing them together means one pass over the two subcommands.

**Risk:** low. The one thing worth pinning is that `internal/mgmt`'s "a
successful GET is deliberately not logged" rule survives the port — that
exclusion is what keeps the ring usable, and its reasoning is written down in
`internal/mgmt/README.md`.

## 12. `client_route.go` has no build tag and shells out to `ip`

```sh
head -1 dataplane/client_route.go     # package dataplane   ← no build tag
```

So it compiles on every platform and fails at runtime with
`exec: "ip": executable file not found`, rather than the clean
"not supported on darwin (Linux only)" its neighbour `tun_other.go` returns. A
`_linux` suffix and a stub is fifteen minutes and belongs with item 10.

Separately: the README calls the `veepin` package one with "no runtime
dependencies" while this file shells out to `ip` and `internal/hostnet` to
`iptables` and `sysctl`. Either qualify the claim or move to netlink — `x/sys`
is already a dependency and speaks it. Qualifying is the cheaper honest answer;
netlink is the better one and is not urgent.

---

# Part 4: claims that have drifted

## 13. Two protocols do not meet the sentence at the top of the README

> …**sixteen production protocols, client and server for every one** — […] each
> verified in Docker against a real third-party implementation *and* against
> itself.

AGENTS.md calls that sentence the whole thesis. The matrix twelve screens below
it disagrees for two rows:

- **SoftEther** is `—‡` in all three columns, *including self*
  (`internal/livingreadme/interop.go:186`). The file's own comment says a dash
  in the Self column "is never earned", because a veepin↔veepin cell is always
  possible. Its README additionally states there is no TAP data path — the
  server switches frames between connected clients and nothing bridges them to
  the host — and that every client is assigned the constant `10.70.0.2`.
- **L2TPv3** is `✗` in both real-peer columns (the kernel cells need `l2tp_eth`,
  which GitHub runners lack), and its control connection is unit-tested only.

Two of sixteen. The honest options are to finish the cells or to qualify the
sentence, and they are not equally cheap: **SoftEther's self cell is a day's
work and is unambiguously owed.** The client/server columns need the TAP data
path first, which is a real project. L2TPv3's `✗` is a runner limitation rather
than a defect and is arguably already disclosed by its label — but "verified
against a real third-party implementation" is not true of it in CI, and the
README sentence does not carry the caveat the matrix does.

**Proposed.** Build `TestInteropSoftEtherSelf`; qualify the headline sentence to
name the exceptions the matrix already names; and consider a guard —
`internal/livingreadme` is exactly the place — asserting that no row carries a
dash in the Self column, since the comment already says that is never legitimate
and a comment is not a check.

## 14. Three protocol counts the docs guard cannot see

```sh
grep -n "ten real protocols\|other nine protocols\|seven of the nine" README.md
# 107:  …Only MASQUE imports it; the other nine protocols…      → fifteen
# 328:  …It is not one of the ten real protocols…               → sixteen
# 625:  …on seven of the nine protocols…                        → twelve of sixteen
```

`TestREADMECountsProtocolsCorrectly` anchors on the exact phrases "production
protocols" and "registered protocol", so these three are invisible to it. The
third is doubly stale: twelve facades register a shaping option today
(`grep -rln "OptShape\|OptServerShape" --include=*.go */ | cut -d/ -f1 | sort -u`),
so the sentence understates what the tree does.

Fix the numbers, and widen the guard's anchors to catch a bare spelled-out
number followed by "protocols" — the failure mode here is not that the number
was wrong when written, it is that nothing was watching it.

## 15. Two comments describing a tree that no longer exists

- `doc/protocol-roadmap.md:64-68` states that `internal/softether/switch.go` "is
  still unwritten" and that `dataplane/tun_linux.go`'s `OpenTAP` is called by
  nothing. Both were true when written and are now false: the file exists with
  its own tests, and `internal/l2tpv3` calls `OpenTAP`.
- `internal/livingreadme/interop.go:179` says "SoftEther and AmneziaWG are
  implemented but not yet proven against a peer" — directly above the AmneziaWG
  row that now names three passing cells against `amneziawg-go`.

Both are in files whose entire purpose is to be the truthful record. Landed
plans are kept here deliberately (`protocol-roadmap.md` says so), so the fix is
a *(landed)* marker and a corrected sentence, not a deletion.

---

## Explicitly out of scope

- **Another protocol.** Everything above is worth more than a seventeenth row,
  and several items get harder with each row added — item 9 most of all.
- **Rewriting any data path.** Every one of them is interop-verified; none is
  asking to be rearchitected. Item 8 adds counters to the pump and must leave
  its allocation behaviour alone, which the existing guards will enforce.
- **Windows.** See item 10.
- **A user database with groups, RADIUS or SSO.** Item 6 is "more than one
  user", which is the gap between unusable and usable. Everything past that is
  product work and should wait for someone who actually wants it.
- **The `nm/` plugin.** It consumes `client.Result` and the option specs, so it
  inherits items 1 and 9 for free and needs no separate plan. NetworkManager
  already applies DNS itself, which is part of why item 1 went unnoticed for so
  long: the desktop path was fine and the CLI path was not.

## Sequencing

Each lands on its own so a regression is attributable, and each is green before
the next starts.

1. **Item 1 — DNS.** Smallest change with the largest effect on whether the
   client is usable, and it fixes a leak. One file.
2. **Item 6 — more than one user.** Same shape of finding on the server side:
   the capability is built and unreachable, and the fix is additive.
3. **Item 2 — reconnection**, then **item 3 — the kill switch** on top of it.
   In that order: the kill switch is what makes "routes stay down between
   attempts" deliberate rather than a bug.
4. **Item 8 — counters and `/api/metrics`.** Independent of everything above;
   could run in parallel if it were not for the allocation guards wanting a
   quiet tree.
5. **Item 9 — generate the flags**, carrying **item 11** and then **item 7**
   with it. The largest structural change, and the one that makes each
   subsequent protocol cheaper.
6. **Item 10 — macOS**, with **item 12** folded in.
7. **Items 13, 14, 15 — the drifted claims**, plus the two new guards (no dash
   in the Self column; spelled-out counts). Cheap, and they can be picked up
   whenever a PR is otherwise waiting.
8. **Items 4 and 5** — split-tunnel routes and a generic `probe`. Real, small,
   and nothing depends on them.

**If only three things happen: 1, 2 and 6.** DNS and reconnection are what turn
`veepin connect` from a demonstration into something a person can route a laptop
through, and multi-user is what turns `veepin serve` from a single-seat listener
into a server. Every one of the three is a capability the tree already has and
does not expose — which is why they are cheap, and also why they are easy to
keep not noticing.
