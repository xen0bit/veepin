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

**This plan is being executed.** The Status column below is the record; each
item's own section carries a *Landed* note naming what was actually built,
which is where the plan and the tree are reconciled when they disagree.

## Summary

### Part 1 — the client cannot be lived with

| # | Item | Value | Risk | Verdict | Status |
|---|------|-------|------|---------|--------|
| 1 | DNS is negotiated and then discarded | **High** | Low | **Do first** | ✅ landed |
| 2 | Nothing re-dials, though the machinery for it exists | **High** | Low | **Do** | ✅ landed |
| 3 | No kill switch: a dead tunnel fails open | Medium | Medium | Do, after 2 | ✅ landed |
| 4 | Split tunnel has no way to name a route | Medium | Low | Do | ✅ landed |
| 5 | `veepin probe` covers one protocol of seventeen | Low | None | Do (trivial) | ✅ landed |

### Part 2 — the server cannot be deployed

| # | Item | Value | Risk | Verdict | Status |
|---|------|-------|------|---------|--------|
| 6 | Seven facades accept exactly one user each — the engines don't | **High** | Low | **Do first** | ✅ landed |
| 7 | Secrets arrive as flags, so they are in `ps` | Medium | Low | Do | ✅ landed (with 9) |
| 8 | Nothing anywhere counts a byte | **High** | Low | **Do** | ✅ landed |

### Part 3 — structure and reach

| # | Item | Value | Risk | Verdict | Status |
|---|------|-------|------|---------|--------|
| 9 | 1,200 lines of flag switch restating the OptSpec tables | High | Medium | **Do** | ✅ landed |
| 10 | Sixteen protocols, one operating system | **Very high** | Medium | Do (macOS); don't (Windows) | ✅ landed (unverified on hardware) |
| 11 | Logging has no level and no shape | Low | Low | Fold into 9 | ✅ landed |
| 12 | `client_route.go` has no build tag and shells out to `ip` | Low | Low | Fold into 10 | ✅ landed |

### Part 4 — claims that have drifted

| # | Item | Value | Risk | Verdict | Status |
|---|------|-------|------|---------|--------|
| 13 | Two protocols do not meet the sentence at the top of the README | High | Low | **Do** | ✅ landed (the cell found a missing data path, which was then written) |
| 14 | Three protocol counts the docs guard cannot see | Low | None | Do (trivial) | ✅ landed |
| 15 | Two comments describing a tree that no longer exists | Low | None | Do (trivial) | ✅ landed |

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

### ✅ Landed

`dataplane/client_dns.go` holds the two backends behind a `dnsBackend`
interface, and `ClientRouter` applies one as its last Apply step and reverts it
as its first Revert step. `-no-dns` is the opt-out, `-no-route` still covers
both. `ClientRouter.DNSBackend()` names the mechanism that ran so the connect
log line can, which is the first thing anyone asks when resolution goes wrong.

Three things the writing changed from the proposal:

- **The split-tunnel case needed its own answer, which the plan did not give.**
  A full tunnel keeps only the tunnel's resolvers, because keeping any other is
  the leak. A split tunnel cannot do that — the names outside the tunnel still
  have to resolve, and `resolv.conf` has no way to say which server answers for
  which name — so the tunnel's go first and the host's follow. Under resolved
  the same distinction is the `~.` routing domain, claimed for a full tunnel
  only. Two tests pin each half.
- **`connect` deferred `Revert` only on a fully successful `Apply`**, so a
  failure partway through leaked whatever had already been installed. That was
  survivable when the state was two routes; with a rewritten `resolv.conf` in
  the set it is not. The defer is now registered before the error is examined,
  which `Revert`'s existing per-item guards already made safe.
- **The backup file is on disk, not just in memory.** A `SIGKILL` runs no
  defer; `/etc/resolv.conf.veepin.bak` is what the operator restores by hand,
  and the generated file names it in a comment so the recovery step is written
  on the thing they are already looking at.

Also worth naming: a server that offers no DNS at all now logs a warning on a
full tunnel, because that configuration resolves through the host's resolvers
and is indistinguishable from the bug just fixed unless it says so.

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

### ✅ Landed

`dialConnect` is now the loop and `oneSession` is the body: dial, apply, wait,
undo. `oneSession` returns how long the tunnel was up and whether the teardown
was intended, which is the only thing the loop needs to decide. `cmd/veepin/retry.go`
holds the backoff and the permanence rule, with the arithmetic tested rather
than eyeballed.

Four things the writing changed or added:

- **Option parsing was hoisted out of the loop.** A malformed option produces
  the identical error on every attempt, so retrying it prints the same line
  forever instead of telling the operator their config is wrong.
  `client.ValidateOptions` runs the same ParseFunc `Dial` does, so this costs a
  parse and changes nothing else.
- **The signal context is per-command, not per-session.** It was created inside
  the body, after routing; a Ctrl-C during a sixty-second backoff would have
  waited out the backoff. It is now created once, before the first attempt, and
  the backoff sleep selects on it.
- **The jitter is half-and-half rather than full.** A full-jitter draw of
  "somewhere in [0, nominal]" can come up near zero, which turns backoff into a
  tight loop against a server that is refusing connections. The floor at half
  the nominal keeps the randomisation — which is what stops a fleet re-dialling
  a restarted server in lockstep — without losing the property it is there for.
- **`ErrUnknownProtocol` joins `ErrAuth` as permanent.** It means a missing
  blank import, and no amount of waiting adds one.

The "routes come down between attempts" detail the plan flagged is not a
special case in the code: `oneSession`'s defers run on every path, so a re-dial
always starts from the host as it was. Item 3 is what makes that deliberate
rather than merely correct.

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

### ✅ Landed

`dataplane/client_killswitch.go`, `-kill-switch`, off by default. The switch is
created once per `connect`, outlives every session, and is disengaged by a
defer that runs on every path including a panic.

The proposal's mechanism turned out to be one step short, and the fix is the
interesting part:

- **It is armed while the tunnel is *healthy*, not in response to its death.**
  The blackholes are the same two `/1` halves `ClientRouter` installs, at a
  worse metric, so they are inert while the tunnel's own routes exist and take
  over the instant the kernel drops those routes with the device. Installing
  them on teardown — which is what "on an unintended teardown, replace the
  tunnel's default" describes — leaves however long the teardown takes as
  plaintext, which is exactly the window the flag exists to close.
- **A `/1` blackhole covers the VPN server too.** Without a carve-out, the
  reconnection loop item 2 just added could never reach the server it is
  retrying, and the kill switch would be a brick rather than a switch. The
  switch therefore holds its own host route to the server, at the same worse
  metric so it is a distinct route from `ClientRouter`'s and comes and goes
  independently.

Two configurations are refused rather than half-delivered, both permanently so
the retry loop does not repeat the refusal every sixty seconds:

- **A split tunnel**, which deliberately sends some traffic outside the VPN.
  There is nothing there to fail closed, and blackholing everything would break
  exactly the traffic the operator asked to keep outside.
- **A protocol whose `Result` carries no `Gateway`** — a mesh reaches peers at
  many underlay addresses, so there is no single route to carve out. This is
  the one worth refusing loudly: delivered, it is a host that cannot reconnect
  while looking like it is trying.

**The IPv6 gap is closed, and closing it reversed the first decision.** The
switch originally mirrored the families the tunnel carried, on the reasoning
that "blackholing IPv6 the tunnel never carried would break connectivity nobody
asked us to touch". That reads like restraint and is the leak: a v4-only tunnel
on a dual-stack host leaves every IPv6 packet going out the physical link, in
plaintext, while the operator has explicitly asked to fail closed. **A family
the tunnel does not carry is exactly a family that escapes it.**

So `halves()` returns both families always. Link-local and every other connected
route is more specific than a `/1` and is unaffected; a host with no IPv6 is
unaffected by two routes matching nothing it sends. What stops is traffic that
would otherwise have left by the physical default, which is the flag's whole
purpose. The connect log says so out loud when the tunnel is v4-only, because it
is a change to the host beyond what the tunnel carries and nobody should
discover it by finding IPv6 dead.

Writing that turned up a second defect the first shape had hidden: `Disengage`
ran `ip route del` for every half unconditionally, which was harmless only while
an unconfigured switch had an empty half-list. It is now gated on a `started`
flag — distinct from `engaged`, because `Engage` calls `Disengage` itself to
undo a partial install, and because `Disengage` is reached from a defer that
also runs where `Engage` was refused. Unguarded on a privileged process it would
have deleted four routes belonging to somebody else.

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

### ✅ Landed

`-route` and `-exclude`, both repeatable, parsed into `net.IPNet` on `Set` so a
typo is a command-line error naming the value rather than a route that quietly
never appears. `ClientRouter` installs them beside the routes it already owns
and records exactly what it installed, so `Revert` removes those and nothing
else — a prefix that was already present is left alone on the way out.

Three details the proposal did not cover:

- **`-route` with an explicit `-full-tunnel=true` is refused, not resolved.**
  The implication only fires when the operator did not say otherwise; two
  explicit and contradictory instructions are reported. Silently picking one is
  how someone ends up with routing they did not ask for.
- **`-exclude` alone leaves the full tunnel on.** Excluding a prefix *from* a
  full tunnel is the useful case, so only `-route` carries the implication.
- **A bare address is accepted** and read as a host route. `-exclude
  192.0.2.10` is what an operator will type, and refusing it over a missing
  `/32` helps nobody.

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

### ✅ Landed

Generic over the registry: dial, report the `Result`, close — with the close
deferred, because a probe that leaves a tunnel up is a `connect` with a worse
name. It reports the assigned addresses, the outer gateway, DNS and MTU, and
runs `Result.Validate`, printing what it complains about rather than failing on
it, exactly as `connect` does.

**ikev2 keeps its own path, and the branch says why.** The generic
implementation needs a TUN and therefore `CAP_NET_ADMIN`;
`internal/ikev2/probe` does the exchange with no TUN at all and runs
unprivileged, which is a strictly better answer to "does the handshake work"
and the reason it was written. Collapsing it to save a branch would take that
away from the one protocol that has it — so this went the other way from the
plan's suggestion of aliasing `probe` to `connect -no-route`, and the alias
would additionally have hidden the timeout that a diagnostic wants and a
long-lived tunnel does not.

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

### ✅ Landed

`internal/userdb` is the shared file reader, verifier and hasher; every one of
the eight facades takes `users-file` beside its `-user`/`-pass` pair, and where
a name is in both the command line wins. `veepin passwd` prints a bcrypt
verifier, reading the password from stdin rather than taking it as an argument
— a tool for keeping a password out of the process table should not be the
thing that puts it there.

Four things the writing changed from the proposal:

- **Eight facades, not seven, and the class boundary is one row off.** `ssh`
  collapses the same map and was not in the survey's grep because its
  assignment is spelled one key at a time, like sstp's. And the split is not
  "the three SSL-VPNs can hash": **Cisco XAuth and SSH password auth also carry
  the password itself**, so six protocols can hold a verifier and only the two
  MS-CHAPv2 ones cannot. The table in `doc/security.md` is written from the
  exchange rather than from the family name.
- **The class is enforced, not documented.** A bcrypt verifier in an MS-CHAPv2
  credentials file is refused at startup, naming the reason. Accepting it would
  produce a server that starts cleanly and rejects every login, with no message
  anywhere saying why — which is the shape of failure this whole plan is about.
- **`Required: true` came off `user` and `pass` on all eight.** It had become a
  false claim the moment a file could supply the same thing, and the panel
  renders that flag as an asterisk on a form. The parse still refuses to start
  with no credentials at all; the error names both ways to supply them.
- **Two engines compared passwords with `==`.** `internal/pulse` and
  `internal/cisco` both did, leaking the password's length by timing. Routing
  every comparison through `userdb.Verify` fixed that as a side effect of
  needing one place to decide "hash or plaintext".

The other half of the value is what did *not* change: the engines. Every one of
them already took a `Users` map and looked the username up in it, which is why
this was cheap — and why it was easy to keep not noticing.

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

### ✅ Landed (with item 9)

Nearly free, as predicted, once the flag set came from the specs: `Secret` on a
spec now also produces a `-<flag>-file` companion. Sixty-odd of them, from one
rule.

Three decisions in the writing:

- **It reads the file at parse time, not at collection time.** A file that
  cannot be read is then reported by `fs.Parse` alongside every other
  command-line error, rather than having to be threaded back through a
  collector whose whole signature exists to be simple.
- **Only the line terminator is trimmed.** `echo hunter2 > pass` is how every
  operator will create one of these and the newline it adds is not part of the
  secret — but a secret with leading or interior spaces *is* the secret, and
  trimming it would produce a login that fails with no explanation anywhere.
- **`Get()` returns the path, never the contents.** `-h` and every flag walker
  read a flag's value back, and a Getter that hands out key material is one
  that will eventually print some.

A spec whose `Kind` is already `OptFilePath` is skipped: its value *is* a path,
and `-key-file-file` would be nonsense.

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

### ✅ Landed

`dataplane/counters.go` holds `TunnelCounters` (four `atomic.Uint64` and a
last-seen), `DropReason`, and `PumpStats`. `Pump.Stats()` is the pump-wide
figure with drops by reason; `Pump.TunnelStats(t)` is one tunnel's.
`client.PeerInfo` grew `RxBytes`/`TxBytes`/`RxPackets`/`TxPackets`/`LastSeen`,
filled by the two protocols that implement `PeerDescriber`, rendered by the
panel, and exported by `GET /api/metrics`.

Where the counters sit, and what it cost:

- **Inbound is free.** `decapInbound` already resolves the demux key through
  `p.byKey`, so the counters live in that map's *value* — the lookup that was
  already happening now yields the tunnel and its counters together. The
  `AllocsPerRun` guards are the check that this stayed free, and they pass.
- **Outbound pays one pointer-keyed map read**, inside the `RLock` it already
  takes. The route trie stores a bare `Tunnel`, and threading counters through
  it would ripple into `routes_test.go` for no gain: the outbound path
  allocates in `Encapsulate` regardless, so it is not the path the guards pin.
  Named here because it is the one place this deviates from "not a keyed map".

Four things the writing found that the plan did not anticipate:

- **A rekey must not reset a peer's counters.** WireGuard re-registers the same
  `Tunnel` under a new inbound key every two minutes; counters keyed by the
  key rather than by the tunnel would have reset that often, and a byte total
  that resets every two minutes means nothing.
- **A removed tunnel's counts must be retained in the pump total.** A peer that
  disconnected still carried what it carried, and a counter that decreases is
  read by every time-series database as a counter *reset*.
- **Aggregating and segmenting paths must count inner packets, not datagrams.**
  IP-TFS puts several inner packets in one datagram and GSO turns one
  super-frame into many segments; counting the datagram would make both report
  a fraction of what they moved. Counted in the loop in each case.
- **A keepalive is an authenticated packet with no payload.** It must move
  last-seen — it is the proof of life — and must not move the byte count.

`PeerInfo.LastSeen` is the field the plan asked for and is worth naming
separately from `LastHandshake`: a peer that handshook an hour ago and has been
silent since is indistinguishable from a healthy one by handshake time alone.

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

### ✅ Landed

`cmd/veepin/optflags.go` generates both flag sets from the spec tables.
`connectFlags` and `serveFlags` are eleven lines each. Net: **1,366 lines
deleted, 196 added.** Item 7 came with it and is described below.

The de-risking was done by dumping every flag every protocol bound today —
name, type, default, help, and the key it reached, discovered by perturbation —
and diffing that against the spec tables before writing a line of the binder.
That dump answered the one question that decided the design:

- **`OptSpec.Default` and "the flag's default" are not the same claim.** The
  spec's `Default` is what the *protocol* does when the option is unset: 443 for
  an HTTPS port, `AES-256-GCM` for an OpenVPN cipher. Making that the value the
  CLI *emits* would have broken `veepin connect openvpn -config work.ovpn`,
  where the file names a cipher — an unset `-cipher` would have overridden it,
  and the operator would have got a cipher they never asked for with nothing
  saying so.

  So the flag *carries* `spec.Default` (which is what finally makes `-h` tell
  the truth about what happens when you say nothing) and the collector **omits
  any key still holding it and not explicitly passed**. An unset flag
  contributes nothing, exactly as the hand-written switch did; passing the
  default on purpose still emits it, which is how you override a config file
  with the stock value deliberately.

`OptSpec.Flag` is as proposed, and the dump found exactly thirteen options
needing it: `-pass` for the nine protocols whose key is `password`, ikev2's
`-server`/`-id`, and toy's `-insecure-shared-secret` (named to make the
insecurity hard to miss).

What it bought, against the plan's list:

- Step 4 of "Adding a protocol" is gone; it now reads "add a blank import".
- The two "spec keys and flags are the same set" guards collapsed into
  `TestTheFlagSetIsTheSpecTable`, which asserts the bridge rather than
  comparing two hand-written copies — plus one thing the old pair could not
  see: two specs claiming one flag spelling, which would bind one and silently
  drop the other.
- `-h` is uniform, and now prints real defaults. It also stopped printing them
  twice: a `Help` that spells "(default 500)" out is stripped, because the flag
  package appends its own.

Two things the plan did not anticipate:

- **The facade imports in `connect.go`/`serve.go` were load-bearing.** They
  looked like ordinary imports and were the registration side effect for
  thirteen of the seventeen protocols. They are now blank imports in `main.go`,
  which already claimed that role for the other four and now has the whole list
  in one place with the reason written above it.
- **The `-file` companions needed the perturbation guard taught about them**,
  not excluded from it. A companion takes a *path*, so the guard's sentinel
  string failed to open and the flag would have been reported as untestable
  rather than tested. It now hands them a real file, which keeps them inside
  the same guard as every other flag.

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

### ✅ Landed — and **unverified on hardware**, which is the important half

`dataplane/tun_darwin.go` (utun over `AF_SYSTEM`/`SYSPROTO_CONTROL`),
`client_route_darwin.go` (`ifconfig`/`route`) and `client_dns_darwin.go`
(`networksetup`). No cgo, no new dependency: everything came from `x/sys/unix`
except `SYSPROTO_CONTROL` and `UTUN_OPT_IFNAME`, which it does not export and
which are spelled out as constants naming the header they come from.

`GOOS=darwin go build ./...` and `go vet` pass. **That proves it type-checks and
nothing more — no one has run it.** `doc/verifying-macos.md` is the procedure
for the person who does, written in four steps ordered so that a failure names
which of the four independent things is wrong, and the README says "written, not
proven" rather than claiming macOS support.

Three things are refused rather than half-delivered, each naming why:

- **The kill switch.** The Linux one is armed while the tunnel is *healthy*,
  which depends on blackhole routes carrying a metric so two routes for one
  prefix can coexist and be ordered. The BSD table has no per-route metrics, so
  it could only be armed on teardown — which leaves the window the flag exists
  to close. The honest macOS answer is a `pf` anchor, which is the firewall
  ownership the Linux file already declines.
- **The layer-2 protocols.** No in-kernel TAP on macOS; the kexts that provide
  one cost the same claim wintun does.
- **GSO.** A Linux offload with no utun equivalent, and the pump already handles
  a device reporting none.

BSD is left as the next step and the file says what it would take: the same
`ifconfig`/`route` commands, the same 4-octet AF header, a different device open
(`/dev/tunN`) and `/etc/resolv.conf` — a backend that already exists.

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

### ✅ Landed

`-log-level` and `-log-format` on `log/slog`, in `cmd/veepin/logging.go`, plus
`internal/debuglog` for the one thing package `main` cannot hold.

**What the level can and cannot do is the honest part**, and it is written into
the file rather than left for someone to discover. The tree logs through
`*log.Logger`, which has no per-call level: every line a protocol writes is one
`Printf`. Reclassifying several hundred of those into `slog` calls is a far
larger change than a Low/Low item justifies, so the level is a gate on the
stream rather than a filter within it — `debug` adds protocol detail, `info` is
what the command always printed, and above `info` the informational stream is
suppressed.

That last part is useful rather than half-implemented only because of how this
command reports failure: a fatal error returns to `main` and is printed to
stderr by `run()`, never through the logger. So `-log-level=error` leaves errors
visible, which is what the person asking for it wants. The limitation to know
about is that a protocol logging a *non-fatal* problem through the same logger
is suppressed with the rest.

Two things beyond the proposal:

- **`text` is unchanged, deliberately.** A `slog` `TextHandler` renders every
  line as `time=… level=INFO msg="…"`, which is strictly worse to read at a
  terminal than the timestamped line this has always printed. Being able to
  *choose* json is the feature; being made to take structured text is not.
  `json` goes through `slog.NewLogLogger`, which hands back a `*log.Logger` —
  so the seventeen protocol packages need not know `slog` exists.
- **`internal/debuglog` replaces the environment variables.** `sstp` read
  `VEEPIN_SSTP_DEBUG` in three places because there was nowhere to put it, and
  one variable per protocol is not a design — it is what happens without one.
  `-log-level=debug` sets it; the old spellings still work, because they are
  what the interop entrypoints pass and the only route for a Go program
  embedding a protocol package directly.

`internal/mgmt`'s logging is untouched, so the "a successful GET is deliberately
not logged" rule the plan flagged never came into question.

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

### ✅ Landed

`client_route.go` is now `_linux`, `_darwin` and `_other`, with the shared
`ClientNetConfig` in an untagged `client_net.go` so every platform describes the
same thing and only the installing differs. The `_other` stub returns "not
supported on %s (Linux and macOS only)", which is the answer `tun_other.go` one
file over was already giving.

The claim is qualified rather than chased: the README now says "no *library*
dependencies", naming `ip`/`iptables`/`sysctl` and
`ifconfig`/`route`/`networksetup` as base-system tools it shells out to. Netlink
remains the better answer and remains not urgent.

One thing found on the way: `dataplane/pktconn_test.go` had no build tag and
reached into `pktconn_linux.go`'s internals, so the package failed to typecheck
off Linux. Nothing noticed because nothing had ever built the tree for another
platform.

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

### ✅ Landed — after the cell found something the plan did not expect

The headline sentence is qualified, the stale comment is corrected (item 15),
`TestInteropSoftEtherSelf` exists and passes (1.09 Gbit/s across the tunnel), and
`TestNoRowCarriesADashInTheSelfColumn` is the guard the plan asked for.

But the estimate was wrong in a way worth recording, because it is the whole
value of having built the cell rather than reasoning about it:

> **"SoftEther's self cell is a day's work" was wrong, and the reason was not
> effort.** The cell could not pass because SoftEther had no data path — at
> either end.

Two veepin clients connected, authenticated, addressed their TAPs, and no frame
crossed. The cause was two omissions that had been there since the protocol
landed:

```go
// softether/softether.go, Dial
tap, err := dataplane.OpenTAP(cfg.TUNName)
…
return &Session{cs: cs, tap: tap}, client.Result{…}, nil   // and nothing else
```

- **The client opened a TAP and started nothing.** No pump, no goroutine, no
  relay between the TAP and the TLS session. Every SoftEther tunnel came up,
  authenticated, reported an interface and carried nothing.
- **The server's switch forwarded between *sessions* only.** `forwardTo` walked
  the destination ports and looked each one up in the session table, so a port
  that was not a client had nowhere to be delivered to — and the server's own
  TAP was not a port at all. It was opened, named, and closed.

Both are now written. `internal/softether/local.go` puts the server's interface
on its own switch as an ordinary bridge port — learned, flooded to, excluded as
a source, exactly like a client's — and `deliver` is the one place that resolves
a port to somewhere to write, shared by the session path and the local one so
they cannot drift. The client runs two goroutines, because both directions
block and neither can be polled from the other's loop without starving it.

It is deliberately not `dataplane.Pump`: the pump routes layer-3 packets to a
tunnel by inner destination, and there is nothing to route here — every frame
goes to the one session and the switching happens at the far end.

**What this says about the matrix.** The row's three dashes were read for months
as "the cells have not been built yet". They meant "this protocol does not move
traffic". That is the difference a cell makes over a plan, and it is why the
Self-column guard now exists: a dash there was never about a peer being
unavailable, and treating it as a scheduling note is what let it hide a missing
data path.

The client and server columns are still `—‡`. They now wait on a real
cross-implementation cell against SoftEther VPN Server rather than on anything
missing in the tree.

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

### ✅ Landed

All three fixed, and `assertBareProtocolCounts` is the wider anchor.

The shape of the check matters more than the numbers. The obvious version — a
list of words to ignore before "protocols" — starts with "transport", "SSL-based"
and "selecting" and grows with the prose, which means it grows with every
sentence anyone writes and eventually stops catching anything. The version that
landed keys on a set of *spelled-out numbers* instead: a word that is not a
number is not this guard's business, and the set only grows if someone writes a
bigger number.

The two legitimate subset counts are declared with what they count
(`subsetProtocolCounts`), so an exemption is a claim someone wrote down and a
reader can check, rather than a number quietly allowed through.

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

### ✅ Landed

Both carry a *(landed)* block naming what changed, with the original text kept
above it — `protocol-roadmap.md`'s reasoning for why L2TPv3 went first does not
stop being the right decision because its premise was later fixed, and deleting
it would lose why the tree looks the way it does.

`interop.go`'s comment got more than a correction: writing item 13's cell
replaced "not yet proven against a peer" with the actual reason, which is that
SoftEther's client has no data path. That is the difference between a comment
that ages and one that explains.

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

---

# What actually happened

Every item is landed. Nine commits, one per item or per pair the plan grouped,
each green before the next started.

| # | Item | Outcome |
|---|------|---------|
| 1 | DNS | ✅ two backends, `-no-dns` opt-out |
| 2 | Reconnection | ✅ jittered backoff, `ErrAuth` never retried |
| 3 | Kill switch | ✅ armed while healthy, not on teardown |
| 4 | Split-tunnel routes | ✅ `-route` / `-exclude` |
| 5 | Generic `probe` | ✅ over the registry; ikev2 keeps its unprivileged path |
| 6 | More than one user | ✅ `-users-file`, eight facades, bcrypt where the protocol allows |
| 7 | Secrets in `ps` | ✅ `-<flag>-file` for every `Secret` spec |
| 8 | Counters | ✅ per tunnel, drops by reason, `/api/metrics` |
| 9 | Generated flags | ✅ **1,366 lines deleted, 196 added** |
| 10 | macOS | ✅ written; **unverified on hardware**, and CI says only that it compiles |
| 11 | Logging | ✅ `-log-level` / `-log-format`, with the level's real limits written down |
| 12 | Route build tags | ✅ `_linux` / `_darwin` / `_other` |
| 13 | Drifted claims | ✅ headline qualified, and the cell found + fixed a missing data path |
| 14 | Stale counts | ✅ fixed, and the guard widened by number rather than by ignore-list |
| 15 | Stale comments | ✅ *(landed)* markers, original text kept |

## Where the plan was wrong

Worth recording, because a plan that is never contradicted was not specific
enough to be useful.

- **Item 13 was the big one.** "SoftEther's self cell is a day's work" was
  wrong, and not about effort: building it found that neither end had a data
  path. The client opened a TAP and started nothing; the server's switch
  forwarded between sessions only, with its own TAP not on the switch at all.
  Both were written, and the cell now passes. The row's three dashes had been
  read for months as "not built yet" and meant "does not move traffic" — which
  is the difference between running a cell and reasoning about one.
- **Item 6 counted seven facades; there are eight**, and the class boundary was
  one row off: Cisco XAuth and SSH password auth also carry the password, so six
  protocols can hold a bcrypt verifier and only the two MS-CHAPv2 ones cannot.
- **Item 3's mechanism was one step short.** "On an unintended teardown, replace
  the tunnel's default" leaves the teardown's own duration as plaintext. The
  switch has to be armed while the tunnel is *healthy*, at a worse metric.
- **Item 5 suggested aliasing `probe` to `connect -no-route`.** That would have
  taken the unprivileged, TUN-less path away from the one protocol that has it.
- **Item 9's `OptSpec.Default`** could not become the emitted value, only the
  flag's default, or an unset `-cipher` would silently override a `.ovpn` file.

## What is owed next

1. **Run `doc/verifying-macos.md` on a Mac.** The client is written and
   compiles; nobody has run it. Until someone does, macOS is "written, not
   proven" and the README says so.
2. **A SoftEther cell against SoftEther VPN Server.** The data path is written
   and the self cell passes; the two cross-implementation columns now wait on a
   peer image and the address assignment, since every client is still handed
   the constant `10.70.0.2`.
3. **A pf-based kill switch for macOS.** The route-based one cannot work there
   (no per-route metrics), so `-kill-switch` refuses. A pf anchor is the honest
   answer and means owning firewall state on the user's host — the same trade
   the Linux implementation declined, and worth revisiting only deliberately.
4. **Per-call log levels.** `-log-level` gates the stream because the tree logs
   through `*log.Logger`. Making `warn` mean something *within* the stream is a
   `slog` migration of several hundred call sites.
