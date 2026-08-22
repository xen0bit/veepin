# internal/supervisor

Runs several `client.Server` instances in one process and reconciles them to a
directory of JSON files.

`veepin serve <proto>` constructs exactly one server and blocks on it. The
supervisor keeps a set of them, each in its own goroutine, and can rebuild one
without disturbing the others.

```
  <config dir>/                     Manager
    site-a.json   ──LoadDir──▶  ┌─────────────────────────────┐
    branch.json                 │ listeners map[string]*running│
    mgmt/token                  └──────────────┬──────────────┘
                                               │ one goroutine each
                                   ┌───────────┴───────────┐
                                   ▼                       ▼
                            client.Server            client.Server
                            (ListenAndServe)         (ListenAndServe)
```

## The unit of change is the file

`ListenerConfig` is one JSON file. `Apply` reconciles the live set to whatever
`LoadDir` reports: new files are built, deleted files are torn down, changed
files are cold-rebuilt, disabled files are stopped, untouched files keep
running. It is called on startup, on `SIGHUP`, and by the management API after
a write.

A change is a **cold rebuild** — Close, `NewServer`, `ListenAndServe` again —
because that is what the `client.Server` contract permits. There are no runtime
mutation methods on a `Server`, deliberately: configuration is validated once at
construction, so reconfiguration is reconstruction.

## Locking

Two locks, with one rule that is easy to get wrong.

`Manager.mu` guards the listeners map. `running.mu` guards **every** field on a
listener handle, on every path. That second one is stricter than the call graph
makes it look, and it has to be: `Manager.Status` looks a handle up under
`Manager.mu` and then *releases it* before reading the handle, so `Manager.mu` is
not a second layer of protection over those fields the way it is over the map.

`running.done` doubles as a generation marker. `stopListener` clears it, so a
serve goroutine that returns late — after a rebuild installed a new server, or
after the stop gave up waiting — can tell its outcome is stale and decline to
publish it over the live listener's state.

## Host networking

Everything that mutates host state is `internal/hostnet`, called from here. This
package is the caller that the `NewServer installs no host state` contract
assumes: `NewServer` opens the TUN and validates, the supervisor installs the
address, forwarding, and the `veepin:<name>`-tagged iptables rules, and takes
them back out on rebuild and delete.

`Manager.SetCommander` swaps the external command runner, so the host-networking
half of a build is testable without privileges — the same shape as the pluggable
`Constructor` that covers the server half.

## Caveats

**A listener whose `Close` blocks is abandoned, not waited for.**
`Close` is called on a goroutine and waited for with a bound (`stopGrace`, 5s) —
an unbounded wait would freeze every other listener's status and rebuild behind
it. The original cause is fixed: `dataplane`'s TUN fd is held non-blocking and
polled against a wake eventfd, so a `Close` waiting on its packet pump unblocks
instead of hanging on an idle tunnel. But `Close` can still stall on any other
blocking path a protocol owns (a wedged control connection, a peer that never
answers), and past the bound the listener is logged and abandoned, which
**leaks its pump goroutine and TUN fd until that listener's `Close` finally
returns** — or until the process exits, if it never does. Repeatedly restarting
a genuinely wedged listener accumulates both.

That is still a leak, and it is not one this package can close: the blocking
path belongs to whichever protocol owns it. What this package does is stop the
leak being invisible. `Manager.Abandoned` reports a gauge (how many right now)
and a cumulative counter (how many ever), `/api/metrics` exports both as
`veepin_listeners_abandoned` and `veepin_listeners_abandoned_total`, and a
reaper keeps watching each abandoned teardown so a `Close` that eventually
returns brings the gauge back down while the counter keeps the record. Before
this the only trace was a log line, and a fleet accumulating a descriptor per
restart had nothing an operator could alert on.

Both counters are atomics rather than fields under `Manager.mu`, and that is a
correctness constraint rather than a performance one: `stopListenerLocked` runs
with `mu` held, so touching it from the abandonment path deadlocks the manager —
which `TestAWedgedCloseDoesNotFreezeTheFleet` catches immediately, and did.

**A rebuild is a gap in service.** Close, construct, bind again. Clients of that
listener are disconnected and must re-handshake. There is no draining and no
overlap; a protocol with a long handshake makes the gap longer.

**`Apply` holds `Manager.mu` for the whole pass.** Building a listener opens a
TUN and may shell out to iptables, so a large fleet's reconciliation blocks
status reads for the duration. Fine for the tens of listeners this is built for;
it is not a design for hundreds. (The per-listener `Rebuild` path is the
exception: it releases the lock around the rebuild so a slow construction shows
a `"building"` status instead of freezing the other listeners' reads — `buildMu`
on the handle is what keeps a SIGHUP reconcile from rebuilding it concurrently.)

Releasing that lock means a `Stop`, a `Close` or a reconcile can drop the
listener from the live set while the rebuild is still running. The removal is
the later decision and it wins: `Rebuild` tears down whatever it built rather
than putting the handle back. Re-adding it was the obvious move and the wrong
one — every remover blocks on `buildMu` until the rebuild finishes, so the
removal normally lands *after* the new server is up and closes it, and the
re-add then resurrected a dead entry, leaving a deleted listener still tracked
and `Close` returning with a non-empty map.

**Nothing here is multi-tenant.** Every listener runs with the supervisor's
privileges, reads whatever files its options name, and can be edited by anyone
holding the management token. The boundary is the host, not the listener — see
`doc/security.md`.
