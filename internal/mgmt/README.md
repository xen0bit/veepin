# internal/mgmt

The supervisor's management plane: a REST API over the listener directory, and
(in `ui/`) a server-rendered panel that drives it.

Stdlib only, like everything else here. The dependency contract forbids a router,
so `net/http.ServeMux` pattern matching is the routing; it forbids a logging
library, so one `*log.Logger` writes a line per request that changed something
or failed.

```
GET    /api/health                     liveness + uptime
GET    /api/protocols                  every server + client protocol + its OptSpec metadata
GET    /api/listeners                  status of each listener
POST   /api/listeners                  create (409 if it exists); returns {status, generated}
GET    /api/listeners/{name}           status + config, secrets redacted
PATCH  /api/listeners/{name}           partial update, then cold-rebuild
DELETE /api/listeners/{name}           stop + remove the file and its iptables rules
POST   /api/listeners/{name}/restart   rebuild from the on-disk config
GET    /api/listeners/{name}/peers     peers, if the protocol implements PeerDescriber
DELETE /api/listeners/{name}/peers     remove a configured peer (WireGuard family), then cold-rebuild; key in ?key=
POST   /api/listeners/{name}/client-config  generate a client profile (provisions a peer + rebuilds for WireGuard-family protocols)
GET    /api/audit                      recent mutations, newest first (in-memory, bounded)
GET    /api/logs                       the supervisor's log tail, newest first (in-memory, bounded; 404 without a ring)
GET    /api/profiles                   list client profiles (when a profile dir is configured)
POST   /api/profiles                   create a profile
GET    /api/profiles/{name}            get a profile, secrets redacted
PATCH  /api/profiles/{name}            partial update
DELETE /api/profiles/{name}            delete a profile
```

## Profiles

Client connection profiles — the same confstore shape as listeners, for the Dial
side — are a second entity type under the same API. The endpoints are only
mounted when the supervisor configured a profile directory (`-profiles`, default
`<config>/profiles`), and they are pure CRUD: a profile is not a running thing,
so there is no state, restart, or peer list. Secrets are redacted on read the
same way, and PATCH has the same presence-aware semantics and sentinels. The
panel's profile forms render from `client.RegisterClientOpts` metadata, the
mirror of the listener forms' server-side specs.

## The audit log

Every create / patch / delete / restart — listener or profile — records one
line into a bounded (200-entry) in-memory ring: action, entity, and outcome.
`GET /api/audit` returns it newest-first, and the panel renders it as "recent
activity". It answers "what has changed since the supervisor started", not
"what happened last month" — persistence is the supervisor's own log file's job.

## The log ring

The supervisor's logger writes into a bounded (1000-line) in-memory ring as
well, served at `GET /api/logs` newest-first. It is the "why is this listener
in error state" view: the status field carries the last failure, the log shows
the sequence (build errors, hostnet messages, refused and mutating API calls)
that produced it. The caller attaches it with `WithLogRing`; without one the
endpoint answers 404 rather than serving a fabricated empty log.

A GET that succeeded is deliberately not logged, and that exclusion is what
makes the ring usable. The panel polls five endpoints every five seconds, so
logging them wrote a line per second into the very ring being displayed — the
1000 lines held nothing but `GET /api/logs -> 200` after about seventeen
minutes, and the build error an operator opened the panel to read was evicted by
the act of reading it. Failures (the 401s especially) and every mutation are
kept, so nothing that changed state, or tried to and was refused, goes
unlogged.

## Peer removal

`DELETE /api/listeners/{name}/peers?key=<public-key>` removes one configured
peer from a WireGuard-family listener and cold-rebuilds it, rolling the peer
back in if the rebuild fails. It exists for stranded peers: a client-config
response lost after a successful provision leaves a peer on the listener that
nobody holds the private key for, and hand-editing the config was the only way
to take it back out. The key is a query value, not a path segment, because it
is base64 and a path segment would be split by any `/` or `+` in it.

## Client config generation

`POST /api/listeners/{name}/client-config` assembles a client connection
profile from the listener's stored config — real secrets, never redacted
placeholders — plus the operator-supplied endpoint. It is protocol-aware only
where it must be: most protocols are a straight carry-over of the listener's
options (see the `clientProtoMaps` table, guarded by
`TestClientConfigMapKeysAreDeclared`); file-path options are bundled as
companions with the profile paths rewritten. WireGuard and AmneziaWG are the
mutating case: they mint a client keypair, allocate a free address from the
server's `address` subnet (scanning the `peers` option for what is taken),
append the peer, and cold-rebuild the listener. That mutation is why the
endpoint is a POST and is audit-logged as `listener.client-config`.

The derivation table's keys, ports and defaults are tied to the registry's
OptSpecs by a test; the endpoint requirement, the bundle, and the WireGuard
provisioning path each have API-level coverage.

Only paths the *listener's own config* supplied are opened and bundled. A
file-path option supplied as an override is copied into the profile verbatim
and never read — the endpoint would otherwise be an authenticated arbitrary
file read, as root, for any protocol declaring a file-path option.

What it cannot derive it refuses to guess. A client option the facade marks
`Required` that the listener does not supply — an ikev2 local identity, a nebula
per-host certificate — fails the generation with a 400 naming the keys, so the
operator re-runs with them as overrides. The alternative is a profile that looks
complete, saves cleanly, and fails at dial with nothing pointing back here.

### Generated key material and the names it covers

A listener whose protocol declares `Generate` on an `OptSpec` gets its key
material minted on create — a WireGuard keypair, a PSK, an SSH host key, or a
certificate chain. A generator is all-or-nothing: supplying some of
`x509-chain`'s `ca`/`cert`/`key` and leaving the rest empty is refused, because
the alternative was writing a fresh certificate next to the operator's unrelated
private key and answering 201.

For the certificate generators, the listener's `hostnames` field is what the
leaf's SANs are built from. It matters more than it looks:

```jsonc
{"name": "site-a", "protocol": "anyconnect",
 "hostnames": ["vpn.example.com", "203.0.113.4"], ...}
```

Empty means loopback plus the listener's own name, which is enough to dial from
the same machine and covers no remote client. There is no way to infer better —
the supervisor cannot know its own public name — and a leaf with no matching SAN
verifies against nothing at all, since Go and every browser dropped the Common
Name fallback years ago. `client-config` compares the two and warns when the
endpoint it is given is not one the certificate covers, which is the only point
in the flow where both facts are in the same place.

nebula is the narrow case: only the mesh CA carries across. A host's own
certificate and X25519 key are its identity, and copying the lighthouse's would
clone the lighthouse rather than provision a peer. Issuing a per-host
certificate is a CA operation veepin does not perform.

## Auth, and the two boundaries

A bearer token, 256 bits of `crypto/rand`, generated on first run into
`<config>/mgmt/token` mode 0600 and compared with `subtle.ConstantTimeCompare`.
That is the boundary for `/api/*`.

The panel at `/` has no token, necessarily — it is the thing that *hands* the
browser one, by writing it into the page. Its boundary is `RequireHost`, which
answers 403 unless the `Host` header names loopback, `localhost`, or the exact
`-listen` address. Without it, a page that rebinds its own hostname to
`127.0.0.1` becomes same-origin with the panel, reads the token out of the DOM,
and drives every endpoint. `doc/security.md` has the long form.

## PATCH is presence-aware

`listenerPatch` uses pointers, not a plain `ListenerConfig`, because
`encoding/json` leaves an absent field at its zero value — so `"enabled": false`
and an omitted `"enabled"` decode identically, and a merge cannot tell "leave it
alone" from "turn it off".

Option values carry two sentinels: `"<redacted>"` means keep the stored value
(so a GET-then-PATCH round trip cannot overwrite a private key with the
placeholder it was shown), and `""` means delete the key (which is how the panel,
which submits every declared option on every save, expresses "unset").

## Caveats

**Secrets are redacted on read, not protected at rest.** The option maps are
plaintext JSON, mode 0600. Redaction stops `curl /api/listeners/site-a` from
leaking a PSK by accident; it is not encryption, and anyone who can read the
config directory has the keys.

**Redaction depends on the metadata being right.** A key whose `OptSpec` is
missing `Secret: true` is returned in the clear. `cmd/veepin`'s
`TestServerOptSpecsMatchTheKeysTheProtocolReads` checks that every key the
protocol reads has a spec, and `TestSecretFlagsAgreeAcrossBothTables` checks
that a key appearing in both a protocol's client and server tables is flagged
the same way in each — which is what caught l2tpv3 calling its cookies secret in
one file and explicitly not-secret in the other. Neither can check that a flag
is *correct* where a key appears in only one table; that is a judgement call in
each facade, and `doc/security.md` records the rule it is judged against.

**Generated certificates are trusted by nobody but the operator.** The CA is
self-signed, minted per listener, and distributed by hand. That is the right
shape for a VPN — the client should pin exactly one issuer — but it means the
`ca.crt` in the listener's key directory is load-bearing, and losing it strands
every client that verified against it.

**Transport is plaintext HTTP.** There is no TLS here at all. On loopback that is
fine; anywhere else the token crosses the wire in the clear and a reverse proxy
with TLS is not optional.

**No rate limiting, no accounts.** One token, full authority, and the request
log is a line per mutation or failure. The audit log does record *what* changed and *whether
it worked*, but not *who* — every authenticated mutation shares the one token,
so a fleet where several people hold it still cannot attribute an edit. That is
a deliberate boundary: accounts and per-user authorization are a separate
problem from running a VPN fleet, and the token file's filesystem protection is
the real gate.

**`Server.CloseFleet` closes the whole fleet**, not just the HTTP server — it
delegates to the manager, and the Server owns no listening socket to close. It
was spelled `Close`, which is exactly the trap it looks like: the conventional
teardown call on the HTTP-shaped object shutting down every VPN listener on the
host. `cmd/veepin` closes the manager directly and never calls this.

**Mutations are serialized by one lock over the whole config directory.** Every
handler that reads a listener file, changes it and writes it back holds
`Server.mutate`, because two concurrent client-config generations against one
WireGuard listener would otherwise each allocate the same tunnel address and the
second write would discard the first peer. It is one lock rather than one per
listener: these are operator actions at human rates and the critical sections
already contain a cold rebuild. Reads do not take it.

**A generated client profile is the only copy of that client's private key.**
It exists in the response body and nowhere else — the server stores only the
public half, as a peer. If the response is lost, the peer is stranded: delete it
from the listener's `peers` and generate again.
