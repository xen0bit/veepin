# internal/mgmt

The supervisor's management plane: a REST API over the listener directory, and
(in `ui/`) a server-rendered panel that drives it.

Stdlib only, like everything else here. The dependency contract forbids a router,
so `net/http.ServeMux` pattern matching is the routing; it forbids a logging
library, so one `*log.Logger` writes a line per request.

```
GET    /api/health                     liveness + uptime
GET    /api/protocols                  every server protocol + its OptSpec metadata
GET    /api/listeners                  status of each listener
POST   /api/listeners                  create (409 if it exists)
GET    /api/listeners/{name}           status + config, secrets redacted
PATCH  /api/listeners/{name}           partial update, then cold-rebuild
DELETE /api/listeners/{name}           stop + remove the file and its iptables rules
POST   /api/listeners/{name}/restart   rebuild from the on-disk config
GET    /api/listeners/{name}/peers     peers, if the protocol implements PeerDescriber
```

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
protocol reads has a spec, but nothing can check that a spec's `Secret` flag is
*correct* — that is a judgement call in each facade.

**Transport is plaintext HTTP.** There is no TLS here at all. On loopback that is
fine; anywhere else the token crosses the wire in the clear and a reverse proxy
with TLS is not optional.

**No rate limiting, no audit log, no accounts.** One token, full authority, and
the request log is a line per request with no record of what changed. A fleet
where several people hold the token cannot tell afterwards which of them edited
a listener.

**`Server.Close` closes the whole fleet**, not just the HTTP server — it
delegates to the manager. The name is a trap and the caller in `cmd/veepin` does
not use it.
