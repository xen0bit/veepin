# veepin: the rest of the openconnect column (Juniper NC, Array, F5)

## What this is

openconnect supports seven protocols. veepin implements five of them —
AnyConnect, Fortinet, GlobalProtect, Pulse and (via a different peer) the IPsec
family. Three remain:

| Protocol | openconnect flag | Vendor |
|---|---|---|
| Juniper Network Connect | `--protocol=nc` | Juniper (pre-Pulse) |
| Array Networks AG | `--protocol=array` | Array Networks |
| F5 BIG-IP | `--protocol=f5` | F5 |

They are grouped into one document because they share a shape, share a peer, and
share a verdict.

## The verdict, first

**These are the cheapest additions available and the least valuable.** Each would
add a row to the README protocol table and teach the tree nothing it does not
already know. They are documented here so the decision is on record, not because
they are recommended.

Do them if completing the openconnect column is itself the goal — it is a
legitimate goal, and "veepin speaks every protocol openconnect does, in both
directions" is a claim worth being able to make. Do not do them expecting to
learn anything.

## Why each is low-value

**F5 BIG-IP** — already rejected once, on the same grounds, when GlobalProtect
was chosen over it. It is **PPP over TLS with a DTLS data channel**, which is
structurally what `internal/fortinet` already is: openconnect prefers
PPP-over-DTLS and falls back to PPP-over-TLS, exactly Fortinet's arrangement.
`internal/ppp` and `internal/dtls` would both be reused unchanged. Its one
distinction is that a second independent client exists (`gof5`, in Go), so the
interop cell could have two peers.

**Juniper Network Connect** — Pulse's predecessor, and the *same vendor lineage*.
Ivanti servers still accept it alongside Pulse unless an administrator disables
it. openconnect implements it in `oncp.c`, and much of `internal/pulse` — the
ESP data path, the key-block handling, the split-route conversion — is shaped by
the same design. The ESP probe convention veepin already implements (a single
zero octet, echoed) came from `oncp.c` in the first place. Highest reuse of the
three, lowest novelty.

**Array Networks AG** — a fourth variation on "HTTPS login yields a cookie, then
a second HTTPS connection becomes a framed packet tunnel". That is AnyConnect,
Fortinet, GlobalProtect and Pulse already. The framing details differ; nothing
structural does.

## If they are done anyway

The path is entirely mechanical and the checklist in `CLAUDE.md` covers it
without amendment. Per protocol:

1. Read openconnect's implementation — `oncp.c`, `array.c`, `f5.c` — and record
   the wire format in a plan document *before* writing code. This is not
   optional; it is what caught the wrong cipher identifiers in the Pulse work.
2. `internal/<proto>/` with codecs first, then both roles, then `e2e_test.go`.
3. Facade, CLI, docs, `datapath_test.go`, fuzz targets, NM wiring.
4. Interop: openconnect as the client, veepin as the server. **All three get
   `—†` in the client column** — none has an open-source server, so the veepin
   client cannot be tested against a real peer, exactly as with GlobalProtect
   and Pulse.

F5 is the one exception worth noting: `gof5` gives the client direction a real
peer, so F5 could have a genuine ✓/✓/✓ row where the other two cannot. If
exactly one of these three is ever done, that is a mild argument for it being F5
— which is the opposite of the argument that rejected it on novelty grounds.

## Estimated order, if the column is to be completed

1. **Juniper NC** — highest reuse from `internal/pulse`; likely the fastest.
2. **F5** — highest reuse from `internal/fortinet`, and the only real ✓/✓/✓.
3. **Array** — least reuse of the three and the least deployed.
