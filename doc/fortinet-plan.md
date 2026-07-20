# veepin: Fortinet FortiOS SSL VPN (protocol #11)

## What this is

FortiOS SSL VPN is Fortinet's remote-access VPN: an HTTPS handshake authenticates
and hands back a config, then the same connection becomes a **PPP-over-TLS** (or,
preferred by real clients, **PPP-over-DTLS**) tunnel. It is the second enterprise
SSL VPN in veepin next to AnyConnect, and the highest-reuse protocol the tree
could add: it is, structurally, *SSTP's PPP data path over AnyConnect's TLS+DTLS
transport*.

Chosen over GlobalProtect because it reuses two from-scratch veepin subsystems at
once (`internal/ppp` and `internal/dtls`) where GP would reuse only ESP, and
because its control plane is a clean form-POST rather than GP's
portal→gateway→HIP→prelogin flow. The interop shape is identical either way (see
below), so it did not break the tie.

## Wire details — verified against openconnect source, not assumed

**Control plane (HTTPS):**
- `POST /remote/logincheck` — form auth (`username`, `credential`, realm).
  Success returns `ret=1,redir=/remote/fortisslvpn_xml` and sets the
  **`SVPNCOOKIE`** session cookie. 2FA returns `ret=2` with challenge parameters.
- `GET /remote/fortisslvpn_xml` (with SVPNCOOKIE) — XML config:
  `<assigned-addr ipv4=…>`, `<dns ip=… domain=…>`,
  `<split-tunnel-info><addr ip=… mask=…></>`, `<tunnel-method value="ppp|tun">`,
  idle/auth timeouts.
- `GET /remote/sslvpn-tunnel` (with SVPNCOOKIE) — no HTTP response body; the TLS
  stream immediately becomes the framed PPP tunnel.

**Data plane — PPP over TLS (`PPP_ENCAP_FORTINET`).** Each PPP frame is wrapped
in a 6-octet header, followed by a *bare* PPP frame (RFC 1661 protocol+payload,
never async-HDLC):

```
0      2        4          6
+------+--------+----------+----------------------+
|len BE| 0x5050 | plen BE  |  bare PPP frame ...  |
+------+--------+----------+----------------------+
 len  = plen + 6   (whole record)
 plen = PPP frame length
```

Inside runs standard **LCP + IPCP**, with **no PPP-level authentication** — the
SVPNCOOKIE already authenticated, so the FortiOS PPP link does not do CHAP.

**Data plane — PPP over DTLS** (preferred by the openconnect client; a later
phase here). A bespoke pre-handshake over the DTLS session:
`[len BE16] "GFtype\0clthello\0SVPNCOOKIE" <cookie> \0`, answered with
`"GFtype\0svrhello\0handshake" … "ok"`. openconnect falls back to TLS if DTLS is
not offered, so a **TLS-only veepin server interoperates with the real client**
from the first data-path phase.

## Two integration points, established by reading the code

Both are why the plan is concrete rather than hopeful.

1. **`internal/ppp` is already transport-delimited** — "there is no async-HDLC
   layer; the transport delimits frames, so a frame is just the protocol number
   and its payload." The 6-octet Fortinet header *is* that delimiter, and the
   bare PPP frame inside is exactly what `encodeFrame`/`decodeFrame` produce and
   accept (with tolerant ACFC handling). So Fortinet plugs in as a `Transport`
   with almost no impedance.

2. **`internal/ppp` currently assumes authentication always happens** — the
   client's `maybeLCPUp` enters `phaseAuth` and *waits for an MS-CHAPv2
   challenge*, and the server always advertises the Auth-Protocol LCP option.
   Fortinet does neither. So the real net-new PPP work is an **auth-optional
   mode**, driven by LCP negotiation: a client that sees no Auth-Protocol option
   goes straight LCP→IPCP, and a server can be built to omit it. This is also
   simply more correct PPP (RFC 1661: auth happens only if negotiated), so it is
   an improvement to the shared layer, not a Fortinet special case.

## Architecture — the reuse map

```
        TUN  <──IP──>  PPP session (LCP/IPCP, auth-optional)   REUSE internal/ppp (+ no-auth mode)
                          │
                 6-octet Fortinet header                        NEW internal/fortinet (framing)
                          │
        TLS stream  ──or──  DTLS session                        REUSE crypto/tls / internal/dtls
                          │
        HTTPS control: /remote/logincheck,                      NEW internal/fortinet (auth + XML)
        /remote/fortisslvpn_xml, /remote/sslvpn-tunnel
```

- **Reused:** `internal/ppp` (LCP/IPCP; gains an auth-optional mode),
  `internal/dtls` (from AnyConnect — a validating second consumer, in the DTLS
  phase), the TLS-listener and HTTP patterns from `anyconnect`/`sstp`,
  `dataplane` (TUN, `AddrPool`, admission gate), the `client` registry.
- **New — `internal/fortinet`:** the 6-octet framing codec, the HTTP auth
  exchange (`logincheck` + SVPNCOOKIE), the `fortisslvpn_xml` config parse/build,
  and the client/server engines binding PPP to the TLS (later DTLS) transport.
- **New — `fortinet/`:** the public facade — `Dial` + `NewServer`, `Config`,
  registration, and the `cmd/veepin` `fortinet` cases.

## Interop

Both openconnect *fake servers* stub the data channel (Fortinet's returns 403,
GP's 502), so — for either protocol — the packet-moving peer is the **real
openconnect client**, which fully implements the data path.

- **openconnect client → veepin server** (`openconnect --protocol=fortinet`):
  the packet-moving cell, ping across the tunnel. Uses TLS (openconnect falls
  back from DTLS when the server offers none).
- **veepin client → openconnect `fake-fortinet-server.py`**: control-plane cell
  — proves veepin's auth and XML parsing against an independent implementation
  (no ping, since that server stubs data).
- **veepin ↔ veepin self**: full data path, for attribution.

## Sequencing (each phase builds, vets, tests, lints green)

- **Phase 0 — framing + PPP auth-optional mode.** The 6-octet codec with
  byte-exact tests; add the auth-optional path to `internal/ppp` (client skips
  auth when not negotiated; server `NoAuth` config) with tests that an LCP→IPCP
  link comes up with no CHAP. In-process LCP/IPCP over the Fortinet framing.
- **Phase 1 — HTTP control + config.** `logincheck` auth + SVPNCOOKIE issue/parse,
  `fortisslvpn_xml` parse/build. Unit tests, including split-route XML.
- **Phase 2 — PPP-over-TLS data path, both roles.** Assemble client and server;
  veepin↔veepin over loopback (ping). Interoperable with the openconnect client
  already.
- **Phase 3 — facade + CLI + registry + README.**
- **Phase 4 — interop.** Docker: openconnect client → veepin server (ping),
  veepin client → fake-fortinet-server (handshake), self. Fuzz the framing, the
  XML, and the auth parsers; extend the CI fuzz list and interop path filter.
- **Phase 5 (optional) — PPP-over-DTLS.** The `GFtype` handshake and the DTLS
  transport, reusing `internal/dtls`. Deferred because TLS already interoperates.

## Verification

```sh
go build ./... && go vet ./... && go test -race ./... && golangci-lint run
cd nm && go build ./... && cd ..
make interop   # openconnect client vs veepin server, veepin client vs fake server, self
```

## Open risks

- **Auth-optional PPP** must not regress SSTP, which requires MS-CHAPv2. The mode
  is opt-in; SSTP keeps demanding auth, and a test pins that.
- **ACFC on send** — veepin always sends the `0xFF 0x03` pair; confirm the
  openconnect Fortinet PPP parser accepts it (it handles ACFC, so it should), or
  negotiate ACFC in LCP.
- **openconnect's DTLS-first preference** — a TLS-only server must decline DTLS
  cleanly so the client falls back; verify the "no DTLS offered" path in Phase 4.
- **2FA/challenge** (`ret=2`) is real surface; implement single-factor first and
  treat challenge as additive.
- **FortiOS version drift** in the config XML — parse leniently, ignoring unknown
  tags, as veepin already does elsewhere.
```
