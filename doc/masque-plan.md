# veepin: MASQUE CONNECT-IP (protocol #10)

## What this is

MASQUE CONNECT-IP (RFC 9484) is IP-over-HTTP/3: an Extended CONNECT request
turns a QUIC/HTTP-3 connection into an IP tunnel, with inner packets carried as
HTTP Datagrams. It is the first *modern* tunnel in the tree — everything else is
legacy-enterprise (IKEv2, L2TP, OpenVPN, SSTP, AnyConnect), mesh (Nebula, WG,
SSH), or the teaching example (TOY). It is what Apple Private Relay and the
newest zero-trust products actually run.

It is also the first protocol permitted to use a `golang.org/x` module beyond
`x/crypto`: the dependency policy was widened to the whole pure-Go `x` namespace
specifically so QUIC could be had without hand-rolling it or vendoring quic-go.

## Foundation findings (verified before any code)

These were established by reading `golang.org/x/net@v0.57.0` and running a
loopback handshake, not assumed. They shape the whole design.

1. **`x/net/quic` is fully usable and pure Go.** `quic.Listen` yields an
   `Endpoint` that both `Accept`s (server) and `Dial`s (client); a `Conn` opens
   and accepts bidirectional and unidirectional `Stream`s; ALPN is taken from
   `TLSConfig.NextProtos`. A self-signed loopback test completed a real TLS 1.3
   QUIC handshake (ALPN `h3`) and a bidirectional stream round-trip. The entire
   transitive dependency graph is `golang.org/x/{net,crypto,sys,text}` — all
   pure Go, all in policy.

2. **`x/net/http3` cannot carry MASQUE.** The public package exports *nothing*
   usable — it is a `//go:linkname` shim for `net/http`'s internal HTTP/3
   transport. The real implementation lives in `internal/http3`, and it has no
   Extended CONNECT (`:protocol`), no HTTP Datagrams, and no Capsule Protocol.
   So the HTTP/3 layer MASQUE needs must be built from scratch on top of the
   public `quic` package. This is the same from-scratch protocol work the repo
   already does nine times.

3. **`x/net/quic` does not implement QUIC DATAGRAM frames (RFC 9221).** There is
   no `SendDatagram`/`ReadDatagram` and no `max_datagram_frame_size` transport
   parameter; every "datagram" in the source refers to UDP-packet sizing and
   congestion control. **Consequence:** MASQUE's unreliable datagram fast path
   is unavailable, so veepin runs CONNECT-IP in **capsule-transport mode** (RFC
   9297 §3.5) — HTTP Datagrams carried as DATAGRAM capsules on the request
   stream, which is reliable and ordered.

### The capsule-mode limitation, stated honestly

Carrying every inner packet over one reliable, in-order QUIC stream reintroduces
head-of-line blocking and is the classic "TCP-over-a-reliable-tunnel" pathology
on a lossy path. It is spec-compliant (a MASQUE endpoint that does not negotiate
`h3_datagram` uses capsules), and it interoperates with any proxy that supports
the fallback — but it is not the performance profile a datagram-mode MASQUE VPN
has. This is a genuine boundary, documented in the README the way DTLS/EMS and
key-zeroization already are, with a one-line upgrade path: when `x/net/quic`
grows DATAGRAM frames, the data path swaps the capsule transport for them and
nothing above changes. veepin↔veepin is unaffected in correctness either way.

## Architecture

```
        TUN  <──IP──>  inner IPv4/IPv6 packets
                          │
        CONNECT-IP payload: context-ID 0 + raw IP packet (RFC 9484 §7)
                          │
        HTTP Datagram, capsule mode: a DATAGRAM capsule (RFC 9297)
                          │
        Capsule Protocol on the request stream: (type, length, value) (RFC 9297 §3.2)
                          │
        HTTP/3 request stream: Extended CONNECT — :method=CONNECT,
        :protocol=connect-ip, :path=/.well-known/masque/ip/{target}/{proto}/  (RFC 9484 §3)
                          │
        HTTP/3 framing (RFC 9114): SETTINGS on the control stream, HEADERS (QPACK) on the request
                          │
        QUIC bidi stream  ──  QUIC conn (ALPN h3, TLS 1.3)  ──  UDP   (x/net/quic)
```

### New packages

- **`internal/masque/http3/`** — the minimal HTTP/3 substrate:
  - QUIC varints (RFC 9000 §16).
  - frame codec: the frame types MASQUE touches — SETTINGS, HEADERS; the request
    stream body after HEADERS is raw capsules, not DATA frames.
  - control-stream + QPACK-stream setup: each side opens a unidirectional
    control stream, sends SETTINGS (including `SETTINGS_ENABLE_CONNECT_PROTOCOL`
    and `H3_DATAGRAM=0`, i.e. capsule mode), and opens zero-capacity QPACK
    encoder/decoder streams.
  - **minimal QPACK** (RFC 9204) with a zero-capacity dynamic table: the encoder
    emits Indexed Field Line (static table) and Literal Field Line
    representations only, so no encoder-stream instructions are ever needed; the
    decoder parses the required 0/0 prefix and both literal forms. Huffman
    coding is accepted on decode and not required on encode. This is the largest
    net-new codec and gets its own known-answer tests.
- **`internal/masque/`** — the CONNECT-IP engine (initiator + responder):
  - capsule codec (RFC 9297): type/length/value.
  - CONNECT-IP capsules (RFC 9484 §4): ADDRESS_REQUEST, ADDRESS_ASSIGN,
    ROUTE_ADVERTISEMENT, and the DATAGRAM capsule carrying context-0 IP packets.
  - request construction and the `/.well-known/masque/ip/*/*/` path template.
  - client role (send CONNECT, request an address, pump the TUN) and server role
    (accept CONNECT, assign from a `dataplane.AddrPool`, advertise a route,
    demux inner-dest → client).
- **`masque/`** — public facade, matching the other nine: `masque.go`
  (`client.Register`, `Config`, `Dial`), `server.go` (`RegisterServer`,
  `ServerConfig`, `NewServer`, `Server`), `config.go` (option parsing).

### Reused as-is

`dataplane` (`OpenTUN`, `NewAddrPool`; and a dedicated per-role loop, since a
single reliable stream does not fit `SPIDemux`), `client` registry, `cmd/veepin`
connect/serve (a tenth case in the existing pattern). No `cryptoutil` — QUIC
brings its own TLS 1.3.

## Sequencing

Each phase builds, vets, and tests green before the next.

- **Phase 0 — HTTP/3 substrate.** varint + frame + QPACK + SETTINGS/control-stream
  handshake over `x/net/quic`. Prove an Extended CONNECT round-trip veepin↔veepin
  returns `:status 200`, no tunnel yet. KAT tests for varint and QPACK.
- **Phase 1 — capsules + CONNECT-IP semantics.** Capsule codec, the four CONNECT-IP
  capsules, address assignment from the pool, route advertisement. Unit tests.
- **Phase 2 — data path.** Wire TUN ↔ DATAGRAM capsules for both roles; the
  server's reverse inner-IP → conn map. veepin↔veepin end-to-end over loopback:
  a ping traverses TUN → capsule → QUIC → capsule → TUN.
- **Phase 3 — facade + CLI + registry + docs.** `masque.Dial`/`NewServer`,
  register both, `cmd/veepin` cases, README matrix + runbook + the capsule-mode
  limitation.
- **Phase 4 — interop.** A cross-process self-test (veepin client ↔ veepin
  server in Docker, real QUIC over the loopback network), and a third-party peer:
  a small **aioquic**-based CONNECT-IP proxy speaking capsule mode, containerized
  the way strongSwan/xl2tpd/toypeer already are (a test fixture, so its own
  third-party deps are fine). Add fuzz targets for the varint/QPACK/capsule
  parsers; extend the CI interop path filter. govulncheck/lint/CI green.

## Verification (every phase boundary)

```sh
go build ./... && go vet ./...
go test -race ./...
golangci-lint run
cd nm && go build ./... && go test ./... && cd ..
```

End-to-end proof (Phase 2+):

```sh
sudo ./veepin serve   masque -public 127.0.0.1 -cert cert.pem -key key.pem -pool 10.30.0.0/24
sudo ./veepin connect masque -server 127.0.0.1 -insecure
ping -c1 <assigned gateway>
make interop        # masque self-test + aioquic CONNECT-IP
```

## Open risks

- **QPACK is the hard codec.** Mitigated by the zero-capacity dynamic-table
  restriction (no encoder-stream state machine) and by known-answer tests taken
  from RFC 9204's appendix examples before any live interop.
- **aioquic capsule-mode interop.** aioquic supports QUIC datagrams; the test
  proxy must be written to use *capsule* mode to match veepin. Since the proxy
  is ours, it sends/receives DATAGRAM capsules on the request stream directly
  rather than relying on a datagram-mode helper.
- **Extended CONNECT negotiation.** The server must advertise
  `SETTINGS_ENABLE_CONNECT_PROTOCOL`; a client that sends `:protocol` before
  seeing it is malformed. The SETTINGS exchange has to complete before the
  CONNECT is emitted.
- **Scope.** This is the largest single protocol in the tree. The phase
  boundaries are the commit points; each is independently green on `feat/masque`.
```
