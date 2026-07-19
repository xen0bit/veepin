# veepin: MASQUE CONNECT-UDP (RFC 9298)

## What this is

CONNECT-UDP proxies **individual UDP flows** through an HTTP/3 connection: a
client asks a proxy to open a UDP socket to one `host:port`, then exchanges that
socket's datagrams as HTTP Datagrams. It is the sibling of CONNECT-IP (RFC 9484)
and, per RFC 9298, the more widely deployed of the two — it is the outer hop of
Apple Private Relay and what most MASQUE proxies actually run.

It reuses almost everything CONNECT-IP already built: the entire HTTP/3 substrate
(`internal/masque/http3`), the capsule codec, and the context-0 HTTP-Datagram
payload — which for UDP carries a raw UDP payload rather than an IP packet, but is
byte-identical on the wire. The net-new code is the request path template and the
socket relay.

## Why it does not fit the TUN model

Every other veepin protocol is a full-IP VPN: a TUN, an assigned address, a
`client.Result`. CONNECT-UDP is not that. It is a per-flow proxy — closer to
`socat` or a SOCKS UDP associate than to a VPN — so it deliberately does **not**
register with the `client` registry or produce a `Result`. It gets its own
surface instead:

- **Server:** additive to the existing MASQUE proxy. `veepin serve masque`
  already accepts CONNECT-IP; it now dispatches on `:protocol`, and a
  `connect-udp` request makes the proxy open a UDP socket to the target named in
  the path and relay datagrams. One proxy, both capabilities.
- **Client:** a new `veepin udp-proxy` subcommand and a `masque.UDPProxy`
  facade. It binds a local UDP socket and, per local source address, opens one
  CONNECT-UDP flow to a fixed target through the proxy — a forwarder, like a DNS
  or QUIC relay.

## Wire details (verified against RFC 9298)

- Request: `:method=CONNECT`, `:protocol=connect-udp`, `:scheme=https`,
  `:path=/.well-known/masque/udp/{target_host}/{target_port}/`, `:authority`,
  `capsule-protocol: ?1`. An IPv6 literal host has its colons percent-encoded.
- HTTP Datagram payload: `Context ID (i)` + `UDP Payload (..)`. Context 0 means
  the payload is the unmodified UDP payload — no IP or UDP header. This is the
  same context-0 framing CONNECT-IP uses, so `EncodeDatagramPayload` /
  `DecodeDatagramPayload` are reused unchanged.
- Only the DATAGRAM capsule is used. No address or route capsules.

## New / changed files

- `internal/masque/connectudp.go` — path template, request headers, target
  parsing out of the path, `IsConnectUDP`.
- `internal/masque/udpproxy.go` — the client forwarder: local socket ↔ per-source
  CONNECT-UDP flows.
- `internal/masque/server.go` — dispatch `connect-ip` vs `connect-udp`; the UDP
  relay half.
- `masque/udp.go` — `UDPProxy` facade (`ListenAndServe`).
- `cmd/veepin/udpproxy.go` + `main.go` — the `udp-proxy` subcommand.
- Reused unchanged: the http3 substrate, capsule codec, datagram payload.

## Sequencing

- **Phase 0 — protocol primitives + server relay.** connectudp.go, the server
  dispatch and UDP relay. Unit tests for path/target parsing; an in-process test
  driving a CONNECT-UDP request against the veepin proxy through to a UDP echo.
- **Phase 1 — client forwarder + facade + CLI.** udpproxy.go, masque.UDPProxy,
  the `udp-proxy` subcommand. An end-to-end loopback test: local UDP → veepin
  client → veepin proxy → echo → back.
- **Phase 2 — interop + docs.** aioquic CONNECT-UDP added to masquepeer.py (both
  roles) against a UDP echo target; compose cells + interop_test funcs; fuzz the
  path parser; README. govulncheck/lint/CI green.

## Verification

```sh
go build ./... && go vet ./... && go test -race ./... && golangci-lint run
cd nm && go build ./... && cd ..
# loopback: veepin udp-proxy forwards a datagram to an echo target through a veepin proxy
make interop   # + aioquic CONNECT-UDP cells
```

## Open risks

- **Per-source flow lifecycle.** A local UDP forwarder has no connection close
  signal, so idle flows must time out or the proxy leaks sockets. Bounded with an
  idle timeout, the same shape as the existing tunnel expiry.
- **aioquic CONNECT-UDP.** aioquic passed CONNECT-IP through generically; the
  same `:protocol` path should carry connect-udp. Verified with Docker before the
  cell is trusted, as with CONNECT-IP.
