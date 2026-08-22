# internal/masque

MASQUE CONNECT-IP and CONNECT-UDP: IP- and UDP-over-HTTP/3. The HTTP/3 substrate is
the [`http3`](./http3) subpackage; this package is the CONNECT protocol on top of
it — the capsules that assign an address and advertise routes, the HTTP-Datagram
payload that carries an inner packet, and the client/server roles that turn a
request stream into a tunnel.

## Specifications

- [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) — CONNECT-IP (IP proxying over HTTP).
- [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) — CONNECT-UDP (UDP proxying over HTTP).
- [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) — HTTP Datagrams and the Capsule Protocol.
- [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) — Extended CONNECT for HTTP/3.

## Capsule-mode tunnel

```mermaid
flowchart TD
    REQ["Extended CONNECT request (:protocol = connect-ip / connect-udp)"] --> OK["2xx: stream is now the tunnel"]
    OK --> ADDR["ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT capsules"]
    ADDR --> DG["DATAGRAM capsules on the request stream<br/>(each carries one inner IP/UDP packet)"]
    DG <--> TUN["TUN"]
```

## Why capsule mode (and not QUIC datagrams)

`x/net/quic` (v0.56.0) has **no** RFC 9221 QUIC DATAGRAM frames — `dgram.go` in its
internals is an unrelated UDP type, a false signal. So every inner packet rides as
a **DATAGRAM capsule on the request stream** rather than an unreliable QUIC
datagram. This is a documented **performance** boundary, not a correctness one: the
capsule formats are identical either way. What capsule mode costs is reliability and
ordering the tunnelled traffic never asked for.

## API surface

- **Headers/paths** — `ConnectIPHeaders`/`ConnectIPPath`,
  `ConnectUDPHeaders`/`ConnectUDPPath`, `IsConnectIP`/`IsConnectUDP`,
  `ParseConnectUDPTarget`.
- **Capsules** — `WriteCapsule`, `Capsule`, `CapsuleDatagram`/…;
  `EncodeAddresses`/`ParseAddresses` (`AddressEntry`),
  `EncodeRoutes` (`RouteEntry`).
- **Datagram payload** — `EncodeDatagramPayload`/`DecodeDatagramPayload`.
- **Allocation-free data path** — `DatagramEncoder` (Encode reuses its buffer) and
  `CapsuleReader` (Read reuses its buffer; **borrowed-buffer** contract).
- `ErrCapsuleTooLarge`.

## Implementation notes & caveats

- **The data path is allocation-free and guarded.** `DatagramEncoder`/`CapsuleReader`
  hand out **borrowed** buffers reused on the next call — the caller must consume or
  copy before calling again. An `AllocsPerRun` test pins zero allocs per packet;
  send went 465→23 ns and receive 228→43 ns with this. See
  [[masque-datapath-allocation-free]].
- **Capsule mode is the current reality, not a choice** — revisit only when
  `x/net/quic` gains RFC 9221 datagram frames. The earlier framing of capsule mode
  as "the perf lever" was misleading; the real win was the allocation work above.
- **Every parser that reads peer bytes is fuzzed.** `FuzzReadCapsule`,
  `FuzzParseAddresses`, `FuzzParseRoutes` and `FuzzDecodeDatagramPayload` cover
  the tunnel stream; `FuzzParseConnectUDPTarget` covers the request path, which
  any client can send before it is anyone's peer. The [`http3`](./http3)
  substrate adds `FuzzConsumeVarint`, `FuzzParseSettings` and
  `FuzzDecodeFieldSection`. All eight are in the fuzz job's target list, and a
  test fails if that list and these packages ever disagree.
- **Shaping pads inside the DATAGRAM capsule's value, not after it.** RFC 9484's
  context-0 payload is "context ID, then an IP packet" with no length of its
  own, so a receiver hands everything after the context ID to its TUN and the
  kernel's IP stack delimits the real packet by the inner header's Total Length.
  `DatagramEncoder.EncodePadded` grows the capsule's length field to cover the
  filler — a padder that grew the value without the length would leave the peer
  resynchronising on the wrong octet, which looks like a corrupt tunnel rather
  than a padding bug, and `TestPaddedCapsuleLengthFieldCoversTheFiller` is two
  capsules back to back precisely so the second only parses if the first's
  length was right.

  The obvious alternative — a filler capsule of an unregistered type, which
  RFC 9297 requires receivers to skip — was rejected. It would rest the whole
  mechanism on the peer honouring a MUST, where trailing octets rest on
  behaviour every IP stack already has. `compose.masque-server-shaped.yml`
  proves aioquic accepts and trims the padding having been told nothing about
  it.
