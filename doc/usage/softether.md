# SoftEther VPN (SE-VPN)

veepin's SoftEther implementation carries Ethernet frames over TLS, using
SoftEther's PACK serialisation for the control exchange. It is veepin's only
layer-2 protocol: it needs a TAP device rather than the TUN every other
protocol uses.

> **Not yet usable for host traffic.** The server switches frames between
> connected clients, but nothing yet bridges the switch to the host TAP device,
> and every client is assigned the same hardcoded address. See
> [`internal/softether/README.md`](../../internal/softether/README.md) for the
> full list of gaps. This protocol is not verified against SoftEther's own
> implementation — the interop matrix marks it `‡`, meaning the cell is work
> outstanding rather than impossible.

## Server

```sh
veepin serve softether -cert /path/to/cert.pem -key /path/to/key.pem \
    -user alice -pass secret
```

Required flags:
- `-cert`, `-key`: TLS certificate and key (PEM).
- `-user`, `-pass`: the single accepted username and password. Both are
  required — a server with no credentials configured refuses every login
  rather than accepting all of them.

Optional flags:
- `-listen`: local IP to bind (default `0.0.0.0`).
- `-port`: TLS port (default `443`).
- `-tun`: TAP interface name (empty = kernel picks).
- `-pool`: address pool CIDR. **Currently ignored** — every client is assigned
  `10.70.0.2`.

## Client

```sh
veepin connect softether -server vpn.example.com -user alice -pass secret
```

Required flags:
- `-server`: gateway hostname or IP.
- `-user`, `-pass`: credentials matching the server.

Optional flags:
- `-port`: gateway port (default `443`).
- `-hub`: virtual hub name (default `VPN`).
- `-tun`: TAP interface name (empty = kernel picks).
- `-insecure`: skip gateway certificate verification. SoftEther ships a
  self-signed certificate by default, so this is often needed against a stock
  deployment — and it downgrades the transport to unauthenticated, so prefer
  installing the gateway's certificate where you can.

## Authentication

The client sends `SHA1(SHA1(username+password) XOR server_random)`, where
`server_random` is a fresh 20-byte challenge per session. The challenge binding
is what prevents replay of a captured login against a later session. SHA-1 is
what the protocol specifies; the server must hold the plaintext password
because the response is computed from it rather than from a verifier.

## Interoperability

Not yet verified against SoftEther's own server or client. See the
[interoperability matrix](../../README.md#interoperability-matrix); the `‡`
mark means the Docker cell has not been built, not that no peer exists —
SoftEther VPN Server is open source (Apache-2.0).
