# Architecture: the protocol-agnostic boundary

veepin separates machinery any VPN protocol needs from what is specific to one
protocol. The package tree is sketched in the [README](../README.md#architecture);
this document covers *why* the boundary is where it is, and how a packet actually
moves through it.

## `dataplane` and `cryptoutil` know nothing about any protocol

`dataplane` and `internal/cryptoutil` are protocol-agnostic: neither imports
anything else in this module, and neither knows IKEv2 exists. The crypto
primitives are named for what they are (`NewAESGCMSKCipher`, `NewECDH`) rather
than for IKEv2's transform-ID registry, and the pump moves packets between a TUN
device and a set of `Tunnel`s, demuxing inbound packets with a `Demux` the
protocol supplies:

```go
type Demux func(pkt []byte) (key uint32, ok bool)

func SPIDemux(pkt []byte) (uint32, bool) // ESP: the SPI in the first four octets
```

IKEv2 passes `SPIDemux`; a protocol that identifies tunnels differently
(WireGuard's receiver index lives at offset 4, and only on transport-data
messages) passes its own.

## Outbound routing: one mechanism, every case

Outbound, a packet goes to the tunnel whose route matches its destination most
specifically, and a packet matching no route is dropped. One mechanism covers
every case: an IKEv2 server's tunnel carries its peer's assigned address as a
`/32`, an IKEv2 client's carries `0.0.0.0/0` because everything on its TUN
belongs to the one server, and a WireGuard peer carries its AllowedIPs.

`internal/ikev2/transform` is the single place that translates IANA transform IDs
into primitives. Those seams are what keep the boundary honest.

## Data flow once a client is connected

```
client app → client OS ESP → UDP:4500 → veepin serve → decapsulate → TUN → kernel routing → internet
internet → kernel → TUN → veepin serve → encapsulate → UDP:4500 → client OS → client app
```
