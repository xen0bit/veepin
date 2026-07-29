# internal/l2tpv3 — L2TPv3 Ethernet pseudowire

RFC 3931 (L2TPv3) carrying Ethernet frames per RFC 4719, static sessions only.
This is veepin's only layer-2 data path.

## Files

| File | What it holds |
|---|---|
| `frame.go` | the data-packet codec: `EncodeData`, `DecodeData`, cookie verification |
| `session.go` | `SessionConfig` — session IDs, both cookies, sublayer, peer address |
| `pump.go` | the TAP↔UDP data path and `SessionIDDemux` |

## Why this is not a version switch inside `internal/l2tp`

v2 is PPP-over-L2TP keyed by a 16-bit tunnel/session pair; v3 is a pseudowire
keyed by a single 32-bit Session ID, carrying Ethernet rather than PPP. They
share the AVP encoding and essentially nothing else, so ~120 lines of AVP helper
were copied rather than threading a version flag through 2,100 lines that would
then serve two callers with divergent needs. The AmneziaWG package set the same
precedent.

## Why this is not `dataplane.Pump`

`Pump.routeOutbound` calls `innerDest`, which reads the first nibble of the
buffer as an IP version. On an Ethernet frame that nibble is the top half of the
destination MAC. It would not fail cleanly — it would succeed **by accident**
whenever a MAC happened to begin `0x4` or `0x6`, which is the worst available
failure mode for a data path.

`dataplane.Demux`, `dataplane.PacketConn` and `dataplane.OpenTAP` are reused
unchanged; only the routing decision differs, because layer 2 does not have one.
GRO/GSO is deliberately **not** wired: both parse IP and TCP headers at fixed
offsets that mean nothing in an Ethernet frame.

## The wire format

```
 0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|T|x|x|x|x|x|x|x|x|x|x|x|  Ver  |             Res               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Session ID                          |
+---------------------------------------------------------------+
|                  Cookie (0, 4 or 8 octets)                    |
+---------------------------------------------------------------+
|         Default L2-Specific Sublayer (0 or 4 octets)          |
+---------------------------------------------------------------+
|                       Ethernet frame                          |
+---------------------------------------------------------------+
```

The T bit is the MSB of the first word and the version is its **low four bits**,
with eleven unassigned bits between them. Comparing the whole word against 3
happens to work against Linux, which zeroes those bits, and rejects any peer that
sets one. `TestVersionIsTheLowNibble` holds that in place.

## The cookie is chosen by the receiver

Each end picks the value it wants to see on its own inbound packets and tells the
peer, so `LocalCookie` is verified on receive and `RemoteCookie` is written on
send. Swap the two at both ends and a veepin↔veepin tunnel passes perfectly —
both halves wrong the same way — and only a real peer notices.
`TestCookieIsChosenByTheReceiver` is written from the kernel's point of view for
exactly that reason, and the interop cells use **asymmetric 8-octet cookies**
because a symmetric one cannot catch the bug.

## The kernel cells need kernel modules

`TestInteropVeepinClientKernelL2TPv3Server` and
`TestInteropKernelL2TPv3ClientVeepinServer` use the Linux kernel itself as the
peer, so `l2tp_core`, `l2tp_eth` and `l2tp_netlink` must exist on the **host** —
the containers share its kernel. **GitHub runners do not have them**, so those
two cells skip in CI and the interop table shows them as not-passed.

They do pass on any host with the modules; that is where the kernel-interop
claim comes from, and it is how the cookie-direction and sublayer behaviour were
actually verified. Run them yourself with:

```sh
cd tests/interop
docker compose -f compose.l2tpv3.yml down -v --remove-orphans
go test -tags interop -run TestInteropVeepinClientKernelL2TPv3Server -v -timeout 15m ./...
```

The veepin↔veepin cell needs no modules and runs everywhere.

## Caveats

- **No authentication and no encryption.** The cookie is a check value against
  mis-delivery and blind insertion (RFC 3931 §4.1.2.1), not a key: 8 octets, sent
  in the clear on every packet, and unchanging. Anyone who can reach the UDP port
  and observe one packet can inject frames into the bridged segment forever
  after. This is a property of L2TPv3, not of this implementation, and it is why
  the protocol is normally run inside IPsec.
- **Static sessions only.** No control plane: no SCCRQ/SCCRP/SCCCN, no
  ICRQ/ICRP/ICCN, no Hello, no StopCCN. Both ends must be configured by hand, and
  a peer expecting to negotiate will not connect.
- **Shaping covers IP only.** `flowKeyOfFrame` shapes EtherType 0x0800 and
  0x86DD; ARP, STP and everything else goes out unpadded, because Ethernet has no
  length field for a receiver to trim padding by. An observer can therefore still
  see the size of non-IP frames.
- **No sequencing.** The Default L2-Specific Sublayer is carried when configured
  but always emitted as zeros, and the sequence number is neither generated nor
  checked. Out-of-order frames are delivered in the order they arrive, which is
  what the kernel does with sequencing off too.
- **UDP encapsulation only.** IP protocol 115 (L2TPv3 directly over IP) is not
  implemented.
- **IPv4 and IPv6 underlay, one session per tunnel.** Multiple sessions in one
  tunnel are representable in `Pump` but not exposed by the facade.
