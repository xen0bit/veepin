# internal/l2tpv3 — L2TPv3 Ethernet pseudowire

RFC 3931 (L2TPv3) carrying Ethernet frames per RFC 4719, static sessions only.
This is veepin's only layer-2 data path.

## Files

| File | What it holds |
|---|---|
| `frame.go` | the data-packet codec: `EncodeData`, `DecodeData`, cookie verification |
| `session.go` | `SessionConfig` — session IDs, both cookies, sublayer, peer address |
| `pump.go` | the TAP↔UDP data path and `SessionIDDemux` |
| `control.go` | the RFC 3931 control-message codec and AVP parser |
| `keepalive.go` | the quiescent control connection: reliable transport + HELLO |

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

## The control connection is *quiescent*, not dynamic

veepin runs the subset go-l2tp calls a **quiescent** tunnel: the RFC 3931 control
connection with reliable transport, carrying HELLO keepalives and nothing else.
Sessions are still configured statically at both ends.

That is a deliberate stopping point, not laziness. **Nothing open-source
implements a dynamic L2TPv3 control plane.** Debian ships `xl2tpd` and `l2tpns`,
both L2TPv2/PPP. `go-l2tp` is the only implementation of an L2TPv3 control
connection, and its `getV3MsgSpec` (`l2tp/msg.go`) returns a spec for exactly one
message — HELLO; its dynamic tunnel calls `newV2Sccrq` and is L2TPv2 only.
Implementing SCCRQ/SCCRP/SCCCN and ICRQ/ICRP/ICCN would therefore produce ~900
lines testable only against themselves, which this repo's own thesis says proves
nothing.

What the quiescent connection buys is real: a static pseudowire sends nothing of
its own, so a dead peer is indistinguishable from an idle one. HELLO makes
silence mean something, and `Session.Probe` reports the control connection's idle
time when one is running.

**The control connection is not interop-verified.** `tests/interop/ql2tpd/`
and `compose.l2tpv3-keepalive.yml` build a peer and the exchange runs, but
ql2tpd never clears its own retransmit queue on our ACK and eventually declares
the tunnel down — even though a packet capture shows our ACK carrying the Nr its
own `processAckQueue` should accept. veepin's messages are demonstrably
well-formed (ql2tpd parses our HELLOs and acknowledges each one, advancing its
Nr), so the fault is not obviously ours, but it is not understood well enough to
assert on. Until it is, the control connection is covered by **unit tests only**
— which by this repo's own standard means it is not proven correct. The
reproduction is `go test -tags interop -run TestPendingQl2tpdKeepalive`.

Two details that a v2 implementation gets wrong when carried over:

- **The Control Connection ID is one 32-bit field.** v2 has a 16-bit tunnel ID
  and a 16-bit session ID; a v3 control message carries no session ID at all.
- **An acknowledgement is an explicit ACK message (Message-Type 20)**, not v2's
  zero-length body. Send a v3 peer a bare header and it sees a malformed message,
  not an ack, and never clears its retransmit queue.
  `TestAckIsAnExplicitMessageNotAnEmptyBody` holds that in place.

## Caveats

- **No authentication and no encryption.** The cookie is a check value against
  mis-delivery and blind insertion (RFC 3931 §4.1.2.1), not a key: 8 octets, sent
  in the clear on every packet, and unchanging. Anyone who can reach the UDP port
  and observe one packet can inject frames into the bridged segment forever
  after. This is a property of L2TPv3, not of this implementation, and it is why
  the protocol is normally run inside IPsec.
- **Static sessions only.** The control connection carries HELLO, ACK and
  StopCCN; there is no SCCRQ/SCCRP/SCCCN or ICRQ/ICRP/ICCN, so sessions and
  cookies must be configured by hand at both ends and a peer expecting to
  negotiate will not connect. See the section above for why.
- **The control connection is unauthenticated.** RFC 3931 offers a Message
  Digest AVP with a shared secret; it is not implemented, and an inbound hidden
  AVP is rejected rather than mis-parsed. The Control Connection ID is checked on
  every message, which stops an off-path sender resetting the sequence state by
  guessing, but it is a 32-bit value in the clear, not a key.
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
