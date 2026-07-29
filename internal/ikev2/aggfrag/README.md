# internal/ikev2/aggfrag — RFC 9347 AGGFRAG (IP-TFS)

The aggregation-and-fragmentation payload that replaces a plain inner IP packet
inside an ESP SA once both peers have agreed `USE_AGGFRAG`. It is an **IKEv2
option**, not a protocol: `veepin connect ikev2 -iptfs` / `veepin serve ikev2
-iptfs`.

## The format

```
+--------+--------+--------+--------+
|SubType | Resv   |    BlockOffset  |   <- 4 octets (sub-type 0)
+--------+--------+--------+--------+
| DataBlock | DataBlock | Pad ...   |
+-----------------------------------+
```

Negotiated with the `USE_AGGFRAG` notify, status type **16442**. The ESP Next
Header becomes **144** instead of 4 or 41.

**BlockOffset is the field to get right.** It counts the octets at the *start* of
the payload that finish a block begun in an earlier packet. Zero means the
payload begins on a block boundary; a value equal to the payload length means the
packet is entirely continuation and starts no new block. A sender that prepends a
continuation but leaves the field at zero produces a stream **its own decoder
reads back perfectly** and no other implementation can — the mutually-consistent
bug class this tree tests against. `TestBlockOffsetNamesTheContinuation` asserts
the encoded octets directly rather than trusting a round trip, for that reason.

**A DataBlock has no length field.** Its first nibble is the type, and RFC 9347
chose `0x4` and `0x6` to coincide with the IPv4 and IPv6 version values so the
length can be read from the inner IP header itself. `0x0` is padding and runs to
the end of the payload. It looks like an accident;
`TestBlockTypeIsTheInnerIPVersion` exists so a tidy-up does not "fix" it.

## What is implemented

- Sub-type 0 (non-congestion-controlled) headers, both directions.
- Aggregation on receive: a peer that puts several packets in one payload —
  strongSwan does — has all of them delivered, via `dataplane.MultiTunnel`.
- Fragmentation and reassembly in both directions, including a block split
  across three or more payloads.
- Pad blocks, emitted and discarded.
- ESP next-header 144, and the `USE_AGGFRAG` negotiation in both roles. The
  responder never initiates: it echoes only when the initiator asked, because the
  notify is only an agreement when both peers send it.

## Caveats

- **One packet per payload on send.** `aggfragTunnel.Encapsulate` wraps a single
  inner packet, which is well-formed — a payload is a run of blocks and one block
  is a run of one — but it means veepin does not yet get aggregation's efficiency
  benefit on egress. Aggregating several packets needs an outbound queue and a
  timer, which `dataplane.Tunnel`'s one-in-one-out shape has nowhere to put.
- **No constant-rate transmission**, which is the half of IP-TFS that actually
  delivers traffic-flow confidentiality. `-iptfs-rate` is parsed and threaded
  through but does nothing yet. Without it, packet counts and timing still track
  the traffic inside, exactly as the README's "Scope and limitations" says of
  every other protocol here. **Do not describe veepin as providing IP-TFS
  traffic-flow confidentiality until this lands.**
- **No sub-type 1 (congestion-controlled).** Its header is 24 octets with RTT and
  loss-rate fields, and parsing it as sub-type 0 would misread every field, so it
  is rejected outright rather than guessed at.
- **A lost fragment drops the partial.** When a payload arrives on a block
  boundary while a fragment is pending, the pending head is discarded rather than
  spliced onto unrelated bytes. That loses one packet, which is the correct
  trade — the alternative corrupts one.
- **Not yet interop-tested.** There is no strongSwan cell for this; the
  negotiation and data path are covered only by unit tests and a veepin↔veepin
  path. Per this repo's own standard that means it is **not proven correct** —
  a self-test shows the two halves agree, not that either is right.
