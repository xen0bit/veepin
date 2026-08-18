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
- The `USE_AGGFRAG` **requirement flags**, which are one octet and not optional.
  RFC 9347 §6.1.4 gives the notify a one-octet body; strongSwan's
  `notify_payload.c` checks its length before it looks at anything else and
  refuses the entire IKE_AUTH message over a body of any other size. veepin sent
  it empty for as long as AGGFRAG existed here, and both veepin ends accepted
  the empty form, so nothing failed until a cell was pointed at strongSwan.
  veepin requires nothing of a peer — it reassembles, so Don't Fragment would be
  a cost for nothing, and it does not implement sub-type 1, so asking for
  congestion control it could not act on would be worse than not asking.
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
- **`Pack` owns the tail it carries; it does not borrow the caller's packet.**
  A split packet is dropped from the returned `remaining` list, which says the
  caller may reuse that buffer immediately, so `Packer` copies the tail into
  storage of its own. It used to alias, and the two statements together — "this
  packet is consumed" and "I am still reading it" — cannot both be true. Nothing
  in this package could see it, because a test that packs and unpacks without
  recycling in between agrees with itself; it took a caller with a free list to
  make it a corrupted continuation on the wire.
  `TestPackDoesNotBorrowAPacketItReportedAsConsumed` is the guard, and it needs
  no race detector.
- ~~**Not yet interop-tested.**~~ Closed: `compose.iptfs.yml`,
  `compose.iptfs-server.yml` and `compose.iptfs-self.yml` run against strongSwan
  6.0.7 in both directions.

  This caveat used to say that a self-test shows the two halves agree rather
  than that either is right, and it earned its keep twice over. Building the
  cells found the empty `USE_AGGFRAG` body above, and a second bug nothing in
  the tree could see: `dataplane`'s GRO batch path called the single-packet
  decapsulator, which rejects ESP next header 144 outright, so on any TUN with
  GSO — which is the veepin client's — every inbound AGGFRAG packet was dropped
  while the handshake reported IP-TFS negotiated and working.

  Every cell asserts a log line naming AGGFRAG, in the peer's own words:
  swanctl.opt says the iptfs mode "is subject to mode negotiation; tunnel mode
  is negotiated if the preferred mode is not available", so a veepin that failed
  to negotiate gets a working plain tunnel and a ping that crosses it.
