# Scaling the data path past one core per direction

Status: **design note; Option 1 is built.** The UDP batching primitive
(`dataplane.BatchConn`) is implemented and measured,
`dataplane.PacketConn.ReadBatch`/`WriteBatch` carry it into the shared socket
wrapper, every single-socket UDP read loop — server and client, across IKEv2,
WireGuard, OpenVPN, Nebula, and L2TP — reads through one of the two, and the
TUN half is in: `OpenTUNGSO` negotiates the virtio-net header path so the
kernel hands the pump TCP super-frames, which segment in userspace
(offload_linux.go) and egress as one batched send (IKEv2, WireGuard, OpenVPN —
server and client). Not built: GRO (write-side TUN coalescing), TSO6/USO, and
everything under Option 2. Written while sharpening the
[security boundary](security.md#throughput-is-bounded-by-one-core-per-direction)
that states the current ceiling. It captures which protocols the ceiling actually
binds, the two levers that lift it (in the order worth trying them), and the
single-goroutine *assumptions* a naive parallelization would break — so the work
is scoped honestly rather than half-built.

## Which protocols this even affects

Split the protocols by how they read inbound traffic, because that is where the
ceiling lives:

- **Single-socket UDP demux** — IKEv2, WireGuard, OpenVPN, Nebula, L2TP. Every
  client's ingress funnels through one socket-reader goroutine, and egress
  through the one `Pump.Run` TUN reader. **This is the only class with the
  ceiling.**
- **Connection-per-client** — SSTP, SSH, AnyConnect, Fortinet, MASQUE. Each
  client is its own TCP/TLS/QUIC connection with its own goroutine, so these
  already scale across clients on the Go runtime for free. They need nothing
  here.

So "let every protocol inherit parallelism" is the wrong target: half of them
already have it. The work is for the single-socket class — and, usefully, most of
that class (`ikev2`, `wireguard`, `openvpn`, `nebula`) already shares
`dataplane.Pump` for egress, so shared machinery can carry the fix.

## The current model

A single-socket server runs exactly two data-path goroutines, one per direction,
both shared across every client:

- **Outbound** — `dataplane.Pump.Run` (dataplane/pump.go) reads the TUN in one
  loop, and for each packet looks up the tunnel, encapsulates, and sends.
- **Inbound** — the transport's socket reader (e.g. `internal/ikev2/ike`
  `transport.serve`, the UDP/4500 goroutine) reads every ESP datagram for every
  client and calls `Pump.HandleInbound`, which decapsulates and writes the TUN.

Adding clients adds no parallelism. The crypto is not the bottleneck — `ESPCrypter`
holds no shared mutable state and scales linearly (`BenchmarkESPDecapParallel`) —
the plumbing above it simply never calls it from more than one goroutine.

## Profile before choosing

One core already does **~15 Gbit/s of AES-GCM** (ESP decap benches at ~2 GB/s at
1400 B). At that rate the limit is almost never the cipher; it is the
**per-packet syscall cost** of reading the TUN and the UDP socket one datagram at
a time. So the first task is to confirm *where* the time goes — a CPU profile of a
saturated single tunnel. If it is syscall-bound (it usually is), the lever below
that removes syscalls beats the one that adds cores, and does so without any
reordering risk.

## Option 1 (try first): batch the syscalls

Cut the number of read/write/send calls per packet instead of adding goroutines.
This is the first lever to pull for a userspace VPN — it works *on a single
core*, carries **no packet-reordering risk**, and needs no change to any
protocol's per-SA state. It is also where the reference `wireguard-go` got its
throughput, not from more goroutines.

- **UDP:** `recvmmsg`/`sendmmsg`, wrapped by `golang.org/x/net/ipv4`'s
  `PacketConn.ReadBatch`/`WriteBatch` (`x/sys/unix` has no mmsg wrappers), to
  move a batch of datagrams per syscall on both the inbound socket and the
  `Sender`. `dataplane.BatchConn` is this primitive, measured below.
- **TUN:** the virtio-net header path (`IFF_VNET_HDR`) so the kernel hands up /
  accepts back GSO super-frames — one read/write for many segments — with
  segmentation offloaded. `dataplane.OpenTUNGSO` negotiates it
  (`TUN_F_CSUM|TUN_F_TSO4`, falling back to a plain TUN on kernels that
  refuse), and offload_linux.go is the userspace TSO: header replication,
  per-segment length/ID/sequence fixups, and full checksum computation —
  `TUN_F_CSUM` also hands us the NIC partial-checksum contract to finish,
  GSO frame or not.

The two halves are not symmetric, and the asymmetry decides what can be built
when. **Inbound UDP batching stands alone**: `recvmmsg` drains whatever the
socket has queued and blocks for one datagram when it has nothing, so it batches
under load and adds no latency when idle. `dataplane.PacketConn.ReadBatch` is
that, with each message carrying its own `IP_PKTINFO` control data so batched
reads keep the wrapper's source-address pinning. Every single-socket read loop
now reads this way: the IKEv2, WireGuard, OpenVPN, and L2TP servers, the Nebula
host, and the IKEv2, WireGuard, OpenVPN, and L2TP client loops (connected client
sockets use the bare `dataplane.BatchConn`; the toy example keeps its plain
single-read loop on purpose — it is teaching code). Each adoption carried its
own buffer-retention audit, and the audits split the loops in two:

- **Data packets ride borrowed buffers.** For the flat protocols (IKEv2 ESP,
  WireGuard transport data, OpenVPN data opcodes, Nebula messages) the handler
  chain decrypts in place and writes the TUN before returning, so the loop hands
  the batch buffer over directly — the per-packet copy the single-read loops
  made is gone from these hot paths. Control-plane packets (handshakes, rekeys,
  session control) are still copied out, because their handling outlives the
  batch.
- **L2TP copies everything, data included.** The engine behind its ESP handler
  parses control AVPs whose handling may alias the packet beyond the loop, so
  only its syscalls are batched, not the buffer ownership.

**Outbound batching needed the TUN half first**: a plain TUN read yields one
packet, so there was no accumulation point — holding a packet hoping a second
arrives adds latency on exactly the interactive traffic that would notice. A
GSO super-frame *is* the accumulation point: it segments into a burst that all
belongs to one tunnel (one route lookup for the lot), and
`Pump.SetBatchSender` flushes the encapsulated burst in one `sendmmsg` — via
`PacketConn.WriteBatch` on the servers (source-pinned per message) and
`BatchConn` on the connected client sockets. One TUN read becomes one UDP
syscall, instead of N reads and N sends. The kernel produces super-frames only
when the sending application outpaces the wire — exactly when batching pays —
and idle or interactive traffic arrives as ordinary packets on the same loop,
so nothing waits on a timer.

What the TUN half is *not*, yet: **GRO** — the write side still puts one
decapsulated packet per TUN write (vnet-framed with a zero header). Coalescing
inbound TCP back into super-frames the kernel accepts in one write is the
symmetric other half, a flow table away; it is the remaining piece of Option 1.
TSO6 and UDP GSO stay un-negotiated (the tree tunnels IPv4, and no data path
here carries bulk UDP inner flows). Protocols with their own TUN loops (Nebula,
L2TP, and the toy on purpose) keep plain TUNs — a GSO TUN may only be driven
by the pump's vnet loop. There is no loopback micro-benchmark for this half —
a real TUN needs CAP_NET_ADMIN — so its win shows where it should: the living
throughput table, measured over real tunnels in CI. The segmentation itself is
unit-tested (checksums verified the way a receiver would, allocation-free in
steady state).

### Measured: what the UDP half alone buys

`dataplane/batchconn_test.go` benchmarks mmsg batching in isolation — 1400-byte
datagrams over loopback, `strace`-confirmed one `sendmmsg`/`recvmmsg` per batch:

| direction | one datagram per syscall | batched | gain |
|-----------|--------------------------|---------|------|
| send | ~4.8 µs/pkt (~290 MB/s) | ~3.8 µs/pkt (~365 MB/s), saturates at batch-8 | ~20–25% |
| receive | ~0.9 µs/pkt (~1.6 GB/s) | ~0.67 µs/pkt (~2.1 GB/s), saturates near batch-64 | ~15–33% |

How to read that honestly:

- **The send gain is real but loopback under-sells it.** Batching removes a
  fixed ~1 µs/packet of syscall entry; the residual ~3.8 µs is loopback's
  *inline per-datagram delivery*, cost that on a real NIC lives in the TX ring
  and softirq, not in the send call. Treat the measured number as the floor.
- **Batched receive dequeues at ~2.1 GB/s — parity with the single-core AES-GCM
  rate** ([benchmarks](benchmarks.md)). After batching, the inbound syscall and
  the cipher cost about the same, which is as good as the UDP half gets:
  "multiplies throughput" would be too strong for mmsg alone. The multiplier,
  if there is one, is the TUN GSO half — unmeasured, because it needs a real
  TUN device.
- **One wiring caveat:** `x/net/ipv4.ReadBatch` allocates each datagram's
  source address (2 allocs, ~52 B per packet), where the old single-read paths
  used `ReadFromUDPAddrPort` and allocated nothing. `WriteBatch` is
  allocation-free. The wiring accepts that cost: on the flat protocols it is
  more than paid for by the dropped per-packet data copy, and hand-rolling
  `recvmmsg` stays the escape hatch if a profile ever blames it.

Egress lives entirely in `Pump`, so the GSO path is **inherited by every
pump-using protocol** for the price of two lines in its facade: open the TUN
with `OpenTUNGSO`, and hand `SetBatchSender` a batch-capable send (IKEv2,
WireGuard, and OpenVPN did, server and client). (Inbound batching did not need
the shared UDP source described below after all — `PacketConn.ReadBatch` wrote
the mechanism once and each read loop adopted it in place.) The `Tunnel`
interface is unchanged — `Encapsulate`/`Decapsulate` are still called once per
inner packet, and `Encapsulate`'s one-seal-allocation contract is what lets the
pump hold a whole burst's outputs before flushing; only the TUN and transport
syscalls are amortised.

Batching alone may lift the ceiling far enough that Option 2 is never needed.

## Option 2 (if still CPU-bound): parallelize, with per-tunnel affinity

If profiling shows the work is genuinely CPU-bound after batching — the busy
multi-client concentrator case, where aggregate crypto across hundreds of
road-warriors exceeds one core per direction — then add worker goroutines. The
design that lets protocols **inherit parallelism *and* safety unchanged** is
per-tunnel affinity:

> Shard tunnels across N workers and pin each tunnel to exactly one worker. A
> tunnel is never touched by two goroutines at once; only *cross-tunnel* work runs
> in parallel.

That is the whole trick. Every protocol's data path was written assuming one
goroutine per SA (see the hazards below); affinity preserves that assumption
verbatim, so no `Tunnel` implementation has to be re-audited. The mechanism:

- **Inbound — shared `dataplane` UDP source + `SO_REUSEPORT`.** Move socket
  ownership out of each protocol into a small shared source that opens N sockets
  on the port, runs one reader goroutine each, and calls a handler + `Demux`. The
  kernel hashes each datagram's 4-tuple to one socket, so a given peer lands on
  one reader — per-peer affinity for free. The single-socket protocols opt in by
  swapping their read loop for the source; the connection-per-client protocols
  never touch it.
- **Outbound — multi-queue TUN (`IFF_MULTI_QUEUE`), N `Pump.Run` loops.** This is
  the side with the wrinkle: the kernel distributes TUN packets by *inner-flow*
  hash, which does **not** align with our tunnel-ownership sharding, so a queue
  reader can hold a packet for a tunnel another worker owns. Either make the
  owning worker do the encap (hand the packet to it over a per-worker queue —
  restores affinity, costs a hop) or make `Encapsulate` concurrency-safe for that
  one SA (an atomic ESP sequence counter — see hazard 2). The hand-off keeps the
  affinity contract clean and is the safer default.

Both options are `x/sys/unix` socket/ioctl surface, not new dependencies —
consistent with how the tree already does PMTU and source-address selection.

## What breaks if you skip affinity and just add goroutines

Several data paths were deliberately made allocation-free by keeping **per-SA
scratch that is only safe because one goroutine touches it.** These are exactly
what per-tunnel affinity protects; drop affinity and they become races, not
slowdowns:

1. **Inbound receive-nonce scratch is per-SA, single-goroutine.** OpenVPN reuses a
   per-`Cipher` receive-nonce buffer and Nebula/DTLS a per-tunnel / per-`aeadState`
   scratch, each documented "safe because open runs on the single inbound
   goroutine." Two packets of the *same* SA opening concurrently races that
   scratch. Affinity (or `SO_REUSEPORT` per-4-tuple, treated as an optimisation
   not a guarantee, since a roaming peer can move) keeps a single SA on one worker.

2. **Outbound ESP sequence numbers are a per-SA counter.** `Encapsulate` assigns
   the next anti-replay sequence number. Two workers encapsulating for the same SA
   assign duplicates and the peer's replay window drops one — this is the outbound
   wrinkle above. Fixed by the hand-off, or an atomic counter. (Seal itself is
   already concurrency-safe: the nonce is built in the output buffer's own tail,
   no shared scratch.)

3. **The pump's `byKey`/`routes` maps are `RWMutex`-guarded.** One reader holds the
   `RLock` at a time today; N readers taking it per packet is read-mostly but the
   lock traffic is real. Swap an immutable snapshot on `AddTunnel`/`RemoveTunnel`
   (RCU-style) to remove per-packet locking entirely — a pure win, worth doing
   before the reader count is raised.

4. **Reordering within a flow.** Flow/tunnel-sharded workers keep a single
   5-tuple in order; anything that round-robins packets reintroduces reordering
   that TCP reads as loss. Affinity is precisely what avoids it — any deviation
   has to be justified against this.

## Sequencing

1. **Profile a saturated tunnel.** Confirm CPU-bound vs syscall-bound; it decides
   whether Option 2 is even worth starting.
2. **Option 1 — batching: done.** Ingress: `PacketConn.ReadBatch` /
   `BatchConn` in every single-socket read loop, measured above. Egress:
   `OpenTUNGSO` + userspace TSO + `SetBatchSender` flush in the pump
   protocols. Remaining inside Option 1: GRO on the TUN write side.
3. **Lock-free pump map** (hazard 3). Pure win, testable in isolation, de-risks
   Option 2.
4. **Option 2 — per-tunnel-affinity workers**: shared `SO_REUSEPORT` source
   inbound, multi-queue TUN with hand-off outbound. Guard with the interop matrix
   plus a new multi-reader stress test.
5. Validate with a multi-core benchmark **and** the full interop matrix. A
   reordering regression shows up as a throughput cliff on the TCP-carried cells,
   not a test failure, so watch the living throughput table across the change.

None of this is urgent: one core per direction is already several Gbit/s, and no
workload here is asking for more. The value of writing it down is that the
single-goroutine assumptions are invisible until someone adds a goroutine — so
this note exists to be read *before* that happens, not after.
