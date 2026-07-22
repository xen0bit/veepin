# Security boundaries: what veepin does not protect against

Two boundaries are worth stating outright, because both are the kind of thing a
reader may otherwise assume is handled. Neither is an oversight — each is a
deliberate limit of a readable, self-contained implementation.

## Key material is not zeroed after use

Session keys, derived secrets and private keys are left for the garbage
collector. This is deliberate rather than overlooked. Go's collector moves and
copies objects, so a `[]byte` holding a key may have been duplicated to somewhere
the code holding it cannot name, and overwriting the copy that is still reachable
would clear one of several. Doing that would produce code that *looks* like it
wipes keys while leaving them in memory anyway — worse than not doing it, because
the appearance invites confidence the implementation has not earned.

The honest consequence: **veepin does not claim protection against an attacker
who can read process memory.** An adversary with a core dump, a debugger, swap
access, or code execution in the process recovers live session keys. Defend that
boundary at the layer that can actually hold it — process isolation, disabled
core dumps, encrypted swap — not by hoping the language cooperated.

## Throughput is bounded by one core per direction

The data path runs on two goroutines per server, one per direction, and both are
shared across every tunnel rather than being per-client:

- **Outbound:** `dataplane.Pump.Run` reads the TUN from a single goroutine,
  encapsulating and sending every client's egress in turn.
- **Inbound:** a single-socket server (IKEv2 on UDP/4500) reads that socket from
  one goroutine and decapsulates every client's ingress in turn.

So the ceiling is roughly one core per direction for the *whole* server, not just
per tunnel — adding clients does not add parallelism. The crypto is not the limit:
the `ESPCrypter` is safe to call concurrently and scales linearly with cores
(`BenchmarkESPDecapParallel`), so it is *parallel-ready* even though the deployed
path drives it from a single goroutine. The syscalls are batched to raise what
that one core can do — inbound reads drain in `recvmmsg` batches, and on
GSO-capable TUNs one read can carry a TCP super-frame that egresses as one
batched send — without changing the boundary. Lifting the ceiling means adding
readers (multi-queue TUN outbound, `SO_REUSEPORT` inbound), which brings
packet-reordering risk and lock contention that nothing here is currently asking
for — the approach and its costs are sketched in
[`doc/scaling-the-data-path.md`](scaling-the-data-path.md).

## MASQUE carries every inner packet on one reliable QUIC stream

Because `x/net/quic` has no QUIC DATAGRAM frames, CONNECT-IP runs in capsule
mode, so inner packets are delivered reliably and in order rather than as
unreliable datagrams. On a lossy path this reintroduces head-of-line blocking —
the classic "TCP over a reliable tunnel" pathology — and it is why MASQUE is the
one protocol here whose data path is not the profile the protocol is designed
for. It is a performance boundary, not a security or correctness one, and it is
confined to MASQUE; the moment `x/net/quic` gains datagram support the transport
swaps under an unchanged data path.
