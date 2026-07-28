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
that one core can do — inbound reads drain in `recvmmsg` batches, on
GSO-capable TUNs one read can carry a TCP super-frame that egresses as one
batched send, and inbound bulk TCP coalesces back into super-frames written to
the TUN once (GRO) — without changing the boundary. Lifting the ceiling means
adding
readers (multi-queue TUN outbound, `SO_REUSEPORT` inbound), which brings
packet-reordering risk and lock contention that nothing here is currently asking
for — the approach and its costs are sketched in
[`doc/scaling-the-data-path.md`](scaling-the-data-path.md).

## GlobalProtect has no key exchange and no forward secrecy

This is the protocol's design, not veepin's implementation of it. A Palo Alto
gateway generates both ESP SPIs and all four ESP keys itself and sends them to
the client **inside the getconfig response**, protected only by the HTTPS session
carrying it. Nothing is negotiated and no ephemeral key is involved.

The consequences are worth stating plainly:

- Anyone who can read one session's configuration document can decrypt that
  session's traffic for its whole life. Recording the ciphertext and obtaining
  the document later is enough; there is no forward secrecy to lose.
- Compromise of the gateway's TLS private key retroactively exposes every session
  whose control exchange was recorded, because that exchange *is* the key
  exchange.
- A rekey is another fetch of the same document over the same channel, so it
  changes the keys but not this property.

veepin implements the protocol faithfully because interoperating with real
GlobalProtect gateways is the point. It is the weakest of the IPsec-carrying
protocols in this tree, and IKEv2 or WireGuard should be preferred wherever the
choice exists. See [`internal/gp/README.md`](../internal/gp/README.md).

## Cisco IPsec exposes the group identity, and its group key protects everything

IKEv1 Aggressive Mode trades identity protection for two round trips. The three
messages carry, in the clear: the group name the client presents as its phase-1
identity, both Diffie-Hellman public values, both nonces, and the responder's
authenticating hash. That hash is computed over the group pre-shared key, so a
passive observer who records one handshake can attack the group key offline, at
whatever rate the key's entropy allows.

This is a property of the protocol, not of this implementation — it is what
strongSwan makes an operator write
`charon.i_dont_care_about_security_and_use_aggressive_mode_psk = yes` to enable.
The consequences:

- The group key must be a high-entropy secret. It is shared by everyone in the
  group and it is the only thing standing between a recorded handshake and the
  session keys, so treating it as a memorable passphrase defeats the protocol.
- XAuth does not repair this. The user's password travels inside phase-1
  encryption, so a passive observer does not learn it — but anyone holding the
  group key can stand up a gateway that clients will authenticate to, and collect
  passwords from it.
- Compromise of the group key does not retroactively expose recorded sessions on
  its own: phase 1 is an ephemeral Diffie-Hellman exchange, so forward secrecy
  survives. What it exposes is every *future* session, actively.

veepin implements this faithfully because it is what the deployed clients speak.
IKEv2 — the same tree, the same ESP data path — has neither weakness, and should
be preferred wherever the choice exists. See
[`internal/cisco/README.md`](../internal/cisco/README.md).

## Ivanti Connect Secure pushes its ESP keys rather than negotiating them

Like GlobalProtect, this protocol has no key exchange for its data path. Unlike
GlobalProtect, each end mints its own direction: the gateway sends a keying
block for the traffic it will receive, the client answers with one for the
traffic it will receive, and both travel inside the authenticated TLS session.

That difference is real but small. It means neither end alone chooses both
directions' keys, so a weak random source at one end does not compromise the
other. It does not restore forward secrecy: the keys are sent, not derived, so
whoever can read one session's configuration exchange can decrypt that session's
ESP traffic for as long as those keys are in use, and recording the ciphertext
and obtaining the exchange later is enough.

The practical consequence is where the security actually sits. The TLS session
is the whole of the data path's confidentiality — the gateway's certificate and
private key protect the ESP keys and nothing else does. A compromise of that key
retroactively exposes every session whose exchange was recorded.

The IF-T/TLS data path, taken when UDP does not get through, has the opposite
property: it is protected by the TLS session directly, so it inherits whatever
forward secrecy the negotiated TLS suite provides. It is the slower path and the
better-protected one.

veepin implements this faithfully because interoperating with real Ivanti
gateways is the point. IKEv2 and WireGuard should be preferred wherever the
choice exists. See [`internal/pulse/README.md`](../internal/pulse/README.md).

## MASQUE carries every inner packet on one reliable QUIC stream

Because `x/net/quic` has no QUIC DATAGRAM frames, CONNECT-IP runs in capsule
mode, so inner packets are delivered reliably and in order rather than as
unreliable datagrams. On a lossy path this reintroduces head-of-line blocking —
the classic "TCP over a reliable tunnel" pathology — and it is why MASQUE is the
one protocol here whose data path is not the profile the protocol is designed
for. It is a performance boundary, not a security or correctness one, and it is
confined to MASQUE; the moment `x/net/quic` gains datagram support the transport
swaps under an unchanged data path.
