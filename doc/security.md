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
who can read process memory.** An adversary with a debugger, or code execution
in the process, recovers live session keys. Defend that boundary at the layer
that can actually hold it, not by hoping the language cooperated.

Two of those layers the process can take itself, and `veepin serve` now offers
both. They are off by default because each trades something real:

- **`-lock-memory`** — `mlockall(MCL_CURRENT|MCL_FUTURE)`. No page of the
  process reaches swap, so key material cannot be recovered from a swap
  partition or file afterwards. The cost is that the whole resident set becomes
  unswappable, which on a memory-constrained host trades an availability risk
  for a confidentiality gain. It needs `CAP_IPC_LOCK` or `RLIMIT_MEMLOCK`
  headroom (`LimitMEMLOCK=infinity` in a systemd unit).
- **`-no-core-dumps`** — `prctl(PR_SET_DUMPABLE, 0)`. A crash writes no core
  file carrying live session keys, and a same-uid process cannot `ptrace` in.
  The cost is that `/proc/self` becomes root-owned, which a deployment reading
  its own `/proc` entries for monitoring needs to know.

**Both fail loudly rather than silently.** A refused `mlockall` aborts the
server; it does not warn and continue. A hardening switch that quietly does
nothing is worse than no switch at all, for exactly the reason given above about
fake key wiping — the appearance invites confidence the process has not earned.
For the same reason, a partial application is never reported: asking for both
and getting one is an error, not a success with a caveat.

What remains uncovered, and is not reduced by either: a debugger with
`CAP_SYS_PTRACE`, a hypervisor, a kernel exploit, or anything with code
execution in the process. See [`internal/harden`](../internal/harden). Both are
Linux-only, and on other platforms requesting either is an error rather than a
no-op.

## Throughput is bounded by one core per direction

The data path runs on two goroutines per server, one per direction, and both are
shared across every tunnel rather than being per-client:

- **Outbound:** `dataplane.Pump.Run` reads the TUN from a single goroutine,
  encapsulating and sending every client's egress in turn.
- **Inbound:** a single-socket server (IKEv2 on UDP/4500) reads that socket from
  one goroutine and decapsulates every client's ingress in turn.

So the ceiling is roughly one core per direction for the *whole* server, not just
per tunnel — adding clients does not add parallelism. Measured, that one core is
17.7 Gbit/s inbound and 14.7 Gbit/s outbound at 1400-byte packets with the
syscalls removed. The crypto is not the limit: the `ESPCrypter` holds no shared
state and is safe to call concurrently, so it is *parallel-ready* even though the
deployed path drives it from a single goroutine.

It is worth being precise about how much that readiness is worth, because it was
overstated here as "scales linearly with cores." It does not.
`BenchmarkESPDecapParallel` — an independent SA per goroutine, nothing shared —
plateaus at **2.4×** the single-core rate and regresses past sixteen threads,
because the one allocation per packet that the data path's contract permits makes
the collector the binding constraint before the cipher is. The same benchmark
under `GOGC=off` reaches 8.8×. So the parallelism is available in the cipher and
not yet reachable through the allocator; see
[`doc/scaling-the-data-path.md`](scaling-the-data-path.md#measured-the-profile-option-2-was-gated-on-taken). The syscalls are batched to raise what
that one core can do — inbound reads drain in `recvmmsg` batches, on
GSO-capable TUNs one read can carry a TCP super-frame that egresses as one
batched send, and inbound bulk TCP coalesces back into super-frames written to
the TUN once (GRO) — without changing the boundary. Lifting the ceiling means
adding
readers (multi-queue TUN outbound, `SO_REUSEPORT` inbound), which brings
packet-reordering risk and lock contention that nothing here is currently asking
for — the approach and its costs are sketched in
[`doc/scaling-the-data-path.md`](scaling-the-data-path.md).

## veepin is a road-warrior VPN on purpose

Every server here assigns a client an address out of a pool and routes to that
address. That is the shape of the whole tree: `client.Result` describes an
interface address and the routes to install for it, config mode (or its
equivalent in fifteen other protocols) hands out the lease, and a tunnel's
traffic selector narrows to the address that was assigned.

**A site-to-site gateway is a different thing, and veepin is not one.** What that
would mean concretely, in IKEv2 terms: traffic selectors that are subnets rather
than one assigned host address, several Child SAs under one IKE SA with
different selectors, no config mode at all because both ends already have their
own addressing, and a `client.Result` that describes a route *set* rather than an
interface address. The last of those is a change to the `client` contract every
protocol implements, which is why this is a program and not a feature.

This is a decision, not an omission, and it is recorded here so that it is
answered on purpose rather than by drift. The evidence for it is available if it
is ever revisited — strongSwan does both roles, so a site-to-site cell would have
a real peer and would not ship with a veepin↔veepin cell as its only proof. What
argues against it is that it would be the largest capability in the tree,
resting on a contract change under sixteen protocols, in service of a deployment
nobody here has asked for. The README's IKEv2 bullet says "deliberately" for this
reason.

Two things follow for anyone reading the tree:

- **Do not read a `-pool` as a site-to-site selector.** A server hands out host
  addresses; it does not route a peer's subnet.
- **A protocol's traffic-selector narrowing is a road-warrior narrowing.**
  `TSi` is answered with the assigned lease (RFC 7296 §2.19's worked example),
  which is correct for a client and wrong for a gateway that owns a subnet.

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

## IKEv2 over TCP costs reliability where reliability is not wanted

`-tcp` (RFC 8229, updated by RFC 9329) exists for one reason: a network that
passes TCP and drops UDP. On such a network it is the difference between a
tunnel and no tunnel, which is why it is here. On any other network it is a
worse transport than UDP, in three specific ways an operator should choose
knowingly.

**Head-of-line blocking, the same pathology MASQUE has above.** ESP is a
datagram protocol carried on a reliable ordered stream: one lost segment stalls
every inner packet behind it while TCP retransmits, and inner TCP then
retransmits on top of that. Do not turn `-tcp` on for a client whose UDP works.

**A stream does not hide packet boundaries.** Each frame carries its own 16-bit
length, so an observer counting bytes on the connection sees the same size
sequence they would have seen as datagrams. Anything `doc/traffic-shaping.md`
says about what padding does and does not hide applies unchanged; TCP
encapsulation is not itself an obfuscation.

**It is distinguishable from TLS on inspection.** The stream opens with the six
ASCII octets `IKETCP` and then length-prefixed IKE, which does not resemble a
TLS ClientHello. `-tcp` defeats a network that blocks UDP by port or protocol,
not one doing protocol identification — for the latter the answer is one of the
TLS-carried protocols in this tree, not this.

What is *not* weakened: ESP replay protection is unchanged. TCP delivers in
order, but a rekey or a reconnect can still replay, so the sliding window stays
exactly as it is on UDP. Authentication, the negotiated suites and the key
schedule are untouched — this is the carrier, not the cryptography. MOBIKE is
refused rather than degraded, because the connection is the address binding.

## Post-quantum IKEv2 protects the key exchange, not the authentication

Hybrid PQ IKEv2 (RFC 9370, RFC 9242, and RFC-ietf-ipsecme-ikev2-mlkem) layers
ML-KEM-768 (FIPS 203) on top of the classical Diffie-Hellman in IKE_SA_INIT via
an IKE_INTERMEDIATE exchange. The derived SKEYSEED is at least as strong as the
strongest component — an adversary who breaks the classical Curve25519 half still
has ML-KEM in the way.

Two things this does NOT protect:

- **Authentication remains classical.** The AUTH payload in IKE_AUTH is still
  keyed by the PSK, EAP-MSCHAPv2 MSK, or certificate signature, all of which are
  classical cryptography. A quantum adversary attacking the authentication *live*
  (rather than retroactively) can forge credentials.

- **Downgrade must be detected by the AUTH computation.** The IKE_INTERMEDIATE
  messages are folded into the AUTH payload (RFC 9242 §3.3), so an attacker who
  strips the intermediate exchange from a captured handshake cannot retroactively
  forge the matching AUTH. `TestAuthOctetsPutsIntAuthLast` and
  `TestFinalIntAuthOrdersInitiatorThenResponderThenMsgID` pin the construction,
  and `TestInteropVeepinClientStrongswanServerPQ` /
  `TestInteropStrongswanClientVeepinServerPQ` prove the AUTH values match a real
  strongSwan. A misimplementation that omits the folding would silently downgrade
  the key exchange to classical-only, and both endpoints would agree with each
  other about it — which is why the cross-implementation cells, not the unit
  tests, are the load-bearing evidence here.

The ML-KEM implementation uses the Go standard library's `crypto/mlkem`, which
is a dependency-free path (no new module beyond the stdlib). The IANA group ID
for ML-KEM-768 in IKEv2 is 36.


## Every TLS 1.3 protocol has a post-quantum key exchange, and its authentication is classical

Post-quantum key exchange in this tree is not only IKEv2's. Go's `crypto/tls`
has led its default `CurvePreferences` with **X25519MLKEM768** (CurveID 4588)
since Go 1.24, and veepin pins `CurvePreferences` nowhere. So every TLS 1.3
handshake here is hybrid — Curve25519 and ML-KEM-768 both, with the derived
secret at least as strong as the stronger half.

Concretely:

- **MASQUE is post-quantum unconditionally.** All three of its `tls.Config`s are
  TLS 1.3-only.
- **OpenVPN's server is too, as of the `SessionTicketsDisabled` change.** It was
  the one exception: capped at TLS 1.2 because TLS 1.3's post-handshake
  `NewSessionTicket` stalled clients on OpenVPN's half-duplex control channel,
  and only TLS 1.3 carries a `key_share`. Suppressing the tickets removes the
  cause instead of the version.
- **AnyConnect, Fortinet, GlobalProtect, Ivanti, SSTP, SoftEther and the OpenVPN
  client** are hybrid whenever the peer negotiates TLS 1.3, which every current
  one does. Their floor is TLS 1.2 for vendor compatibility, and at 1.2 the key
  exchange is classical.

Three things this does **not** cover, and each is a real boundary:

- **Authentication is classical by default, and no longer has to be.** The same
  limit [post-quantum IKEv2 has](#post-quantum-ikev2-protects-the-key-exchange-not-the-authentication):
  a certificate signed with RSA or ECDSA leaves an adversary attacking the
  authentication *live* rather than retroactively unaffected.

  Go 1.27's `crypto/mldsa` closes it, inside the dependency policy and with no
  new module. `crypto/x509` mints, marshals and verifies ML-DSA certificates,
  `crypto/tls` offers `MLDSA44/65/87` as TLS 1.3 signature schemes, and veepin's
  credential paths carry them without any protocol work — they load PEM and hand
  it to `tls.X509KeyPair`, which is the whole of what is needed.
  `TestAFullyPostQuantumHandshake` pins both halves at once (ML-KEM key exchange
  and an ML-DSA signature), and `TestServerAcceptsMLDSACredentials` does it
  through a real facade with **mutual** authentication, so both signatures on
  the connection are post-quantum.

  **It is opt-in and it is not the default**, for one reason: an ML-DSA
  certificate is only useful against a peer that accepts one, and most deployed
  clients do not yet. Point a veepin server at an ML-DSA certificate and key and
  the handshake is post-quantum end to end; point it at an RSA one and it is
  hybrid on the key exchange and classical on the signature, as before.
- **The DTLS data channels are not.** `internal/dtls` is a from-scratch DTLS 1.2
  with two fixed suites and no post-quantum path at all, so AnyConnect's and
  Fortinet's *data* channels stay classical even when their control channels do
  not.
- **A protocol that ever pins `CurvePreferences` silently drops out of this
  list.** The handshake still succeeds; it is just classical again.
  `TestNoTLSConfigPinsCurvePreferences` is what stops that happening in a commit
  about something else, and `TestGoDefaultsStillNegotiateMLKEM` is what stops the
  guard from outliving the default it assumes.


## SoftEther is layer 2, and shares a broadcast domain between clients

Every other protocol here routes IP. SoftEther bridges Ethernet, which means
connected clients share a broadcast domain: ARP, DHCP, mDNS and anything else
that floods reaches every other client. A learning bridge limits *unicast* to
the port that owns the destination MAC, but it floods anything it has not
learned, and nothing stops a client claiming another's MAC to attract its
traffic. There is no port isolation and no MAC pinning.

The login digest is **SHA-0** — the 1993 algorithm withdrawn a year later,
which differs from SHA-1 by one missing rotate in its message schedule — over
`password + UPPER(username)`, hashed again against a 20-octet per-session
server challenge. That is what the protocol specifies, verified against the
reference implementation's own compiled code rather than assumed; veepin
computed SHA-1 over a different construction until a cell against a real
SoftEther server said otherwise.

What rests on it is worth stating precisely, because "SHA-0" reads worse than
the situation is. The digest authenticates a login **inside TLS**, and it is
not used to key anything: no session key, no traffic protection, no integrity
on the data path derives from it. SHA-0's weakness is collision resistance, and
a login exchange needs preimage resistance, against which SHA-0 has no
published break. The real exposures here are elsewhere and are structural: the
server must hold the **plaintext password**, because the response is computed
from it rather than from a verifier, and the challenge binding is the only
thing between a recorded login and a replayed one.

The data path is TLS-only — SoftEther's UDP acceleration is not implemented — so
inner traffic inherits TCP head-of-line blocking, and the gateway sees every
frame in the clear between the TLS termination and the bridge.

`internal/softether/README.md` lists what is not implemented. The client
direction is verified against SoftEther VPN Server; the server direction has no
cross-implementation cell yet, so what a real SoftEther client makes of veepin's
server is stated there as unknown rather than claimed as working.

## AmneziaWG changes what packets look like, not what they protect

AmneziaWG is WireGuard with the wire format perturbed: the message-type byte is
replaced (H1-H4), random padding is prepended (S1-S4), and junk datagrams
precede the handshake (Jc/Jmin/Jmax). The cryptography is untouched — the same
Noise IK handshake, the same ChaCha20-Poly1305 transport keys, the same forward
secrecy and the same rekey behaviour as `wireguard`.

What this buys and what it does not:

- **It defeats a signature match, not an analyst.** Stock WireGuard is
  identifiable from one packet: a fixed type constant followed by three zero
  bytes, at one of three fixed lengths. Changing both defeats a classifier
  keyed on those. It does not disguise the *traffic pattern* — packet timing,
  flow duration and volume are unchanged, and a censor doing statistical
  analysis rather than signature matching is unaffected.
- **The parameters are a shared secret in practice.** There is no negotiation,
  deliberately, since a negotiation would itself be a signature. That means a
  mismatch is a total failure rather than a fallback, and it means anyone who
  learns a deployment's parameters can fingerprint it precisely.
- **The padding is not confidentiality.** S1-S4 prepend *unauthenticated*
  random bytes outside the AEAD. They change the length distribution and
  nothing else; an attacker may strip or rewrite them freely, and doing so
  costs them nothing and gains them nothing.
- **Junk packets are unauthenticated traffic to an unauthenticated peer.** A
  server with obfuscation configured will read and discard them cheaply, but
  they are still bytes an off-path sender can make a server process.

veepin implements the parameter-based obfuscation only. The I1-I5 custom
signature packets, `HeaderProtectionKey`, and protocol mimicry (QUIC/DNS/SIP)
are not implemented, so a deployment whose peers require them will not
interoperate.

## L2TPv3 has no authentication and no encryption at all

L2TPv3 (RFC 3931) is a transport, not a security protocol. veepin implements it
faithfully, which means the pseudowire it builds protects nothing:

- **Every frame crosses the network in the clear.** Anyone on the path reads the
  full Ethernet frame, inner IP header included.
- **There is no authentication of any kind.** The only thing standing between an
  off-path attacker and the bridged segment is the pair (Session ID, cookie), and
  both are sent in the clear on every packet. One observed packet is enough to
  inject frames forever after — there is no rekey, no sequence check, and no
  replay window, because the protocol defines none.
- **The cookie is not a key.** RFC 3931 §4.1.2.1 is explicit that it guards
  against mis-delivery and *blind* insertion — an attacker who has to guess
  8 octets. It is compared in constant time here, which stops a timing oracle,
  but that is the limit of what it can be asked to do.

This is why L2TPv3 is normally deployed inside IPsec. veepin does not do that for
you: `veepin connect l2tpv3` builds the pseudowire and nothing else. Run it on a
trusted network, or inside another veepin tunnel.

Being layer 2, it also inherits everything the SoftEther section above says about
sharing a broadcast domain: ARP, DHCP and every broadcast frame cross the tunnel,
and a host on the segment can ARP-spoof any other.

## IP-TFS costs its rate continuously, and its timing is bounded by a Go timer

`-iptfs` negotiates RFC 9347 AGGFRAG and moves the data path onto ESP next-header
144. On its own that is framing: aggregation and fragmentation, with packet
counts and timing still tracking the traffic inside, exactly as the README's
"Scope and limitations" says of the byte shaper.

`-iptfs-rate` is the part the RFC is named for. It transmits a fixed-size payload
at a fixed interval **whether or not there is anything to carry**, so the
datagram stream a passive observer sees is the same idle as saturated; only the
proportion of each payload that is padding changes. That is the one mechanism in
this tree that defends against the traffic-analysis class
[`doc/traffic-shaping.md`](traffic-shaping.md) names (Xue et al., USENIX Security
2024), because it is the only one that removes the *schedule* rather than the
sizes.

Two costs, and neither is small.

**It spends the rate continuously.** At 10 Mbit/s an idle tunnel moves 10 Mbit/s
of padding, forever, and in both directions if both ends enable it. This is why
the option is a number rather than a flag and why it is off by default: the
operator has to decide what they are willing to spend, and on a metered link the
answer is usually nothing.

**Above roughly 100 Mbit/s the timing is quantised rather than constant.** The
interval is payload/rate — 1.12 ms at 10 Mbit/s, 112 µs at 100 Mbit/s, 11 µs at
1 Gbit/s — and a Go timer will not deliver the last of those. Above the threshold
the sender emits the backlog as a burst on the next tick. The stream is still
independent of the offered load, which is the security claim, but an observer
sees burst boundaries rather than a smooth stream. `burstsFor` in
`internal/ikev2/ike/aggfrag_pacer.go` computes where the boundary is and
`TestTheRateAboveWhichTimingIsQuantised` pins it, so this paragraph cannot drift
from the code.

**It is IKEv2 only.** Every other protocol here still has load-dependent packet
counts and timing.

Interop-tested in both directions against strongSwan 6.0.7, and the constant-rate
half against it too: strongSwan does not *send* a constant rate, but its kernel
receives one perfectly — pad blocks are ordinary AGGFRAG — so
`compose.iptfs-constant.yml` measures the claim from the peer's own XFRM byte
counters, idle versus saturated. That cell is the only one in the harness that
measures a property rather than proving a path, because a ping is equally true of
a sender that pauses when idle.

Building those cells is also the reason to distrust a self-test here in
particular. Two bugs survived every unit test and both veepin roles agreeing
with each other: the `USE_AGGFRAG` notify was sent with an empty body where
RFC 9347 gives it one octet of flags (strongSwan refuses the whole IKE_AUTH
message over it), and every inbound AGGFRAG packet was dropped on any TUN with
GSO because `dataplane`'s batch path reached for the single-packet
decapsulator. The second is the one worth remembering: the tunnel reported
IP-TFS negotiated and working while carrying nothing inbound.

## What counts as a secret option, and why the rule needs writing down

Redaction — in the API, in the panel, in `veepin profile show` — is driven
entirely by `OptSpec.Secret`. A key whose spec omits it is printed in the clear,
so the flag is the whole of the policy and a judgement call in each facade.

The rule:

- **Key material is secret.** Private keys, PSKs, passwords, group keys.
- **A path to key material is secret**, not because the path is sensitive but
  because it names the file to go after, and because the panel showing
  `/etc/veepin/site-a/tls.key` in a field next to `<redacted>` teaches the wrong
  lesson about which of the two matters. `tls-auth` and `tls-crypt` are the
  awkward case: they are paths to an OpenVPN *static* key, symmetric material
  protecting the control channel, and they are secret.
- **A value whose only security property is being unguessable is secret**, even
  where it authenticates nothing. L2TPv3's cookies are the example. RFC 3931
  §5.4.3 calls them "a modest level of protection against blind insertion of
  data", which is protection that survives exactly as long as the value is not
  printed in a profile listing.
- **A public value is not secret**, even when it is cryptographic: a WireGuard
  *public* key, a certificate, a CA bundle.

`cmd/veepin`'s `TestSecretFlagsAgreeAcrossBothTables` enforces the one part of
this a test can: a key in both a protocol's client and server tables must be
flagged the same in each. It cannot decide whether a lone option is key
material, which is why the rule is here.

## Half the password protocols must store the password itself

`veepin serve` takes a credentials file — one `username:secret` line per user —
for every protocol that authenticates a person by password. Whether that secret
may be a **bcrypt verifier** rather than the password is not a configuration
choice. It follows from the protocol's authentication exchange, and the two
classes below are the whole of it:

| Class | Protocols | What the server stores |
|---|---|---|
| Receives the password and compares it | AnyConnect, Fortinet, GlobalProtect, Ivanti (Pulse), Cisco IPsec (XAuth), SSH | a bcrypt verifier, or the password |
| Computes its response *from* the password | SSTP, L2TP/IPsec (both MS-CHAPv2) | **the password itself** |

MS-CHAPv2 does not send a password. Both ends derive a response from the
NT hash of it, so there is nothing for the server to compare a verifier
against — the password is an *input to a derivation*, and a one-way function of
it is not a substitute. The same is true of SoftEther's challenge/response.

The consequence is worth stating plainly, because it is a property of those
protocols that veepin inherits and cannot fix: **an SSTP or L2TP server's
credentials file is a list of plaintext passwords.** Anyone who reads that file
can log in as any of those users anywhere else those passwords are reused. Keep
it `0600`, keep it off shared storage, and prefer one of the protocols in the
first row where the choice is yours.

`internal/userdb` enforces the split rather than documenting it: a bcrypt
verifier in an MS-CHAPv2 credentials file is refused at startup, naming the
reason. The alternative — accepting it — is a server that starts cleanly and
then rejects every login, with no message anywhere saying why.

Two smaller notes on the same file:

- It is marked `Secret` in every facade's `OptSpec`, under the "a path to key
  material is secret" rule above.
- `veepin passwd` prints a verifier, reading the password from stdin rather
  than taking it as an argument. The format is bcrypt's own, so `htpasswd -B`
  output works equally well; a tool whose purpose is keeping a password out of
  the process table should not be the thing that puts it there. For the same
  reason it turns the terminal's echo off while the password is typed — a
  secret kept out of `ps` and out of the shell history, then printed into the
  scrollback of a shared screen, has moved rather than closed the leak — and
  asks for it twice, since with nothing on screen to check against, a typo is
  not a visible error but a login that never succeeds. A password arriving on
  a pipe is read once and is not echoed by anything.

## The management plane is for one operator on one host, permanently

This is a decision, recorded so it stops looking like an omission somebody will
eventually "fix" by adding a login form.

The management plane is designed for the person who is already root on the box:
a bearer token in a `0600` root-only file, a panel with no login, and a
localhost bind plus a `Host` check as the boundary. Every one of those is
correct for a single operator with shell access, and every one of them is a
hard ceiling on anything else.

**veepin is not going to grow a multi-operator management plane.** The pieces
for one are in the tree — `internal/userdb`, `internal/otp`, `internal/profile`
— but they exist for the *VPN's* users, not for its administrators, and reusing
them here would change what the security boundary is. Real authentication means
the localhost bind stops being what protects the panel, which in turn means
every handler, the audit log, and the `Host` check all need to be re-reasoned
about against a hostile network peer rather than a trusted one. That is a
different project with a different threat model, not a feature.

If more than one person needs to administer a veepin host, the supported answer
is the one that already works and that this design assumes: give them shell
access, or put an authenticating reverse proxy in front of the API. Both put the
multi-user problem where there are mature tools for it.

## The management plane binds to localhost; do not bind it to a routable interface

The supervisor (`veepin serve -config <dir>`) starts a management HTTP API and
an embedded web panel, listening on `127.0.0.1:8443` by default. The API is
authenticated with a bearer token generated on first run into
`<config>/mgmt/token` mode `0600` root-only — the same filesystem-protection
posture the protocol facades' PEM and key files already rely on. That posture
holds because the panel is reachable only from the host itself.

If you bind the management API to a routable interface, the token file's
filesystem protection is no longer the boundary: anyone with network access can
attempt it. The token is 256 bits of `crypto/rand` and the comparison is
constant-time, so a blind online guess is not practical against a network peer
with no auth. Still, the panel transit is plaintext HTTP unless you put mTLS or
an SSH tunnel in front of it; a traffic observer then learns the token; the
token in their hands is a write primitive to every listener's options,
including protocol keys and PSKs.

### The panel is unauthenticated, and the `Host` check is what makes that safe

The panel at `/` is served without a bearer token, necessarily: it is the thing
that hands the browser the token, which it does by writing it into the page. The
token is then the per-request boundary for `/api/*`.

That arrangement survives ordinary cross-origin abuse. JavaScript on another
site cannot set an `Authorization` header without a CORS preflight the
supervisor never grants, so it cannot call the API — and it cannot read `/`
either, because the same-origin policy stops it seeing the response.

It does not survive **DNS rebinding**. A page the operator visits can rebind its
own hostname to `127.0.0.1`, at which point it is same-origin with the panel: it
fetches `/`, reads the token straight out of the DOM, and drives every endpoint
with the operator's full authority. No CORS involved.

What gives a rebound request away is that the browser sends the name it dialled,
so it arrives as `Host: attacker.example` rather than a loopback literal. The
supervisor wraps its whole listener — panel and API together — in
`mgmt.RequireHost`, which answers `403` unless the `Host` header names loopback,
`localhost`, or the exact address passed to `-listen`. If you front the panel
with a reverse proxy under some other name, that proxy must present one of those
in the upstream `Host`.

The dashboard escapes every value it renders into a row, `error` most of all:
protocol errors quote the option values that caused them, so an operator-supplied
path or hostname reaches the page as text. Since the page holds the token in its
DOM, markup landing in a row would be a token-exfiltration path rather than a
cosmetic bug.

Operate the management plane behind one of:

- **localhost only (default)** — the recommended posture. SSH to the host and
  use the panel through a port-forward, or use `veepin mgmt` locally with
  `VEEPIN_MGMT_TOKEN` in the environment.
- **mTLS on the bound address** — terminate TLS in a reverse proxy in front of
  the supervisor with client-certificate authentication. The supervisor's
  bearer token remains the second factor.
- **Unbound only behind a firewall** — acceptable in a controlled lab; document
  it as such so a future operator inherits the boundary.

The supervisor persists listener option maps to disk as mode `0600`, root-only
JSON files. Secrets inside them (private keys, PSKs, passphrases, TOTP seeds)
are plaintext at rest and redacted as the literal `<redacted>` on every API
read. A PATCH that submits `<redacted>` for a secret key preserves the on-disk
value rather than overwriting it with the placeholder, so a GET-then-PATCH
round trip cannot destroy a stored key. A POST cannot preserve anything — there
is nothing on disk yet — so it refuses the sentinel as a literal value with a
`400` naming the key, rather than storing the placeholder as if it were a key.
That was the shape of a GET-then-POST-under-a-new-name copy: a `201 Created` and
a listener whose private key was the eleven characters `<redacted>`.

### Secrets reach the CLI as command-line arguments

`veepin serve <proto> -psk …`, `veepin profile add … -password …` and the
`-set key=value` overrides all take secret values on argv. On Linux that means
the value is in `/proc/<pid>/cmdline`, readable by any process of the same user
(and by root), and it lands in the invoking shell's history file. There is no
`@/path/to/file` indirection and no interactive prompt; adding one is worthwhile
and has not been done.

Until then, the two surfaces that avoid argv entirely are the ones to prefer for
key material:

- **`veepin profile add` reading a JSON document on stdin** — the whole config,
  secrets included, arrives through a pipe. `veepin profile show` redacts by
  default and needs `-secrets` to print values.
- **A listener JSON file the supervisor reads** — mode `0600`, root-only, never
  on a command line. This is what the panel and `veepin mgmt add` write.

`veepin mgmt client-config` likewise redacts on stdout by default; `-o <dir>`
writes the real profile at mode `0600`, and `-secrets` is the explicit opt-in to
put it on the terminal. The bearer token itself is never accepted on argv: it
comes from `VEEPIN_MGMT_TOKEN` or `<config>/mgmt/token`.

The supervisor is **the only `veepin` subsystem that mutates host state.**
Single-protocol `veepin serve <proto>` opens a TUN and binds sockets but
declines to touch iptables unless you pass `-setup-nat`; the supervisor, by
contrast, **does** manage iptables for listeners that have `setup_nat: true`:
every rule it installs is tagged `veepin:<name>` and is removed on rebuild and
on `DELETE`. The exposure is bounded to its own rules (it does not own, for
example, your existing FORWARD policy), but it does mean the supervisor
process needs `CAP_NET_ADMIN` in addition to the `CAP_NET_ADMIN` every veepin
process already needs to open a TUN.
