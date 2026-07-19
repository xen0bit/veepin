# TOY v1 — a teaching protocol

**TOY provides no security. It is a worked example of how a protocol is put
together in this tree, not something to carry traffic you care about.**

Read the [Why this is not secure](#why-this-is-not-secure) section before the
rest. Everything else in this document describes machinery that is deliberately
breakable.

## What it is for

veepin implements eight real protocols. Each is large enough that the *shape*
of a protocol — how it registers, what it hands back, where the data path comes
from — is buried under the details of the real thing. TOY exists so that shape
can be read in one sitting:

- a handshake with a challenge/response step, so `client.Dial` has something to
  do and `Result` has something to report;
- a framed data path, so `dataplane.Pump`'s `Tunnel`/`Demux`/`Sender` triple is
  demonstrated end to end;
- both roles, so `client.Register` and `client.RegisterServer` are both
  exercised;
- a spec precise enough to reimplement from — which the interop harness proves
  by talking to an independent Python implementation of this document.

If you are adding a real protocol to veepin, `internal/toy` is the smallest
complete example to copy the structure from. Copy the structure, not the
cryptography.

## Transport

UDP. Default port **5555**. One socket per host; the server demultiplexes
clients by session ID rather than by source address.

All integers are **big-endian**. All lengths are in octets.

## Header

Every datagram begins with the same 12-octet header.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      'T'      |      'O'      |      'Y'      |    version    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     type      |     flags     |           session             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           counter                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Offset | Size | Meaning |
|-------|--------|------|---------|
| magic | 0 | 3 | `0x54 0x4F 0x59` (`TOY`). A datagram without it is discarded. |
| version | 3 | 1 | `1`. Another value is discarded. |
| type | 4 | 1 | Message type, below. |
| flags | 5 | 1 | Reserved, sent as `0`, ignored on receipt. |
| session | 6 | 2 | Server-assigned session ID. `0` until `CHALLENGE` assigns one. |
| counter | 8 | 4 | Per-direction message counter, starting at `1`. |

The session ID is the demux key: a server finds the right client by reading
offset 6, never by looking at the source address. That is what lets a client
survive a NAT rebinding, and it is why the field is in the header rather than in
the encrypted body.

## Message types

| Value | Name | Direction | Body |
|-------|------|-----------|------|
| `0x01` | HELLO | client → server | `nonce(8) ‖ userLen(1) ‖ user` |
| `0x02` | CHALLENGE | server → client | `nonce(8)` |
| `0x03` | AUTH | client → server | `proof(8)` |
| `0x04` | WELCOME | server → client | see below |
| `0x05` | REJECT | server → client | `reasonLen(1) ‖ reason` |
| `0x06` | DATA | both | `tag(8) ‖ ciphertext` |
| `0x07` | KEEPALIVE | both | `tag(8)` (empty ciphertext) |
| `0x08` | BYE | both | empty |

Handshake messages are **not** obscured. Only `DATA` and `KEEPALIVE` carry a tag
and keystream, because only they exist after a key has been derived.

### WELCOME body

```
assignedIP(4) ‖ netmask(4) ‖ gateway(4) ‖ mtu(2) ‖ dnsCount(1) ‖ dns(4) × dnsCount
```

This is what becomes `client.Result`: the address the server assigned, the
gateway to anchor routes on, the MTU, and any DNS servers. veepin installs none
of it — `Dial` returns it and the caller applies it.

## Handshake

```
client                                                     server
  |                                                            |
  |  HELLO      session=0  counter=1   nonce_c ‖ user          |
  |----------------------------------------------------------->|
  |                                                            |  allocate session
  |  CHALLENGE  session=S  counter=1   nonce_s                 |  allocate address
  |<-----------------------------------------------------------|
  |                                                            |
  |  AUTH       session=S  counter=2   proof                   |
  |----------------------------------------------------------->|
  |                                                            |  verify proof
  |  WELCOME    session=S  counter=2   address ‖ mtu ‖ dns      |
  |<-----------------------------------------------------------|  (or REJECT)
  |                                                            |
  |  DATA       session=S  counter=3+  tag ‖ ciphertext         |
  |<----------------------------------------------------------->|
```

Both sides derive the key after `AUTH`/`CHALLENGE`, from the two nonces and the
shared secret. The client retransmits `HELLO` and `AUTH` on a timer until the
next message arrives; there is no reliability layer.

### Handling retransmission and forgery

Because the client retransmits, and because anything on the wire can be forged,
two rules govern how a server treats handshake messages. Both are requirements,
not optimisations — an implementation that skips them is exploitable rather than
merely inefficient.

**A repeated `HELLO` must not start a second handshake.** The client nonce
identifies the attempt: a `HELLO` carrying a nonce already in progress replays
the same `CHALLENGE` for the same session. A server that allocated afresh each
time would consume one session and one address per retransmission, so a lossy
link — or a peer that simply repeated the message — could exhaust the address
pool without ever authenticating.

**A failed `AUTH` must not discard the pending handshake.** The server sends
`REJECT`, and otherwise leaves the session alone. Session IDs travel in the
clear, so anyone who saw the `CHALLENGE` knows one, and sending a wrong proof for
it requires no secret; discarding state on that basis would let a single forged
datagram cancel a legitimate client's handshake. The legitimate client can still
complete, and the pending timeout below reclaims the address if nobody does.

Both are instances of one rule, which the data path follows too: **unauthenticated
input must never destroy state.** See "Anti-replay" for the same principle
applied to the message counter.

A handshake that is never completed is discarded after the session timeout, along
with the address it reserved. That bound is what makes it safe to keep state that
an attacker can cause to be created.

## The digest

One 64-bit function is used for everything: key derivation, the auth proof, and
the packet tag. It is **FNV-1a**, chosen because it is four lines in any
language, which is the whole point.

```
h = 0xcbf29ce484222325
for each octet b of input:
    h = (h XOR b) * 0x100000001b3   (mod 2^64)
```

`toyDigest(input) -> 8 octets, big-endian`.

## Key derivation

```
seed = secret ‖ nonce_c ‖ nonce_s
key  = toyDigest(seed ‖ 0x00) ‖ toyDigest(seed ‖ 0x01)
     ‖ toyDigest(seed ‖ 0x02) ‖ toyDigest(seed ‖ 0x03)
```

32 octets. Both sides compute the same value; nothing is transmitted.

## The auth proof

```
proof = toyDigest(secret ‖ nonce_c ‖ nonce_s ‖ "toy-auth")
```

The client sends it; the server recomputes and compares. Comparison is
constant-time in veepin — not because it matters here, but because that is the
habit worth showing.

## The keystream

`DATA` and `KEEPALIVE` bodies are XORed with a keystream derived from the key
and the header's counter, so that identical plaintexts do not produce identical
ciphertexts:

```
for each octet index i of the payload:
    ks[i] = key[(i + counter) mod 32] XOR ((counter >> (8 * (i mod 4))) AND 0xFF)
    out[i] = in[i] XOR ks[i]
```

XOR is its own inverse, so encryption and decryption are the same routine.

## The tag

```
tag = toyDigest(key ‖ header(12) ‖ ciphertext)   -> 8 octets
```

The tag covers the header, so the type, session and counter cannot be edited
without invalidating it. A receiver recomputes the tag before doing anything
else with the packet, and discards a mismatch.

This is the right *shape* — authenticate the ciphertext and the framing that
describes it — attached to a construction that provides none of the guarantee.

## Anti-replay

The counter is per-direction and starts at `1`. A receiver keeps the highest
counter seen and a 64-entry bitmap behind it:

- ahead of the highest → accept, slide the window;
- inside the window and unseen → accept (UDP reorders);
- inside the window and already seen, or older than the window → discard.

A receiver **must** check the tag before touching the window, or anyone able to
send a datagram could advance it and lock the peer out.

## Keepalive and teardown

A client transmits `KEEPALIVE` every 15 seconds for the life of the session,
whether or not it has data to send. Sending unconditionally rather than only when
idle costs one datagram every 15 seconds and removes a whole class of question
about what counts as idle; it also keeps a NAT binding open on a link carrying
only inbound traffic.

A server discards a session it has heard nothing on for 60 seconds, releasing the
address. The interval and the timeout are chosen so a live peer has four chances
to be heard before being reaped.

Liveness is counted only from packets that **authenticate**, so a forged datagram
can neither keep a dead session alive nor, by itself, prove one is. Clients do
not enforce a timeout in either direction: a client that stops hearing from a
server simply stops receiving, which the application above it will notice.

`BYE` ends a session immediately, but it is unauthenticated and therefore
advisory — anyone able to send one datagram could otherwise tear down any
session. veepin logs it and ignores it.

## Why this is not secure

Stated plainly, because a reader who skips to the code deserves to have been
told:

1. **The keystream repeats.** It is 32 octets keyed by a counter the attacker
   can read. Two packets with the same counter modulo the pattern share
   keystream, and XORing two ciphertexts cancels it, leaving the XOR of two
   plaintexts. IP headers are highly predictable, so this falls apart
   immediately.
2. **FNV-1a is not a MAC.** It is a non-cryptographic hash designed for hash
   tables. It is not collision resistant and is trivially invertible in the ways
   that matter; forging a tag is arithmetic, not search.
3. **The proof is replayable within a session** and reveals a digest of the
   secret. An observer who records one handshake can compute the key, because
   both nonces travel in the clear and the digest is cheap.
4. **There is no forward secrecy.** There is no key exchange at all — the key is
   a function of a long-term secret and two public nonces, so recovering the
   secret retroactively decrypts everything ever sent.
5. **The handshake is unauthenticated in both directions until AUTH**, and
   `CHALLENGE` is never authenticated at all, so an active attacker can
   impersonate the server outright.
6. **The key derivation barely derives anything.** The four blocks differ only
   in a trailing counter octet, and FNV-1a has almost no avalanche, so they come
   out nearly identical. A real derived key, printed:

   ```
   block 0  047ae0563b133f25
   block 1  047adf563b133d72
   block 2  047ade563b133bbf
   block 3  047add563b133a0c
   ```

   Five of every eight octets are shared across all four blocks. The "32-octet
   key" carries closer to 12 octets of variation, and the keystream inherits
   that structure directly. A real KDF (HKDF, say) exists precisely so that
   related inputs produce unrelated outputs.
7. **Nothing here was reviewed as cryptography**, because there is no
   cryptography here to review.

Every one of these is a deliberate simplification, and each corresponds to
something a real protocol in this tree does properly: WireGuard's Noise_IKpsk2
handshake for 3–5, AES-GCM or ChaCha20-Poly1305 for 1–2, and an ephemeral key
exchange for 4.

## Relationship to the real protocols

| Concern | TOY | What a real protocol here does |
|---------|-----|--------------------------------|
| Key agreement | none; key = f(secret, nonces) | X25519 / MODP DH, ephemeral |
| Confidentiality | 32-octet repeating XOR | AES-GCM, ChaCha20-Poly1305 |
| Integrity | FNV-1a over key ‖ header ‖ ct | AEAD tag, or HMAC encrypt-then-MAC |
| Authentication | digest of a shared secret | certificates, PSK+Noise, EAP, MS-CHAPv2 |
| Forward secrecy | none | ephemeral DH per session, rekeying |
| Replay | 64-entry window | 1024-entry window, per-SA |

The rows on the left exist so the rows on the right have somewhere obvious to be
compared against.
