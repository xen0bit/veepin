# veepin: hybrid post-quantum IKEv2 (RFC 9370 + RFC 9242)

## What this is

Not a fourteenth protocol — an extension to `internal/ikev2` that layers an
**ML-KEM** key encapsulation on top of the existing classical Diffie-Hellman, so
the derived IKE and Child SA keys survive an adversary who records traffic today
and owns a quantum computer later.

Two RFCs, and both are needed:

- **RFC 9370** (*Multiple Key Exchanges in IKEv2*) defines up to seven
  *additional* key exchanges beyond the mandatory one, negotiated as new
  transform types `ADDKE1`…`ADDKE7`. The shared secrets are chained into
  `SKEYSEED`, so the result is at least as strong as the strongest component —
  a peer that breaks the classical half still has ML-KEM in the way.
- **RFC 9242** (*Intermediate Exchange*) defines `IKE_INTERMEDIATE`, an exchange
  that runs between `IKE_SA_INIT` and `IKE_AUTH`. RFC 9370 carries every
  additional key exchange in one of these rather than stuffing them into
  `IKE_SA_INIT`, because they do not fit — see the sizes below.

## Why this is the highest-value item on the roadmap

It reuses everything. The DH negotiation, the SKEYSEED derivation, the payload
codec, the fragmentation, the ESP data path and the strongSwan interop harness
all already exist. What is missing is one exchange type, two-to-eight transform
types, one notify, and a KEM.

And the dependency question that would have blocked it is settled.

## Verified before writing this, not assumed

Checked on this machine, Go 1.25.0:

- **`crypto/mlkem` is in the standard library.** `mlkem.GenerateKey768()`,
  `EncapsulationKey768.Encapsulate() (sharedKey, ciphertext []byte)`,
  `DecapsulationKey768.Decapsulate(ct)`. A round trip agrees.
- **Sizes:** ML-KEM-768 encapsulation key **1184** octets, ciphertext **1088**,
  shared key **32**. ML-KEM-1024: encapsulation key **1568**, ciphertext **1568**.
- The dependency policy is satisfied with **no new module**.

Note the return order: `Encapsulate` yields `(sharedKey, ciphertext)`, not the
reverse. Getting it backwards produces a ciphertext-length error at decapsulation
rather than a silent mismatch, which is a small mercy.

Also checked in the tree:

- `internal/ikev2/payload/const.go` has `ExchangeType` 34–37 only —
  **`IKE_INTERMEDIATE` (43) is absent** and must be added.
- `TransformType` is 1–5 (`ENCR`, `PRF`, `INTEG`, `DH`, `ESN`) — the
  **`ADDKE1`…`ADDKE7` types (6–13) are absent** and must be added.
- **RFC 7383 fragmentation already exists** (`internal/ikev2/ike/fragment.go`).
  This is load-bearing: a 1184-octet KE payload will not fit a 1500-octet path
  once IKE and UDP headers are on it, so without fragmentation the exchange
  would black-hole on any real network.

## Why the size forces the design

`IKE_SA_INIT` is unauthenticated and unencrypted, so it is the message an
attacker can cheapest-ly amplify. Putting 1184 octets of encapsulation key in it
makes veepin an amplifier. RFC 9370's answer is to keep `IKE_SA_INIT` carrying
only the classical KE, negotiate the additional ones there, and then run each
additional exchange inside an encrypted `IKE_INTERMEDIATE` — which is also
fragmentable, because it is an ordinary encrypted exchange.

## Phases

**1. `IKE_INTERMEDIATE` (RFC 9242) — on its own, with tests.**
Exchange type 43; the `INTERMEDIATE_EXCHANGE_SUPPORTED` notify in `IKE_SA_INIT`;
and the one subtle part — the *authentication* of intermediate exchanges. RFC
9242 §3.3 requires every `IKE_INTERMEDIATE` message to be folded into the
`AUTH` payload computation in `IKE_AUTH`, so a downgrade that strips an
intermediate exchange is caught. Get this wrong and the whole feature is
decorative. A test must assert that a tampered or dropped intermediate message
fails authentication.

**2. Transform types 6–13 and the negotiation.**
`ADDKE1`…`ADDKE7` in the SA proposal, each naming a group from the same registry
as `TransformDH` (so ML-KEM gets its own IANA group IDs — confirm the assigned
numbers against the IANA registry at implementation time rather than trusting
this document). Both roles must handle a peer that offers none, one, or several,
and must agree on the *count* — a mismatch is a negotiation failure, not
something to paper over.

**3. `internal/cryptoutil` gains a KEM interface.**
Deliberately not "a DH group with a funny shape": a KEM is asymmetric between
the two roles — the initiator sends an encapsulation key, the responder sends a
ciphertext — where DH is symmetric. Modelling it as DH is the mistake that makes
the responder's code wrong. Something like:

```go
type KEM interface {
    GenerateKeyPair() (public []byte, private KEMPrivate, error)
    Encapsulate(public []byte) (ciphertext, shared []byte, err error)
}
type KEMPrivate interface{ Decapsulate(ciphertext []byte) (shared []byte, err error) }
```

**4. Chaining into SKEYSEED.**
RFC 9370 §2.2: after each additional exchange, `SKEYSEED` is recomputed as
`prf(SK_d(prev), SK_i | ...)` with the new shared secret mixed in. The order is
specified and must be followed exactly; a test with a fixed vector on both roles
is the guard, because a wrong chain still produces *matching* keys on two veepin
ends and fails only against strongSwan. (This is the same failure class as the
Pulse ESP key direction — see `CLAUDE.md`.)

**5. Interop against strongSwan 6.x.**
`tests/interop/strongswan` already exists. strongSwan 6.0+ implements RFC 9370
natively. Cells: veepin initiator → strongSwan responder, and the reverse, both
with `ke1_` proposals configured. A third cell with classical-only proposals on
the peer proves the negotiation degrades rather than breaking.

**6. Docs and guards.** `doc/security.md` gains a section stating precisely what
this does and does not protect — it is forward secrecy against a future quantum
adversary for the *key exchange*; it does nothing for authentication, which
remains classical (PSK or RSA/ECDSA signatures) and is the part a quantum
adversary attacks *live* rather than retroactively.

## Risks

- **IANA group IDs for ML-KEM.** The numbers must be read from the current IANA
  IKEv2 registry, not from any draft or from this file. Wrong IDs interop with
  nothing and the failure is a clean "no proposal chosen", so it is at least
  loud.
- **Fragmentation interaction.** Fragmentation exists but has not been exercised
  against 1088-octet payloads inside an intermediate exchange. Expect to find at
  least one off-by-one.
- **This is an extension, so the counts in `doc.go` and the README do not
  change.** The `docs_test.go` guards will not remind you of anything, which
  means the documentation has to be updated by hand and deliberately.
