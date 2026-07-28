# veepin: Rosenpass (post-quantum keys for WireGuard)

## What this is — and why it is not a protocol row

Rosenpass is a post-quantum authenticated key exchange that runs **beside**
WireGuard. It performs its own handshake over UDP, derives a symmetric key, and
installs that key into WireGuard's **pre-shared-key** slot roughly every two
minutes. WireGuard's own Noise IK handshake is unchanged; the PSK it mixes in is
simply one no quantum adversary can recover from recorded traffic.

The cryptography is a hybrid of two KEMs: **Classic McEliece** (`mceliece460896`)
as the static KEM providing authenticity, and **Kyber-512** as the ephemeral one
providing forward secrecy. It descends from the 2020 *Post-Quantum WireGuard*
paper, has a published whitepaper, and the protocol has been machine-verified.

**It is filed as a WireGuard option, not as protocol #14, deliberately.** It has
no data path. It cannot answer `Dial`; it cannot return a `client.Result`; there
is no tunnel to `Wait` on. Registering it in `client` would put something in the
registry that fails every contract the registry exists to express. The right
shape is:

```go
wireguard.Config{
    // ... existing peer configuration ...
    Rosenpass: &wireguard.RosenpassConfig{
        PeerPublicKey: ..., // Classic McEliece static public key
        SecretKey:     ...,
        Listen:        ..., // its own UDP endpoint
    },
}
```

with the resulting key delivered into the existing PSK path on a timer.

## The dependency problem, which is the whole story

This is the item on the roadmap most likely to be **rejected on policy**, and
that should be decided before any code is written rather than discovered
halfway.

veepin's rule is: standard library, plus `golang.org/x/{crypto,net,sys}`, and
nothing else. Rosenpass needs:

- **Kyber / ML-KEM** — *available*. `crypto/mlkem` is in the Go 1.25 standard
  library (verified: ML-KEM-768 round-trips, ek 1184 / ct 1088 / shared 32).
  But note Rosenpass specifies **Kyber-512**, and the standard library ships
  **ML-KEM-768 and ML-KEM-1024 only**, and ML-KEM is the *standardised* FIPS 203
  variant, not the round-3 Kyber that Rosenpass's spec names. These are not
  wire-compatible. Interoperating with the reference implementation therefore
  needs round-3 Kyber-512, which the standard library does not provide.
- **Classic McEliece** — *not available anywhere in the permitted set*. There is
  no `crypto/mceliece`, and `golang.org/x/crypto` has none. `mceliece460896` has
  a **524 KB public key**; a correct, constant-time, from-scratch implementation
  is a serious cryptographic engineering project in its own right, and getting it
  wrong is worse than not shipping it.

So the honest position: **Rosenpass cannot be implemented interoperably under the
current dependency policy.** Either the policy changes for this one case, or
Classic McEliece and round-3 Kyber-512 get written from scratch — which is
weeks of work whose failure mode is silent and severe.

## What could be done instead, and is arguably better

Implement the *idea* — a post-quantum PSK feed for WireGuard — using
`crypto/mlkem` alone, with veepin on both ends. That is:

- fully inside the dependency policy;
- a genuine improvement to veepin's WireGuard against a record-now-decrypt-later
  adversary;
- **not Rosenpass**, and must not be described as it. It would interoperate with
  nothing, which means it gets a `—†` in the client column and its
  veepin↔veepin cell is the only evidence — the weakest position in the matrix,
  and precisely the situation that hid the Pulse ESP key-direction bug until a
  real peer was involved.

That last point is the strongest argument against doing it at all. A
cryptographic protocol whose only test is against itself is exactly the thing
this project's interop matrix exists to distrust.

## Recommendation

**Do not implement Rosenpass**, and do not implement a look-alike either, unless
one of these changes:

1. The dependency policy admits an audited third-party Classic McEliece — in
   which case implement the real protocol and interop against the Rust reference
   implementation, which is the only version worth having.
2. Or the goal shifts from "post-quantum WireGuard" to "post-quantum IKEv2", in
   which case [pq-ikev2-plan.md](pq-ikev2-plan.md) achieves the same security
   property, entirely within the standard library, **with a real interop peer**
   in strongSwan.

Option 2 is strictly better on every axis this project cares about. It is the
reason PQ IKEv2 is ranked second on the roadmap and this is ranked fourth.
