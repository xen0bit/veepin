# veepin: `pq-` protocol variants — post-quantum by name, not by flag

## What this is

Not new protocols. A second **name** for protocols that already exist, under
which the post-quantum path is mandatory rather than negotiated: `ikev2` and
`pq-ikev2`, `openvpn` and `pq-openvpn`, and so on for every protocol that can
carry the guarantee.

The decision that shapes everything below is that **there is no `-pq-only`
flag.** A flag is a modifier an operator can forget, and forgetting it silently
yields the weaker thing — the exact silent-downgrade failure that
`TestNoTLSConfigPinsCurvePreferences` already exists to prevent one commit at a
time. A name cannot be forgotten. `veepin serve pq-ikev2` either starts with the
guarantee in force or does not start.

The second reason is evidentiary, and it is the one that matters most in this
tree: **the interop matrix is keyed by protocol name.** A `pq-ikev2` row in
`internal/livingreadme/interop.go` is a published, CI-verified claim that the
forced mode works against a real peer, and it renders into the README beside
every other row. A flag gets no row. It would need a per-flag cell convention
invented for it, and — per `AGENTS.md` — a mode with no cell runs in no CI shard
and therefore never runs.

## Verified before writing this, not assumed

Everything in this section was measured on this machine against the real
toolchain and real peer images, on 2026-08-25. Where a number came out different
from what the surveys in [`claims-and-reach-plan.md`](claims-and-reach-plan.md)
predicted, the measurement wins and the difference is called out.

### The toolchain is ready, and the floor bump already landed

```sh
go version                     # go1.27.0 linux/amd64
head -3 go.mod                 # go 1.27.0
head -3 nm/go.mod              # go 1.27.0
ls "$(go env GOROOT)/src/crypto" | tr '\n' ' '
#   … mldsa mlkem … tls x509
```

Both modules are already at `go 1.27.0`. The six-place floor bump that H3 in
`claims-and-reach-plan.md` scoped as a prerequisite is **done**; nothing in this
plan is gated on it.

### Sizes, measured rather than quoted

```
ML-DSA-44  SPKI= 1334  sig= 2420  self-signed cert DER= 3915
ML-DSA-65  SPKI= 1974  sig= 3309  self-signed cert DER= 5444
ML-DSA-87  SPKI= 2614  sig= 4627  self-signed cert DER= 7402
ML-KEM-768 encapKey=1184 ciphertext=1088 shared=32
```

The ML-DSA-65 signature alone is **3309 octets**, and its certificate is 5444.
That is the number that makes IKEv2 fragmentation a hard prerequisite rather
than a nicety, and it is why the AUTH payload work in §6 cannot be attempted on
a path without RFC 7383 outbound fragmentation — which this tree has.

### PEM and `tls.X509KeyPair` carry ML-DSA with no protocol work

```
PEM round-trip OK: cert 7517 B PEM, key 128 B PEM, leaf alg=ML-DSA-65
```

`x509.MarshalPKCS8PrivateKey` accepts an `*mldsa.PrivateKey`, the result PEM-
encodes, and `tls.X509KeyPair` loads the pair. The private key PEM is **128
bytes** — PKCS#8 stores ML-DSA as its 32-octet seed, not the expanded key. So
every credential path in the TLS family already carries ML-DSA: they read PEM
and hand it to `tls.X509KeyPair`, which is the whole of what is needed. This
confirms the claim in `doc/security.md` rather than resting on it.

### A PQ-only TLS config refuses loudly, and says why

```
PQ-only server vs classical-only client
    client = remote error: tls: handshake failure
    server = tls: no key exchanges supported by both client and server

PQ-only server vs TLS1.2-max client
    client = remote error: tls: protocol version not supported
    server = tls: client offered only unsupported versions: [303]
```

Both refusals are diagnosable from the server log without a packet capture,
which is the bar a hardening switch has to clear. Compare the `mlockall`
argument in `doc/security.md`: a protection that quietly does nothing is worse
than no protection, and so is one that fails without saying what it wanted.

### The DER AlgorithmIdentifiers `certauth.go` will need

Extracted from certificates actually minted by `crypto/x509`, not copied from a
draft:

```
ML-DSA-44  0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x11   2.16.840.1.101.3.4.3.17
ML-DSA-65  0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x12   2.16.840.1.101.3.4.3.18
ML-DSA-87  0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x13   2.16.840.1.101.3.4.3.19
```

**Note the length: 13 octets, not 15.** The ML-DSA AlgorithmIdentifier has
*absent* parameters, where the existing RSA entries in `knownSigAlgs` carry an
explicit `0x05 0x00` NULL. Copying the RSA pattern and appending a NULL produces
an identifier no peer recognises, and `lookupSigAlg` compares with
`bytes.Equal`, so the failure is a clean "unrecognized signature
AlgorithmIdentifier" rather than a silent mismatch. Small mercy; still worth a
test that pins the byte length.

### The peers — and this is where the plan's shape actually comes from

Measured by running each image and asking it what it supports.

| Peer image | Base | Crypto stack | PQ key exchange | ML-DSA |
|---|---|---|---|---|
| `openconnect` → anyconnect, fortinet, gp, pulse | bookworm | **GnuTLS 3.8.9** (trixie) | ✗ **no ML-KEM group at all** | ✗ |
| `openvpn` | alpine 3.20 → OpenSSL 3.3.7 | OpenSSL **3.5.6** on trixie | ✓ | ✓ (library; app untested) |
| `sshd` / `ssh-client` | bookworm → **OpenSSH 9.2p1** | OpenSSH | ✗ on 9.2, ✓ on 10.0 | ✗ — none exists in SSH |
| `sstp-client`, `ocserv` | bookworm | OpenSSL 3.0 / GnuTLS 3.7 | ✗ | ✗ |
| `strongswan-pq` | **sid** | — | ✓ ML-KEM-768 | ✗ until 6.1.0 |
| `libreswan` | alpine 3.22 | OpenSSL 3.5.7 | ✓ (lib) | ✗ |
| `masque` (aioquic) | python 3.12 bookworm | aioquic | untested | untested |
| `softether` | `siomiz/softethervpn` | own stack | untested | untested |

Three measurements from that table deserve to be stated on their own, because
each one moves the plan.

**GnuTLS 3.8.9 has no ML-KEM whatsoever.** Asked directly:

```
Groups: GROUP-SECP192R1 … GROUP-X25519, GROUP-GC256B, GROUP-GC512A,
        GROUP-X448, GROUP-FFDHE2048 … GROUP-FFDHE8192
```

openconnect 9.12 links GnuTLS, not OpenSSL (`libssl` is present only through
`xmlsec`). So the peer for **four** of this tree's protocols cannot do a
post-quantum key exchange on any current Debian, let alone ML-DSA. Bumping that
image achieves nothing. This is not a version problem to wait out for a release
or two; it is the state of GnuTLS.

**OpenSSH's PQ key exchange is real but newer than the image.** `mlkem768x25519-sha256`
is OpenSSH 9.9+, default in 10.0. Before that it is `sntrup761x25519-sha512@openssh.com`,
and **`x/crypto` implements no sntrup761 at all** — its `supportedKexAlgos` has
exactly one PQ entry. Measured:

```
bookworm  OpenSSH_9.2p1    sntrup761x25519-sha512  sntrup761x25519-sha512@openssh.com
trixie    OpenSSH_10.0p2   sntrup761…  sntrup761…@openssh.com  mlkem768x25519-sha256
```

So **veepin's SSH cell has no post-quantum key exchange in common with its peer
today** and silently settles on `curve25519-sha256`. `pq-ssh` needs the image on
trixie before it can pass at all. Separately, per <https://www.openssh.org/pq.html>,
OpenSSH has **no post-quantum signature support in any version** and says so
explicitly — so `pq-ssh` cannot carry the authentication half of the guarantee.
See §4.

**A fully post-quantum TLS handshake against a third-party peer works today.**
This is the correction referred to above. A Go server presenting an ML-DSA-65
certificate with `CurvePreferences` pinned to `X25519MLKEM768` only, connected
to by OpenSSL 3.5.6's `s_client` from trixie:

```
Peer signature type: mldsa65
Negotiated TLS1.3 group: X25519MLKEM768
Verify return code: 0 (ok)
```

Both halves post-quantum, chain verified, against an implementation that is not
veepin. The scoping conversation for this plan asserted that no third-party peer
accepts an ML-DSA certificate; for the OpenSSL family that is **wrong**, and the
plan below reflects the measurement rather than the assertion.

## 1. What `pq-` guarantees

One sentence, and every variant either meets it or does not exist:

> Under a `pq-` name, both halves of the handshake are post-quantum — key
> exchange **and** authentication — and anything less is refused rather than
> negotiated down.

Three clarifications that are part of the contract, not caveats on it:

- **"Refused" means the connection fails, not that it degrades.** A `pq-` server
  meeting a classical client produces a handshake failure with a log line naming
  what was missing. A `pq-` client meeting a classical server does the same.
- **Authentication means the *server's* identity is proved with ML-DSA**, plus
  any client certificate where the protocol uses one. For the password-authenticating
  protocols (anyconnect, fortinet, gp, pulse, sstp, softether) the user's
  password travels inside the post-quantum channel; passwords are not a
  quantum-broken primitive, so this is genuinely the whole handshake and not a
  half-measure. For mutual-TLS protocols (openvpn, masque) **both** certificates
  must be ML-DSA.
- **The base protocol is untouched.** `ikev2` keeps negotiating exactly what it
  negotiates today. `pq-` adds a name, never subtracts a capability.

## 2. Decisions taken

Recorded here so they are answered on purpose rather than by drift, in the
manner of the site-to-site boundary in `doc/security.md`.

| # | Decision | Rationale |
|---|---|---|
| D1 | `pq-` forces **key exchange *and* ML-DSA authentication** | The weaker "key exchange only" reading is already what the tree does by default. A name should mean something the default does not. |
| D2 | **Both roles** get variants, and `ikev2 -pq` is **retired** | Two spellings for one thing is the ambiguity the naming scheme exists to remove. |
| D3 | Registry is **split**: base protocols and variants are separate namespaces | Keeps `productionProtocols()` — and therefore the README's "sixteen" — honest, while leaving every mechanical guard able to enumerate variants for self-testing. |
| D4 | Evidence is **per protocol**, not one global policy | Measurement (above) shows the peers differ enormously. openvpn and ikev2 have real PQ peers today; openconnect's four have none and will not soon. |

D4 supersedes the "self-cells first, images after" answer given during scoping,
and it does so in the direction of *more* evidence rather than less. That answer
was given on the premise that no third-party peer accepts ML-DSA, which the
OpenSSL measurement disproves. Where a real peer exists it is used from the
start; where none exists the cell takes the fixed `—†` label that
`internal/livingreadme/interop.go` already carries for exactly this situation
(the Fortinet precedent), rather than a false ✗ or a self-cell dressed up as
cross-implementation evidence.

## 3. The protocols, in four classes

### Class A — a `pq-` variant with a real third-party peer

| Variant | Base | Forced | Peer for the evidence |
|---|---|---|---|
| `pq-ikev2` | ikev2 | ML-KEM-768 via ADDKE1 (mandatory), ML-DSA in the RFC 7427 AUTH payload | strongSwan (`strongswan-pq`, sid) proves the **KEX** half today; the auth half waits for 6.1.0 |
| `pq-openvpn` | openvpn | TLS 1.3 floor, ML-KEM-only curves, ML-DSA certs both ends | `openvpn` 2.6.14 on trixie links OpenSSL 3.5.6 — **both halves testable**, pending the application-level check in §8 |
| `pq-masque` | masque | TLS 1.3 already; ML-KEM-only curves, ML-DSA certs | aioquic — needs the survey in §8 before this row is promised |

### Class B — a `pq-` variant with no peer, and no near prospect of one

`pq-anyconnect`, `pq-fortinet`, `pq-gp`, `pq-pulse`, `pq-sstp`, `pq-softether`.

The code is the same small change as class A. The evidence is not available:
openconnect is GnuTLS and GnuTLS has no ML-KEM group; `sstp-client` and ocserv
are older still; SoftEther has its own stack. These ship with veepin↔veepin self
cells and a `—†` on both directional cells, with `doc/security.md` stating
plainly that no third-party implementation has verified them. That is the
SoftEther-server-direction precedent: state it as unknown, do not claim it.

Two of these carry an extra obligation:

- **`pq-anyconnect` and `pq-fortinet` must force `-no-dtls`.** `internal/dtls` is
  a from-scratch DTLS 1.2 with two fixed suites and no post-quantum path at all.
  Leaving the UDP data channel bound would mean the control channel is
  post-quantum and every byte of tunnelled traffic is not. Both facades already
  have the option; the variant sets it and refuses an operator's attempt to
  unset it.
- **`pq-gp` and `pq-pulse` need no data-path work.** Both push their ESP keys
  *inside* the TLS session, so the ESP data path inherits whatever the TLS floor
  is. Raising the TLS floor raises theirs. This is worth a comment in each,
  because it looks like an omission otherwise.

### Class C — `pq-` cannot carry the full guarantee

`pq-ssh`. SSH has a post-quantum key exchange and **no post-quantum signature
algorithm at all** — not in OpenSSH, not in `x/crypto`, not in a finished
specification. OpenSSH's own PQ page says signature support is future work.

So `pq-ssh` can force `mlkem768x25519-sha256` and cannot force anything about
host-key or user-key authentication. Under D1 that means it does not meet the
contract. **Recommendation: ship it anyway, as a single named exception**, in
the manner of `noCredentialJudged` in `autherr_test.go` — an explicit table
entry naming the protocol and the reason, asserted by a test, so the exception
is a decision on the record rather than an inconsistency. The alternative is to
omit `pq-ssh` entirely, which loses a real key-exchange improvement over the
current silent fallback to `curve25519-sha256`.

**This is the one open decision in the plan that a person should make.** See
§11.

### Class D — no `pq-` variant is possible

| Protocol | Why not |
|---|---|
| `wireguard`, `amneziawg` | Noise_IKpsk2 fixes X25519 and negotiates nothing. Rosenpass is rejected in [`rosenpass-plan.md`](rosenpass-plan.md): it specifies round-3 Kyber-512, which is *not* `crypto/mlkem`'s FIPS 203 ML-KEM and does not interoperate with it, and Classic McEliece exists in no permitted package. |
| `nebula` | Plain `Noise_IX_25519_*`. Its PSK machinery is inert by design — see the comment in `internal/nebula/noise.go:17-23`. |
| `cisco`, `l2tp` | IKEv1. There is no additional-key-exchange mechanism to extend, and there will not be one. |
| `l2tpv3` | No cryptography at all, by design. |
| `toy` | Deliberately insecure teaching example. |

**The absence of `pq-wireguard` is a structural fact, not a backlog item**, and
`doc/security.md` should say so in those words. Otherwise the naming scheme
implies a gap that someone will file a bug about.

## 4. The machinery

### 4.1 Registry variants — `client.RegisterVariant`

```go
// RegisterVariant registers name as a variant of base: a second spelling of an
// existing protocol under which some policy is mandatory. Variants are dialable
// and servable exactly like protocols, and are enumerated separately so that
// counts of "production protocols" stay counts of protocols.
func RegisterVariant(name, base string, parse ParseFunc)
func RegisterServerVariant(name, base string, parse ServerParseFunc)

// Variants lists registered variant names, sorted.
func Variants() []string
// BaseOf returns the protocol a variant varies, or "" if name is not a variant.
func BaseOf(name string) string
```

Three properties this has to have:

- **`Protocols()` keeps returning base protocols only.** `productionProtocols()`
  in `docs_test.go:55` is `Protocols()` minus toy, and `TestREADMECountsProtocolsCorrectly`
  forces every spelled-out occurrence to match it. Leave that path alone and the
  README stays at **sixteen** with no prose churn.
- **`Dial` and `NewServer` resolve both namespaces.** One lookup, variants
  included, so every caller — CLI, supervisor, management API, NM — reaches a
  variant by name with no change.
- **`ServerOptsFor`/`ClientOptsFor` fall back to the base.** A variant declares
  **no** OptSpec table of its own. This is the single most important design point
  in this section: it means `veepin serve pq-sstp` generates byte-for-byte the
  same flag set as `veepin serve sstp` through the existing `optflags.go`, and
  every `flags_test.go` guard passes with no new table to keep in sync. Ten
  duplicated 35-row spec tables is the failure mode this avoids.

Where a variant must *remove* an option (`pq-anyconnect` and `-no-dtls`, which it
forces), the variant's parse function rejects an explicit contrary value with a
named error. It does not silently override — same argument as the harden flags.

### 4.2 The policy lives in one place — `internal/pqpolicy`

```go
package pqpolicy

// HardenTLS raises a tls.Config to the pq- contract: TLS 1.3 floor, ML-KEM key
// exchange only, and ML-DSA certificates only.
func HardenTLS(cfg *tls.Config) error

// RequireMLDSALeaf is the VerifyPeerCertificate hook that enforces the
// authentication half against a peer that presents a certificate.
func RequireMLDSALeaf(rawCerts [][]byte, chains [][]*x509.Certificate) error

// CheckCredential rejects a server credential that is not ML-DSA, at construction
// time rather than at first handshake.
func CheckCredential(cert tls.Certificate) error

// HardenSSH pins the key exchange to mlkem768x25519-sha256. It does NOT
// constrain host keys: SSH has no post-quantum signature algorithm. See the
// exception table in doc/security.md.
func HardenSSH(cfg *ssh.Config) error
```

One package owns what the phrase means. Ten facades forward a bool to it. When
`MLKEM1024` or a future mechanism should join the accepted set, it changes here
and every variant moves together.

**`CheckCredential` is what makes the guarantee load-bearing at startup.** A
`pq-` server pointed at an RSA certificate must fail in `NewServer`, before the
TUN is opened and before anything binds — not at the first client's handshake,
where the operator would see a working listener that refuses everyone.

### 4.3 The seam in each facade

`pq-sstp` cannot reach what it needs to override: `sstp/server.go:125` builds
`&tls.Config{…}` as a local, and `sstp.ServerConfig` has no TLS field at all.
Each base facade gains **one** exported field:

```go
// PostQuantumOnly requires a post-quantum key exchange and ML-DSA
// authentication, refusing anything less rather than negotiating down. It is
// what the pq-<proto> registry name sets; see internal/pqpolicy.
PostQuantumOnly bool
```

and one call to `pqpolicy.HardenTLS` where the config is built. That is the
whole seam. The rejected alternative is a `func(*tls.Config)` hook, which is
more rope and — decisively — would let a caller *lower* the floor as easily as
raise it.

### 4.4 The `pq-` packages themselves

Genuinely thin, and they must stay that way:

```go
// Package pqsstp registers "pq-sstp": SSTP with the post-quantum contract in
// force. It is sstp, with one bool set; see doc/pq-variants-plan.md.
package pqsstp

func init() {
    client.RegisterVariant("pq-sstp", "sstp", dial)
    client.RegisterServerVariant("pq-sstp", "sstp", serve)
}
```

No option parsing of their own — they delegate to the base's parse and set the
field. If a `pq-` package grows past about fifty lines, the policy has leaked out
of `pqpolicy` and should be pushed back into it.

## 5. Where the `CurvePreferences` guard has to give

`pqtls_test.go:TestNoTLSConfigPinsCurvePreferences` fails on the **field name**,
with a deliberately empty `allowed` map, and its own comment says an exception
belongs there "by name with the peer that forced it". This work trips it on the
first line written.

Do **not** add eight file paths to the allowed map. The guard should instead
learn one sanctioned shape: a `CurvePreferences` assignment is permitted **only
inside `internal/pqpolicy`**. Everywhere else it stays a hard error. The rule
then reads "veepin never pins curves, except in the one package whose entire
purpose is to raise the floor" — one exception to argue about, not eight, and
the guard keeps catching the vendor-workaround commit it was written for.

`TestGoDefaultsStillNegotiateMLKEM` needs no change, and gains a sibling that
asserts `pqpolicy.HardenTLS` produces a config that actually refuses a classical
peer — the measured behaviour in §"Verified", pinned.

## 6. `pq-ikev2` — the one that is real protocol work

Every other variant is a bool and a call. IKEv2 is not, and it splits in two.

### 6.1 The key-exchange half — a reject path (small)

The responder accepts ADDKE1 opportunistically today (`internal/ikev2/ike/sa_init.go:122-140`)
and has no configuration for it whatsoever; `PostQuantum` exists only on the
client. Under `pq-ikev2`:

- `ike.ServerConfig` gains `RequirePostQuantum bool`, threaded from
  `ikev2.ServerConfig`.
- In `handleSAInit`, when `RequirePostQuantum` and the selected proposal yields
  no ADDKE group — or the initiator did not advertise
  `INTERMEDIATE_EXCHANGE_SUPPORTED` — respond `NO_PROPOSAL_CHOSEN` and log which
  of the two was missing. The distinction matters diagnostically: a peer that
  proposed ML-KEM without the intermediate exchange is misconfigured
  differently from one that proposed no ML-KEM at all.
- The client already errors when it asked for PQ and the responder did not
  accept (`internal/ikev2/ike/client.go:579`). `pq-ikev2`'s client sets the same
  flag; that path is reused, not rewritten.

### 6.2 The authentication half — H3b, and it is now in scope

This is the piece D1 pulls in, and `claims-and-reach-plan.md` had it gated. The
gate was "no peer implements it"; under D1 with class-B evidence rules that
becomes a labelling question rather than a blocker, and the specification half
is settled: `draft-ietf-ipsecme-ikev2-pqc-auth` is at **-12**, IESG state
*Approved-announcement sent*.

The scoping was already done in that document and holds. Concretely:

1. **`sigHashList` gains the Identity hash (value 5).** `internal/ikev2/ike/certauth.go:82`
   currently offers SHA-512/384/256 and nothing else. ML-DSA hashes the message
   internally, so no external hash is applied and the Identity hash is what says
   so. This is the one wire change with teeth: omit it and a conforming peer
   will not select ML-DSA.
2. **`knownSigAlgs` gains three ML-DSA entries** using the DER identifiers
   measured above — 13 octets, absent parameters, *not* the 15-octet
   NULL-parameter form the RSA entries use.
3. **`chooseSigAlg` gains an `*mldsa.PublicKey` arm.** Its current switch handles
   `*rsa.PublicKey` and `*ecdsa.PublicKey`; the ML-DSA arm selects on the
   parameter set and requires the peer to have advertised the Identity hash.
4. **`sigAlg` grows past its `isRSA bool`.** Two families fit in a bool; three do
   not. Replace it with a small enum before adding the third, or the next reader
   inherits `isRSA == false` meaning "ECDSA or ML-DSA, check elsewhere".
5. **Fragmentation is exercised for real.** A 3309-octet signature plus a
   5444-octet certificate makes IKE_AUTH multi-fragment on any path. This tree
   fragments outbound and reassembles inbound, and `pq-ikev2` is the first thing
   that makes that mandatory rather than incidental. Expect an off-by-one; the
   `pq-ikev2` self-cell is what finds it.

### 6.3 The evidence, and its honest label

- **KEX half: real peer today.** `strongswan-pq` (sid) implements RFC 9370. The
  existing `TestInteropVeepinClientStrongswanServerPQ` /
  `TestInteropStrongswanClientVeepinServerPQ` cells prove the path; `pq-ikev2`
  adds the one that matters — a **negative** cell where strongSwan offers
  classical-only proposals and the veepin `pq-ikev2` server **refuses**, asserted
  through `runInteropRequiringLog` on the rejection line. That negative cell is
  the entire value of the variant, and a bare ping cannot substitute for it.
- **Auth half: no peer until strongSwan 6.1.0.** Its ML-DSA work sits on an
  `ml-dsa` branch targeted at 6.1.0, whose ETA upstream tied to the draft
  finalising — which has now happened. Until then the auth half carries `—†` and
  a sentence in `doc/security.md` saying no third-party implementation has
  verified it.

## 7. Interop: the cells, and what each one is worth

Per `AGENTS.md`, a veepin↔veepin cell proves the two halves agree with each
other, not that they are right. Each variant therefore declares what its
evidence actually is.

| Variant | Client cell | Server cell | Self cell |
|---|---|---|---|
| `pq-ikev2` | strongSwan (KEX) / `—†` (auth) | strongSwan + **negative refusal cell** | ✓ |
| `pq-openvpn` | `openvpn` 2.6.14 on trixie, pending §8 | same | ✓ |
| `pq-masque` | aioquic, pending §8 | same | ✓ |
| `pq-anyconnect`, `pq-fortinet`, `pq-gp`, `pq-pulse` | `—†` | `—†` | ✓ |
| `pq-sstp`, `pq-softether` | `—†` | `—†` | ✓ |
| `pq-ssh` | `sshd` on **trixie** (KEX only) | `ssh` on **trixie** (KEX only) | ✓ |

Mechanics that are not optional:

- **Every `TestInterop*` must appear in `internal/livingreadme/interop.go`.** A
  test absent from the matrix runs in no CI shard and therefore never runs.
- **Each new facade directory goes in *both* path-filter lists** in
  `.github/workflows/interop.yml`.
- **Tear down between local runs.** `docker compose -f compose.<cell>.yml down -v
  --remove-orphans`, or a reused container tests the old code.
- **New peer images are new directories**, not bumps of existing ones — the
  `strongswan-pq` precedent. `sshd-pq` and `openvpn-pq` on trixie sit beside
  `sshd` and `openvpn` on bookworm/alpine. Existing cells keep their current
  peers and their current results; nothing in the 103-cell matrix is revalidated
  as a side effect of this work.

## 8. Two surveys to run before promising the class-A rows

Both are half a day and both are genuinely half a day either way.

1. **Does `openvpn` 2.6.14 accept an ML-DSA certificate?** It links OpenSSL
   3.5.6, so the library can. Whether OpenVPN's own certificate handling,
   `--tls-cert-profile` logic and key-type checks accept one is a separate
   question with a real chance of "no". Run it before `pq-openvpn` is promised
   as class A; if it fails, `pq-openvpn` is class B and says so.
2. **What does aioquic do?** `tests/interop/masque` is Python; aioquic brings its
   own TLS 1.3 and the odds of ML-KEM support are low and of ML-DSA lower. If
   both are absent, `pq-masque` is class B. MASQUE is TLS-1.3-only already, so
   the *key exchange* half may pass where the auth half does not — which is
   exactly the partial result worth publishing.

## 9. The guards, and what each needs

| Guard | What this work owes it |
|---|---|
| `docs_test.go` — `TestPackageDocNamesEveryProtocol` | `doc.go` names every new `pq*` package |
| `docs_test.go` — `TestREADMECountsProtocolsCorrectly` | **Nothing** — variants are outside `Protocols()`, so "sixteen" stands. Verify this rather than assume it. |
| `docs_test.go` — `TestEveryOptConstIsDescribedByAnOptSpec` | Nothing new — variants declare no `Opt*` consts |
| `cmd/veepin/main_test.go` | A `connect` case for every variant; the test iterates the registry, so extend it to `Variants()` |
| `cmd/veepin/flags_test.go` (all five) | Extend to iterate variants, which resolve their specs through the base. This is the check that the fallback in §4.1 actually works. |
| `autherr_test.go` | Variants inherit their base's `ErrAuth` behaviour; assert rather than assume |
| `abandon_test.go` | Every variant's `*Server` still asserts `client.AbandonableServer` |
| `pqtls_test.go` — `TestNoTLSConfigPinsCurvePreferences` | The `internal/pqpolicy` exception, per §5 |
| `internal/livingreadme/interop_test.go` | Every new `TestInterop*` in the matrix, and vice versa |
| `fuzztargets_test.go` | No new `Fuzz*` expected; if any appear, `ci.yml` `TARGETS` **and** `expected=N` |
| `nm/cmd/.../TestAllSupportedProtocolsRegistered` | Decide whether NM offers variants — see §11 |
| `tests/e2e/harness/registry_test.go` | Blank-import every new `pq*` facade |

New guards this work should add:

- **`TestEveryVariantResolvesItsBaseOptSpecs`** — a variant's generated flag set
  is identical to its base's. This is what stops the two drifting.
- **`TestPQVariantsRefuseAClassicalPeer`** — for each variant, an in-process
  handshake against a deliberately classical peer must fail. The claim is
  refusal; refusal is what gets tested.
- **`TestPQServerRefusesAClassicalCredential`** — `NewServer` on a `pq-` name with
  an RSA certificate fails at construction.
- **`TestSSHIsTheOnlyPQAuthException`** — the named-exception table from §3
  class C, so a second exception has to be added deliberately.

## 10. Phases

One commit per phase; they serialise where they touch `doc.go` and the README.

1. **`client.RegisterVariant` + `Variants()` + OptSpec fallback.** No protocol
   uses it yet. Guard updates in `flags_test.go` and `main_test.go` land here, so
   the machinery is proven before anything depends on it.
2. **`internal/pqpolicy`**, with unit tests including the measured refusal
   behaviour. Plus the `pqtls_test.go` exception from §5.
3. **`pq-ikev2`, key-exchange half.** `RequirePostQuantum` on the responder, the
   reject path, the facade, the negative strongSwan cell. **This is the phase
   that proves the whole pattern**, and it has a real peer — do it before
   multiplying by ten.
4. **`pq-ikev2`, authentication half (H3b).** Identity hash, ML-DSA
   `AlgorithmIdentifier`s, `chooseSigAlg`, the `sigAlg` enum, fragmentation
   exercise. Largest single phase.
5. **`pq-openvpn` and `pq-masque`**, gated on the §8 surveys.
6. **The class-B family** — `pq-sstp`, `pq-anyconnect`, `pq-fortinet`, `pq-gp`,
   `pq-pulse`, `pq-softether`. Individually trivial once phases 1–2 exist; the
   `-no-dtls` forcing for two of them is the only non-mechanical part.
7. **`pq-ssh`**, subject to §11's decision, with the `sshd-pq`/`ssh-client-pq`
   trixie images.
8. **Retire `ikev2 -pq`** (D2), with whatever deprecation window is chosen.
9. **Docs.** `doc/security.md` gains the `pq-` contract, the class-D
   impossibility list, the SSH exception, and the honest evidence labels;
   `doc/usage/` gains a page per variant; the README gains the variant table
   *without* changing its counts; each `internal/<proto>/README.md` caveats
   section gains a line.

## 11. Outcome — what was built, and how the open questions were answered

Everything in phases 1–10 landed. The four questions §11 left to a person were
answered as this page recommended, and the reasoning is recorded here rather
than in a commit message nobody will find:

1. **`pq-ssh` ships**, as the single named exception in `pqpolicy.SSHKeyExchangeOnly`,
   with `TestSSHIsTheOnlyPQAuthException` holding that list at one entry. It
   turned out to be worth more than expected: veepin's SSH cell had **no**
   post-quantum key exchange in common with its peer at all, so the variant is
   the difference between a post-quantum key exchange and none, not between two
   grades of one.
2. **NetworkManager does not offer the variants.** The CLI, the supervisor and
   the management panel carry them; `nm/` follows if someone asks.
3. **`ikev2 -pq` is deprecated rather than removed**, warning at Warn level for
   one release. It has shipped, so it is in runbooks and in profiles on disk.
4. **The six no-peer variants ship**, with `—†` on both directional cells and a
   sentence in `doc/security.md` saying no third-party implementation has
   verified them.

### What the implementation changed about the plan

- **§8's two surveys were not needed to start.** `pq-openvpn` and `pq-masque`
  landed with the same seam as the rest; whether their peers accept ML-DSA is
  now a question about a cell rather than about whether the code exists.
- **The `<proto>/pq/` placement paid for itself twice.** `interop.yml` needed no
  new path filters, because `ikev2/**` already matches `ikev2/pq/`. And the
  blank imports read as what they are.
- **The OptSpec fallback held**, which was the plan's own named risk. No variant
  needed a table of its own, so the cost estimate did not triple.
- **`sigAlg`'s `isRSA` bool was replaced rather than extended**, per §6.2 step 4.
- **keygen gained ML-DSA chains**, which the plan did not anticipate. Without it
  a listener created under a `pq-` name in the panel would generate an ECDSA
  credential that the same listener then refuses at construction — a trap laid
  by two correct pieces of code meeting.

### Three things the tests caught that review would not have

- **`connect.go` decided protocol-vs-profile with `client.Protocols()`**, which
  excludes variants by design. So every `pq-` name was unreachable from `veepin
  connect` while `veepin serve` worked perfectly. Found by an interop cell, not
  by any unit test — none of them went through that gate.
  `TestEveryDialableNameResolvesAsAProtocol` now does.
- **`newCertCredential` rejected ML-DSA keys outright**, so the whole IKEv2 AUTH
  path would have been unreachable through any real credential.
- **`net.Pipe` deadlocks when a client rejects a certificate mid-flight** — both
  ends end up writing, neither reading. The refusal tests hang rather than fail
  without deadlines on the pipe.

### The evidence, as it actually stands

| Cell | Peer | Result |
|---|---|---|
| `TestInteropPQIKEv2ServerAcceptsAPostQuantumPeer` | strongSwan (sid) | ✓ ML-KEM-768 negotiated |
| `TestInteropPQIKEv2ServerRefusesAClassicalPeer` | strongSwan (sid), classical proposal | ✓ **refused**, with the reason logged |
| `TestInteropPQSSHClientSSHD` | OpenSSH 10.0p2 (trixie), kex pinned | ✓ no classical path existed |
| `TestInteropPQSSTPSelf` | veepin | ✓ — and labelled self-only |

The second row is the one that matters. Everything else in this matrix asserts
that something works; that cell asserts that something is refused, which is the
only claim that distinguishes `pq-ikev2` from `ikev2` — and a real third-party
implementation is what does the distinguishing.

**Still outstanding**, and deliberately: `pq-ikev2`'s ML-DSA *authentication*
has no third-party peer until strongSwan 6.1.0 ships, and the four
openconnect-backed variants have none at all while openconnect links GnuTLS.
Neither is a code gap.

## 12. The original open questions

1. **Does `pq-ssh` ship?** It cannot meet D1 — SSH has no post-quantum signature
   algorithm anywhere. Ship it as a named exception (recommended: it is a real
   improvement over today's silent fallback to `curve25519-sha256`), or omit it
   until SSH grows one?
2. **Does NetworkManager offer the variants?** Adding them means ten
   `SupportedProtocols` entries, ten `LABEL_` lines in `nm/Makefile`, and ten
   `PROTO` rows plus `FieldDef` tables in `nm/editor/veepin-editor.c` — for
   protocols whose desktop users mostly cannot reach a PQ peer. Recommendation:
   **no**, initially; the CLI and the management panel carry them, and NM follows
   if anyone asks.
3. **How long does `ikev2 -pq` stay as a deprecated alias?** D2 retires it. A
   flag that has shipped is in runbooks and in profiles on disk; removing it in
   the same release that introduces `pq-ikev2` breaks both with no overlap.
   Recommendation: one release accepting it with a `Warnf`, then removal.
4. **Is a `pq-` variant with `—†` on both directional cells worth shipping at
   all?** Six protocols are in that position and will be for years. The
   alternative reading is that a guarantee nobody can interoperate with is a
   guarantee nobody can use. Recommendation: **ship them** — they are
   veepin↔veepin usable today, which is a real deployment for anyone running both
   ends, and they are the thing that is already correct when GnuTLS moves.

## 13. Risks

- **The naming implies a promise about class D.** "Where is `pq-wireguard`?" is
  the first question this scheme invites. `doc/security.md` must answer it in the
  same breath as introducing the scheme, or the answer gets re-derived by
  everyone who reads the table.
- **Six variants with no external evidence is the item-8 position.** It is
  accepted here deliberately (D4, and §11 Q4) rather than by oversight, and it is
  survivable *only* if the `—†` labels and the `doc/security.md` sentence are
  written honestly at the same time as the code. Shipping the code first and the
  labels later is how a false ✗ ends up on the front page.
- **The OptSpec fallback is the load-bearing simplification.** If it turns out a
  variant genuinely needs its own spec table, the plan's cost estimate roughly
  triples. Phase 1 exists to find that out before phases 3–7 depend on it.
- **`sigAlg`'s `isRSA bool` will be extended rather than replaced** unless §6.2
  step 4 is done deliberately. The result compiles, passes, and is wrong to read.
- **strongSwan 6.1.0 could ship mid-project**, which would turn `pq-ikev2`'s auth
  half from class B to class A. That is a good problem; the plan should be
  re-read when it happens rather than followed past it.
- **A future Go release could add a mechanism to the TLS default that
  `pqpolicy` does not list**, silently narrowing what `pq-` accepts. The
  `TestGoDefaultsStillNegotiateMLKEM` sibling in §5 is the guard, and it should
  assert against the pinned list rather than against `nil`.
