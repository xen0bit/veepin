# veepin: AmneziaWG (obfuscated WireGuard)

## What this is

A fork of WireGuard that leaves the cryptography **completely untouched** —
Noise IK, Curve25519, ChaCha20-Poly1305, the same handshake and the same
transport keys — and changes only what the packets *look like* to a passive
observer. Its purpose is to defeat the deep-packet-inspection signature that
makes stock WireGuard trivially classifiable and therefore trivially blockable.

`amneziawg-go` is a Go implementation, so the interop peer is unusually cheap to
stand up, and there is a kernel module for the performance case.

## Why it earns a place

veepin has **no probe-resistance or traffic-shaping-against-classification story
at all** beyond `dataplane.Shaper`, which pads sizes but does nothing about
signatures. Stock WireGuard is the most fingerprintable protocol in the tree: the
first four octets of every handshake message are a fixed, well-known type
constant with three zero bytes, and the message lengths are constants (148, 92,
32+N). A classifier needs one packet.

This is a different axis from everything else on the roadmap. It is not another
vendor's remote-access product; it is a capability class.

## What actually changes

Documented parameters, to be verified against `amneziawg-go` before
implementation:

- **`Jc`** — a count of junk packets sent before the real handshake.
- **`Jmin` / `Jmax`** — the size range those junk packets are drawn from.
- **`S1` / `S2`** — bytes of random padding prepended to the handshake initiation
  and response respectively, which breaks the fixed-length signature.
- **`H1`…`H4`** — replacements for the four fixed message-type constants, drawn
  from a configured range, which breaks the fixed-header signature.

Later versions add protocol *mimicry* — shaping the flow to resemble QUIC, DNS
or SIP. Treat that as a second phase; the parameter-based obfuscation above is
the core and is what the widely deployed configurations use.

Both ends must be configured with identical parameters. There is no negotiation
— which is the point, since a negotiation would itself be a signature. That has a
direct consequence for veepin's config surface: these are peer configuration,
like a pre-shared key, not something `Dial` discovers.

## Reuse

Very high. `internal/wireguard/{noise,transport,wire}` all stay as they are. The
change is confined to:

- the message-type constants becoming configurable values rather than `const`;
- a padding prefix on the two handshake messages, stripped on receive;
- a junk-packet emitter before the handshake, and a receiver that discards
  unparseable datagrams before the handshake completes (which it must already do
  safely — worth confirming the current code does not log or allocate per stray
  packet).

The honest risk is that `internal/wireguard`'s parsers are written against those
constants in ways that are awkward to parameterise. Read `wire.go` first.

## Phases

1. Read `amneziawg-go` and pin the exact parameter semantics and defaults into
   this document.
2. `internal/wireguard`: make the four message types configurable, defaulting to
   the stock values so nothing changes for existing users. Land this alone, with
   the full WireGuard interop matrix green — it touches a shipped protocol.
3. Padding and junk-packet support behind a config struct that is zero-valued by
   default.
4. Facade: whether this is `wireguard` with options or a separate `amneziawg`
   protocol. **Recommendation: a separate facade package** registering as
   `amneziawg`, reusing `internal/wireguard` — because the README table and the
   NM plugin want it to be a distinguishable choice, and because a stock
   WireGuard peer cannot talk to a configured AmneziaWG peer, so presenting them
   as one protocol with a flag would mislead.
5. Fuzz the obfuscated parsers — they now accept variable-length prefixes on
   unauthenticated input, which is exactly where a length bug becomes a remote
   crash.
6. Interop against `amneziawg-go`, plus a **negative cell**: stock `wireguard-go`
   must *fail* to complete a handshake against a configured AmneziaWG veepin
   server. A cell that only proves the positive case would pass even if the
   obfuscation were a no-op.

## Risks

- **It is obfuscation, not security.** It resists classification; it does not add
  confidentiality, and it does not resist an active prober that knows the
  parameters. `doc/security.md` must say so, and must not let "DPI-resistant"
  read as "more secure".
- **Touching `internal/wireguard` risks a shipped protocol.** Phase 2 is the
  dangerous one and should be reviewed as such.
- **Junk packets cost bandwidth and battery**, and the defaults matter. Do not
  enable any of it by default.
- **Parameter mismatch fails silently**, as a handshake that never completes.
  The error message should say "no response — check that both ends use the same
  obfuscation parameters" rather than a bare timeout, because that will be the
  single most common support question.
