# AmneziaWG

AmneziaWG is a DPI-resistant fork of WireGuard. veepin's implementation reuses
the WireGuard noise handshake and ChaCha20-Poly1305 transport wholesale,
wrapping only the wire format to defeat packet-signature classification.

## Server

```sh
veepin serve amneziawg -listen-port 51820 -private-key <base64> \
    -address 10.10.0.1/24
```

## Client

```sh
veepin connect amneziawg -endpoint vpn.example.com:51820 \
    -private-key <base64> -public-key <server-pub> -address 10.10.0.2/24
```

## Obfuscation parameters

All flags default to zero, which reproduces stock WireGuard behaviour.

| Flag | AmneziaWG param | Description |
|------|-----------------|-------------|
| `-type-init` | H1 | Message type for handshake initiation |
| `-type-resp` | H2 | Message type for handshake response |
| `-type-cookie` | H3 | Message type for cookie reply |
| `-type-trans` | H4 | Message type for transport data |
| `-pad-init` | S1 | Random padding before initiation (bytes) |
| `-pad-resp` | S2 | Random padding before response (bytes) |
| `-pad-cookie` | S3 | Random padding before cookie reply (bytes) |
| `-pad-trans` | S4 | Random padding before transport data (bytes) |

These eight are accepted by both `connect` and `serve`. Three more are
client-only, since junk is emitted ahead of a handshake the client initiates:

| Flag | AmneziaWG param | Description |
|------|-----------------|-------------|
| `-junk-count` | Jc | Junk datagrams sent before the handshake (4-12 recommended) |
| `-junk-min` | Jmin | Smallest junk datagram (bytes) |
| `-junk-max` | Jmax | Largest junk datagram (bytes) |

Both ends must use identical parameters. There is no negotiation — that would
itself be a signature — so a mismatch is a handshake that never completes
rather than a fallback to stock behaviour.

Not implemented: the `I1`-`I5` custom signature packets, `HeaderProtectionKey`
(AWG 3+), and protocol mimicry. A deployment whose peers require them will not
interoperate.

## Interoperability

Verified against `amneziawg-go` in both directions
(`TestInteropVeepinClientAmneziaWGServer`,
`TestInteropAmneziaWGClientVeepinServer`), and veepin-to-veepin with every
parameter engaged including S3/S4 and junk packets
(`TestInteropAmneziaWGSelf`).

Note that `mac1` authenticates the message *including* its type word, so H1-H4
must be substituted before the MAC is computed, not after. veepin does this in
the noise layer for that reason.

## Security

AmneziaWG is **obfuscation, not encryption**. It resists passive classification
by DPI systems; it adds no confidentiality or integrity beyond what WireGuard
already provides, and it does not resist an active prober that knows the
parameters. The S1-S4 padding sits *outside* the AEAD and is unauthenticated:
an attacker may strip or rewrite it freely, gaining and costing nothing. Traffic
timing, flow duration and volume are unchanged, so a censor doing statistical
rather than signature analysis is unaffected. See
[`doc/security.md`](../security.md).
