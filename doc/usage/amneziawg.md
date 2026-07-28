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

Both ends must use identical parameters.

## Security

AmneziaWG is **obfuscation, not encryption**. It resists passive
classification by DPI systems; it does not add confidentiality or integrity
beyond what WireGuard already provides, and it does not resist an active
prober that knows the parameters.
