# Interop tests

Docker-based interoperability tests that run veepin against a real peer and
prove a working tunnel with a cross-tunnel `ping`: **strongSwan** for IKEv2/ESP
(both directions), the reference **wireguard-go** for WireGuard, and a stock
**openvpn** server for OpenVPN (across every control/data profile).

```sh
make interop
# or: go test -tags interop ./tests/interop/...
```

They are guarded by the `interop` build tag and need Docker, so they are
excluded from the default `go build`/`go test ./...` and add no module
dependency. Tests skip cleanly if Docker is unavailable.

## Scenarios

| Test | Client | Server | Ping |
|------|--------|--------|------|
| `TestInteropSelf` | `veepin connect ikev2` | `veepin serve ikev2` | `10.10.10.1` |
| `TestInteropVeepinClientStrongswanServer` (A) | `veepin connect ikev2` | strongSwan | `10.20.30.254` |
| `TestInteropStrongswanClientVeepinServer` (B) | strongSwan | `veepin serve ikev2` | `10.10.10.1` |
| `TestInteropVeepinClientWireguardServer` | `veepin connect wireguard` | wireguard-go | `10.10.10.1` |
| `TestInteropWireguardClientVeepinServer` | wireguard-go | `veepin serve wireguard` | `10.10.10.1` |
| `TestInteropWireguardSelf` | `veepin connect wireguard` | `veepin serve wireguard` | `10.10.10.1` |
| `TestInteropVeepinClientOpenVPNServer` | `veepin connect openvpn` | openvpn (GCM, plain TLS) | `10.8.0.1` |
| `TestInteropOpenVPNTLSAuth` | `veepin connect openvpn -tls-auth` | openvpn (GCM, `--tls-auth`) | `10.8.0.1` |
| `TestInteropOpenVPNTLSCrypt` | `veepin connect openvpn -tls-crypt` | openvpn (GCM, `--tls-crypt`) | `10.8.0.1` |
| `TestInteropOpenVPNCBC` | `veepin connect openvpn -cipher AES-256-CBC` | openvpn (AES-256-CBC) | `10.8.0.1` |
| `TestInteropVeepinClientL2TPServer` | `veepin connect l2tp` | strongSwan + xl2tpd | `10.30.0.1` |
| `TestInteropL2TPClientVeepinServer` | strongSwan + xl2tpd | `veepin serve l2tp` | `10.20.0.1` |
| `TestInteropL2TPSelf` | `veepin connect l2tp` | `veepin serve l2tp` | `10.20.0.1` |
| `TestInteropVeepinClientAnyConnectServer` | `veepin connect anyconnect` | ocserv | `10.12.0.1` |
| `TestInteropAnyConnectClientVeepinServer` | openconnect | `veepin serve anyconnect` | `10.11.0.1` |
| `TestInteropAnyConnectSelf` | `veepin connect anyconnect` | `veepin serve anyconnect` | `10.11.0.1` |

## Layout

- `Dockerfile` (repo root) — veepin runtime image (static binaries + ip/iptables/ping).
- `strongswan/` — strongSwan image + swanctl configs for responder and initiator roles.
- `wireguard/` — reference wireguard-go image + wg-quick responder entrypoint.
- `openvpn/` — reference openvpn server image + one `server*.conf` per profile
  (plain GCM, tls-auth, tls-crypt, CBC), selected by `SERVER_CONF`.
- `l2tp-server/` — reference L2TP/IPsec server image: strongSwan (IKEv1, transport
  mode) plus xl2tpd/pppd as the LNS.
- `l2tp-client/` — reference L2TP/IPsec client image: the same pair in initiator /
  LAC roles, as a Linux desktop dials an L2TP VPN.
- `ocserv/` — reference AnyConnect server (ocserv) image + config.
- `openconnect/` — reference AnyConnect client (openconnect) image.
- `veepin/` — entrypoints for `veepin serve` / `veepin connect`.
- `compose.*.yml` — one per scenario.
- `interop_test.go` — the `//go:build interop` harness (compose up → retry ping → down).

## Notes

- Both directions negotiate `aes256gcm16-prfsha256-curve25519` (IKE) /
  `aes256gcm16` (ESP) / PSK — the one suite veepin and strongSwan share.
- strongSwan needs its `openssl` plugin (`libstrongswan-standard-plugins`) for
  X25519, and `encap = yes` as an initiator (veepin has no raw-ESP path).
- `rp_filter=0` (set via compose `sysctls`) is required on the strongSwan side or
  the kernel drops XFRM-decrypted packets.
- A flat 2-container network suffices: the veepin client forces NAT-T, so no
  intermediate NAT router is needed.
- The WireGuard scenario uses **userspace** wireguard-go (via
  `WG_QUICK_USERSPACE_IMPLEMENTATION`), so it needs only `CAP_NET_ADMIN` and
  `/dev/net/tun` — no host WireGuard kernel module. Its keys are fixed test
  material baked into `compose.wireguard.yml`, a preshared key among them.
- The L2TP/IPsec scenarios negotiate IKE `aes256-sha256-modp2048` and ESP
  `aes256-sha256` with a PSK, and both ends set `encap = yes` / force NAT-T:
  veepin's ESP data path is a userspace UDP socket, so ESP must be
  UDP-encapsulated on 4500 even though the container network has no NAT. Their
  pppd containers are `privileged` and mount `/dev/ppp`, as the SSTP one is,
  because pppd sets the PPP line discipline on its pty. pppd is configured to
  refuse everything but MS-CHAPv2, so a pass cannot be a silent fallback to PAP.
- The AnyConnect scenarios share one throwaway self-signed certificate per run,
  generated into `anyconnect/pki/` (gitignored). The veepin client passes
  `-insecure`; openconnect has no such flag, so its entrypoint pins the
  certificate by computing `pin-sha256:base64(sha256(SubjectPublicKeyInfo))` —
  note this is an SPKI pin, not a digest of the whole certificate. openconnect
  runs with `--no-dtls`, since veepin implements the CSTP (TLS) data channel.
- The OpenVPN scenarios share one throwaway EC PKI and a 2048-bit static key,
  generated per run into `openvpn/pki/` (gitignored) and mounted into both ends.
  The four profiles reuse one server image and one client entrypoint; the server
  picks its config via `SERVER_CONF` and the client its extra flags via
  `CLIENT_ARGS`.
