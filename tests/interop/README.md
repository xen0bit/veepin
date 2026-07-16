# Interop tests

Docker-based interoperability tests that run veepin against **strongSwan** and
prove a real ESP-in-UDP tunnel with a cross-tunnel `ping`, in both directions.

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

## Layout

- `Dockerfile` (repo root) — veepin runtime image (static binaries + ip/iptables/ping).
- `strongswan/` — strongSwan image + swanctl configs for responder and initiator roles.
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
