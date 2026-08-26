# internal/fortinet

The FortiOS SSL VPN protocol: the HTTPS authentication/configuration exchange, the
PPP-over-TLS data tunnel, an optional PPP-over-DTLS data channel, and the `ret=2`
two-factor challenge. Transport-light on purpose — PPP link setup (LCP/IPCP) is
[`internal/ppp`](../ppp), and the carrier is an ordinary TLS (or DTLS) connection.

## Specification

FortiOS SSL VPN has no public RFC; the wire behaviour is defined by the gateway and
by `openconnect`'s Fortinet support, against which veepin interoperates. The DTLS
channel uses [`internal/dtls`](../dtls) (cert-based ECDHE-ECDSA); 2FA codes use
[`internal/otp`](../otp).

## Login, tunnel, and the optional DTLS channel

```mermaid
flowchart TD
    LOGIN["POST /remote/logincheck (username/password/realm)"] --> R{gateway response}
    R -->|ret=1| COOKIE["SVPNCOOKIE session cookie"]
    R -->|ret=2| CH["challenge: answer with a second factor (TOTP)"]
    CH --> LOGIN
    COOKIE --> CFG["GET tunnel config XML: address, netmask, DNS, routes"]
    CFG --> TLS["PPP-over-TLS tunnel (6-octet framing)"]
    CFG -. GFtype cookie exchange .-> DTLS["PPP-over-DTLS channel (UDP), attaches alongside TLS"]
    TLS <--> TUN["TUN"]
    DTLS <--> TUN
```

## API surface

- **Auth/config** — `BuildLoginForm`, `BuildLoginSuccess`, `BuildConfigXML`,
  `TunnelRequest`, `PathLoginCheck`.
- **2FA** — `Challenge`, `ChallengeRequest`/`ParseChallengeForm`,
  `BuildChallengeForm`, `BuildChallengeResponse`, `IsChallengeForm`, `ErrChallenge`.
- **TLS framing** — `EncodeFrame`, `ParseFrame`, `ReadFrame`, `ErrShortFrame`.
- **DTLS channel** — `DialDTLS`, `BuildDTLSClientHello`/`ParseDTLSClientHello`,
  `BuildDTLSServerHello`/`ParseDTLSServerHello`, `ErrNoDTLS`.
- `ErrAuth`.

## Implementation notes & caveats

- **The DTLS channel is cert-based and attaches *alongside* the TLS tunnel.** It is
  not a replacement: both carriers move packets for the same session. **Detaching a
  DTLS carrier loses in-flight datagrams by design** — the peer can't know until its
  read loop sees the close — so tests assert eventual recovery, not zero loss. See
  [[fortinet-dtls-channel]].
- **The GFtype ClientHello cookie requires a trailing NUL.** Without it there were
  two encodings for one cookie (a fuzz crash); `ParseDTLSClientHello` now requires
  the NUL terminator.
- **The `ret=2` challenge form must preserve field order — don't use `url.Values`.**
  It sorts keys, and Fortinet's `ftm_push` flow requires `magic` to be **last**;
  the form is hand-built (`challengeEcho` with `magic` last). See [[fortinet-ssl-vpn]].
- **openconnect's `--token-secret` treats a bare value as raw ASCII** — a base32
  TOTP secret needs the `base32:` prefix, or the generated codes won't match.
- **Liveness is an LCP Echo over whichever carrier is live.** Fortinet reads as
  a TLS protocol, and a TLS read error does surface a dead peer — but once DTLS
  attaches it is the egress, and a UDP path can stop delivering without ever
  erroring (an expired NAT binding is the ordinary way). `readAlt` detaches on an
  error and silence is not one, so the healthy TCP connection sat beside a tunnel
  that moved nothing. `internal/ppp` answered echoes and never sent one; it now
  has `SendEcho`, and `Client.Probe` runs it down the current carrier.
- **The client direction has no open-source gateway to test against** with a full
  data path; the independent-implementation proof is real openconnect *client* ↔
  veepin server (see the interop-matrix note in the root README). RSA-key gateways
  fall back to TLS-only since the DTLS channel needs an ECDSA cert.
- **`pq-fortinet` loses the DTLS data channel**, for the reason `pq-anyconnect`
  does: `internal/dtls` has no post-quantum key exchange, so a bound UDP channel
  under a post-quantum name would leave the bulk traffic classical. The variant
  forces `-no-dtls`. Its only evidence is `TestInteropPQFortinetSelf` —
  openconnect links GnuTLS, which has no ML-KEM group — which is
  veepin↔veepin and proves the two halves agree, not that they are right.
