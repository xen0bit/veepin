# internal/otp

The one-time-password algorithms a VPN gateway needs for a second authentication
factor: HOTP and the time-based TOTP built on it. Small enough that a dependency
would cost more than it saves — HOTP is an HMAC, a truncation and a modulo. Used by
Fortinet's 2FA (`ret=2` challenge).

## Specifications

- [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) — HOTP (HMAC-based OTP).
- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) — TOTP (time-based OTP).

## HOTP → TOTP → Verify

```mermaid
flowchart TD
    SEC["shared secret (base32)"] --> H["HMAC(secret, counter)"]
    H --> DT["dynamic truncation<br/>(RFC 4226 §5.3): low nibble picks a 31-bit window"]
    DT --> MOD["code = value mod 10^digits"]
    TIME["current time"] -->|counter = unix / period| H
    subgraph Verify (gateway)
      MOD --> CT["constant-time compare across ±skew steps"]
    end
```

## API surface

- `HOTP(secret, counter, cfg) (string, error)` — RFC 4226 code for one counter.
- `TOTP(secret, t, cfg) (string, error)` — code for a moment in time.
- `Verify(secret, code, t, cfg) bool` — constant-time, accepts ±`Skew` steps.
- `DecodeSecret(s)` — base32 as authenticator apps present it (case-insensitive,
  padding optional, spaces/dashes ignored).
- `Config` — `Algorithm` (`SHA1`/`SHA256`/`SHA512`), `Digits`, `Period`, `Skew`;
  zero value is the universal default (SHA1, 6 digits, 30 s, ±1 step).

## Implementation notes & caveats

- **Verification is constant-time on purpose** and lives *here*, not in a caller: a
  code is a shared secret for its step, so leaking how much of a guess matched
  would let an attacker find it digit by digit. Every candidate step is checked
  even after one matches, so the work done never reveals which step was accepted.
- **`digits()` treats only 0 as "unset".** A negative digit count is a caller
  mistake and is passed through to fail validation, not silently defaulted
  (regression-tested by `TestHOTPRejectsBadDigits`).
- **`Skew` semantics:** 0 means the usual ±1 step (absorbing phone/gateway clock
  drift); a positive value widens it; a negative value refuses any drift (strict).
- SHA1 here is HMAC, **not** a collision-resistance claim — it is the default every
  authenticator app assumes.
