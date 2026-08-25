# Running the post-quantum variants (`pq-*`)

There is no separate runbook per variant, and that is the point: **a `pq-` name
takes exactly the flags its base protocol takes.** `veepin serve pq-sstp -h` and
`veepin serve sstp -h` print byte-identical flag sets, and a test
(`TestEveryVariantResolvesItsBaseOptSpecs`) fails the build if they ever diverge.
So for the options, read the base protocol's page — [`ikev2.md`](ikev2.md),
[`openvpn.md`](openvpn.md), [`sstp.md`](sstp.md), and so on. This page is only
about what changes when you put `pq-` in front of the name.

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` /
`setcap` setup every TUN-based protocol needs.

## What the prefix does

| Variant | Base | What becomes mandatory |
|---|---|---|
| `pq-ikev2` | `ikev2` | ML-KEM-768 as an additional key exchange (RFC 9370); ML-DSA in the RFC 7427 AUTH payload |
| `pq-openvpn` | `openvpn` | TLS 1.3, ML-KEM key exchange, ML-DSA certificates at **both** ends |
| `pq-masque` | `masque` | the same (mutual TLS) |
| `pq-sstp` | `sstp` | TLS 1.3, ML-KEM key exchange, ML-DSA server certificate |
| `pq-gp` | `gp` | the same — and the pushed ESP keys inherit it, since they travel inside that session |
| `pq-pulse` | `pulse` | the same, for the same reason |
| `pq-softether` | `softether` | the same |
| `pq-anyconnect` | `anyconnect` | the same, **plus `-no-dtls`** |
| `pq-fortinet` | `fortinet` | the same, **plus `-no-dtls`** |
| `pq-ssh` | `ssh` | `mlkem768x25519-sha256` — key exchange only |

In every case a peer that cannot meet the requirement is **refused**. It does not
fall back.

## Running one

Identical to the base protocol, with one extra requirement on the server:
**the certificate must be ML-DSA.**

```sh
sudo ./veepin serve pq-ikev2 \
  -listen 0.0.0.0 -public YOUR.PUBLIC.IP \
  -psk 'a-strong-preshared-key' -id vpn.example.com \
  -pool 10.10.10.0/24 -setup-nat -wan eth0
```

```sh
sudo ./veepin connect pq-ikev2 \
  -server vpn.example.com -psk 'a-strong-preshared-key' -id client.example
```

A TLS-carried variant needs an ML-DSA certificate and key:

```sh
sudo ./veepin serve pq-sstp -cert /etc/veepin/tls.crt -key /etc/veepin/tls.key \
  -user alice -pass 's3cret' -setup-nat -wan eth0
```

Point it at an RSA or ECDSA certificate and it refuses to start:

```
veepin: pqpolicy: credential is not post-quantum: the certificate holds a ECDSA
key, want ML-DSA (FIPS 204). A listener created under a pq- name through the
management panel generates one automatically; otherwise mint an ML-DSA
certificate, or drop the pq- prefix to use the base protocol
```

That happens **before the TUN is opened and before anything binds**, which is
deliberate: a listener that came up and then refused every client would be much
harder to diagnose.

## Getting an ML-DSA certificate

The easy path is the management panel. Create the listener under its `pq-` name
and veepin mints an ML-DSA-65 chain for it — `ca.crt`, `tls.crt`, `tls.key` in
the listener's config directory, exactly as it does an ECDSA chain for a base
protocol.

By hand, with Go 1.27 or later:

```go
key, _ := mldsa.GenerateKey(mldsa.MLDSA65())
der, _ := x509.CreateCertificate(rand.Reader, tmpl, parent, key.PublicKey(), key)
pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
// PEM-encode der as CERTIFICATE and pkcs8 as PRIVATE KEY
```

OpenSSL 3.5 or later can also do it (`openssl req -newkey mldsa65 …`). Note the
private key PEM is tiny — about 128 bytes — because PKCS#8 stores ML-DSA as its
32-octet seed rather than the expanded key. That is correct, not a truncated
file.

ML-DSA-65 is the parameter set to use unless you have a reason otherwise: it
matches ML-KEM-768's security level, which is what the IETF hybrid drafts
settled on and what `pq-ikev2` negotiates. ML-DSA-44 and ML-DSA-87 are both
accepted.

## Things that will surprise you

**PSK still works under `pq-ikev2`.** A pre-shared key is symmetric and is not
broken by a quantum adversary — that is the whole premise of RFC 8784. What
`pq-ikev2` refuses is classical *public-key* authentication. Use a high-entropy
PSK; the variant cannot check that for you.

**`pq-ikev2` has no username/password path.** EAP-MSCHAPv2 is refused, and not
for a quantum reason: its own primitives are MD4 and single-DES. Use PSK or an
ML-DSA certificate.

**`pq-anyconnect` and `pq-fortinet` lose their UDP data channel.** `-no-dtls` is
forced, because the DTLS 1.2 data channel has no post-quantum path at all.
Passing `-no-dtls=false` explicitly is an error rather than a silent override:

```
pq-anyconnect: no-dtls="false" is not available here: this variant always sets no-dtls="true"
```

The cost is real — the tunnel runs over TLS, with the head-of-line blocking that
implies. If that matters more to you than the guarantee, use `anyconnect`.

**`pq-ssh` only forces the key exchange.** SSH has no post-quantum signature
algorithm in any specification, so host keys and user keys stay classical —
[OpenSSH says so itself](https://www.openssh.org/pq.html). It also requires a
peer running **OpenSSH 9.9 or later**: earlier versions offer `sntrup761`, which
`golang.org/x/crypto` does not implement, so there is no post-quantum mechanism
in common and the connection is refused. Against those peers, base `ssh`
negotiates `curve25519-sha256` — which is what it silently did before this
variant existed.

**Most variants have no third-party peer to test against.** openconnect links
GnuTLS, which has no ML-KEM at all; `sstp-client`, SoftEther and aioquic are the
same story. Those variants are verified veepin↔veepin only, and
[`doc/security.md`](../security.md) says which is which rather than glossing it.

**`-pq` on base `ikev2` is deprecated.** It *offered* ML-KEM and accepted a
classical SA when the responder declined, which is the downgrade `pq-ikev2`
exists to close. It still works and warns; use the name.

## Where the design is written down

[`doc/pq-variants-plan.md`](../pq-variants-plan.md) — including the measurements
the plan was built on, several of which contradicted what was assumed at the
start. [`doc/security.md`](../security.md) has the boundaries.
