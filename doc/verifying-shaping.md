# Verifying downstream shaping against a stock client

Downstream flow shaping ([`traffic-shaping.md`](traffic-shaping.md)) is **off by
default**, and the only thing keeping it off is that no vendor OS stack has been
tried. Seven third-party receivers pass in CI, but all seven are Linux userspace
— strongSwan, wireguard-go, `openvpn`, pppd, openconnect. The clients the feature
exists to protect are the ones built into Windows, macOS, iOS and Android, and
none of them can be run in a container.

So this is the one step that needs a person and a device. This note exists to
make it a twenty-minute job rather than an afternoon.

## What you are testing

That a stock client, talking to a shaped veepin server, **still works** — and
that it works because the padded packets are accepted and the inner packet is
recovered intact, not because something silently degraded.

Two failure modes are worth distinguishing:

- **Hard failure.** The client drops padded packets, or the tunnel never comes
  up. Obvious, and the outcome is that shaping stays opt-in for that protocol.
- **Quiet failure.** The tunnel comes up and small pings work, but something is
  wrong at size — MTU-adjacent packets are dropped, or throughput collapses
  because every padded packet fragments. This is the one a casual test misses,
  which is why the checks below include a large-payload ping and a throughput
  comparison rather than only `ping -c1`.

## Before you start

You need a machine that can run `veepin serve` and be reached from the client
device — a VPS, or a laptop on the same LAN with the port open. Everything below
assumes the server is at `$SERVER` and you are running as root (the TUN needs
`CAP_NET_ADMIN`).

```sh
git clone https://github.com/xen0bit/veepin && cd veepin && go build ./cmd/veepin
```

## Per-client server invocations

Each one is the ordinary server command plus `-shape 16384`. Nothing else
differs from a normal deployment, which is the point: if a stock client works
unshaped and fails shaped, the padding is the cause.

### Windows / macOS / iOS / Android — IKEv2

The most valuable single test, because IKEv2 is the protocol every mobile OS
ships a client for, and because ESP's TFC padding is the vehicle with the most
implementation variance.

```sh
sudo ./veepin serve ikev2 \
    -public "$SERVER" \
    -psk 'a-strong-preshared-key' \
    -id "$SERVER" \
    -pool 10.10.10.0/24 \
    -dns 1.1.1.1 \
    -shape 16384 \
    -setup-nat -wan eth0
```

Then add a VPN in the OS settings: type IKEv2, server `$SERVER`, remote ID
`$SERVER`, PSK as above. (iOS and macOS need the remote ID to match the
certificate or PSK identity exactly.)

### Windows — SSTP

The only OS with a built-in SSTP client, and the reason the PPP padding vehicle
matters.

```sh
sudo ./veepin serve sstp \
    -cert server.crt -key server.key \
    -user alice -pass hunter2 \
    -pool 10.9.0.0/24 -dns 1.1.1.1 \
    -shape 16384 \
    -setup-nat -wan eth0
```

The certificate must be one Windows trusts and must match the hostname the
client dials — SSTP's crypto binding hashes it, so a self-signed cert needs
installing in the machine store first.

### Windows / macOS — L2TP/IPsec

```sh
sudo ./veepin serve l2tp \
    -public "$SERVER" -psk 'a-strong-preshared-key' \
    -user alice -pass hunter2 \
    -pool 10.20.0.0/24 -dns 1.1.1.1 \
    -shape 16384 \
    -setup-nat -wan eth0
```

### Official WireGuard apps

Lowest risk of the set — WireGuard receivers have always had to trim by the
inner header for the protocol's mandatory 16-octet alignment padding — but worth
confirming, and the quickest to set up.

```sh
sudo ./veepin serve wireguard -config wg0.conf -shape 16384 -setup-nat -wan eth0
```

### FortiClient, Cisco AnyConnect

Use the `fortinet` and `anyconnect` servers with `-shape 16384`; see
[`usage/fortinet.md`](usage/fortinet.md) and
[`usage/anyconnect.md`](usage/anyconnect.md) for the base invocations.

## The checks

Run `scripts/verify-shaping.sh` **on the client device** once the tunnel is up.
It takes the server's tunnel address (the pool's first host — `10.10.10.1` for
the IKEv2 example above):

```sh
./scripts/verify-shaping.sh 10.10.10.1
```

It runs four checks, in increasing order of what they rule out:

| # | Check | Rules out |
|---|---|---|
| 1 | Small ping | The tunnel is not up at all |
| 2 | Ping with a 1200-byte payload | Padded packets are dropped at size, or fragment |
| 3 | Ping with DF set at MTU−28 | The path MTU has silently shrunk under the padding |
| 4 | 100-packet flood, loss counted | Intermittent drops a single ping would miss |

If you have no shell on the client (iOS), do checks 1 and 2 by hand — the OS
ping utilities in any terminal app accept `-s 1200` — and skip 3 and 4.

## Reading the result

- **All four pass.** That client tolerates padded packets. Record it in the
  table below and open a PR; enough entries and the `-shape` default can change.
- **1 passes, 2–4 fail.** The quiet failure. The client accepts the tunnel but
  not padded packets at size. Shaping must stay opt-in for that protocol, and
  the honest fix is *not* to reduce the padding target to something that fits —
  a smaller target leaves size classes standing, which is the signal the whole
  feature exists to remove.
- **Nothing passes.** Re-run the same server without `-shape` first. If that
  also fails, it is a configuration problem, not a shaping one.

## Results so far

| Client | Protocol | Result | Tested |
|---|---|---|---|
| strongSwan (Linux) | IKEv2 | pass | CI, every run |
| wireguard-go | WireGuard | pass | CI, every run |
| `openvpn` (Linux) | OpenVPN | pass | CI, every run |
| `sstpc`/pppd | SSTP | pass | CI, every run |
| openconnect | AnyConnect | pass | CI, every run |
| openconnect | Fortinet | pass | CI, every run |
| strongSwan + xl2tpd | L2TP/IPsec | pass | CI, every run |
| Windows 11 built-in | IKEv2 | — | not yet |
| Windows 11 built-in | SSTP | — | not yet |
| macOS built-in | IKEv2 | — | not yet |
| iOS built-in | IKEv2 | — | not yet |
| Android built-in | IKEv2 | — | not yet |
| WireGuard app (iOS/Android) | WireGuard | — | not yet |
| FortiClient | Fortinet | — | not yet |
| Cisco AnyConnect | AnyConnect | — | not yet |
