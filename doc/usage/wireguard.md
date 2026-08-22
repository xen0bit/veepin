# Running WireGuard

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Connecting as a WireGuard client

`veepin connect wireguard` dials a WireGuard peer as an initiator. It takes a
wg-quick config file, individual flags, or both — a flag overrides the file's
value for the same field, so a checked-in config can carry a per-run override:

```sh
# From a wg-quick file (the same format `wg-quick` and the mobile apps use):
sudo ./veepin connect wireguard -config /etc/wireguard/wg0.conf

# Or entirely from flags:
sudo ./veepin connect wireguard \
  -private-key "$(wg genkey | tee privkey)" \
  -public-key SERVER_PUBLIC_KEY_BASE64 \
  -endpoint vpn.example.com:51820 \
  -address 10.0.0.2/32 \
  -allowed-ips 0.0.0.0/0 \
  -persistent-keepalive 25
```

The config's `AllowedIPs` become the tunnel's routes: a packet leaving the TUN
goes to the peer whose AllowedIPs match its destination most specifically, the
same cryptokey-routing rule WireGuard defines. As with IKEv2, `connect` applies
addressing and routing to the system, and `-no-route` brings the tunnel up
without touching either (useful for diagnostics).

## Running a WireGuard server

`veepin serve wireguard` is the responder. It reads a wg-quick server config —
one `[Peer]` per client — or a single peer from flags, and (with `-setup-nat`)
assigns the gateway address and installs the masquerade rule:

```sh
sudo ./veepin serve wireguard -config /etc/wireguard/wg0.conf -setup-nat -wan eth0
```

where `wg0.conf` is the standard server form:

```ini
[Interface]
PrivateKey = <server private key>
Address    = 10.10.0.1/24
ListenPort = 51820

[Peer]
PublicKey  = <client public key>
AllowedIPs = 10.10.0.2/32
```

`Address` is a list, and both families are honoured on both sides — the server's
own v6 address goes on the interface with `-setup-nat`, and the client's is
installed on its TUN:

```ini
[Interface]
Address = 10.10.0.1/24, fd00:10::1/64
```

WireGuard assigns nothing, so a peer's v6 address is its `AllowedIPs` and is
configured at both ends, exactly as its v4 address is. Order does not matter:
each entry lands in the field its own family names, and two addresses of one
family are refused rather than silently reduced to one.

Cryptokey routing runs both ways: `AllowedIPs` selects which peer an outbound
packet goes to, and an inbound packet whose source is outside a peer's
`AllowedIPs` is dropped. Peers roam (the return address follows each packet's
source), and replayed handshake initiations are rejected by their timestamp. A
veepin client rekeys on its own — re-running the handshake roughly every two
minutes and rotating the new keypair in without dropping traffic — so a tunnel
stays up indefinitely; see the note under
[What it does](../../README.md#what-it-does).

## Downstream flow shaping

`-shape <bytes>` pads the first N bytes of each inner flow out to the tunnel
MTU, so the size pattern of a TLS handshake made *inside* the tunnel does not
survive encapsulation:

```sh
sudo ./veepin serve wireguard -shape 16384
```

It uses the transport message's trailing octets, which a conforming
receiver ignores, so **stock OS clients need no support for it**. Because the
fingerprint it defends against targets handshakes, the budget is spent per flow
rather than per byte and bulk throughput is unaffected. It is off by default;
`veepin connect wireguard -shape` covers the upstream direction when both
ends are veepin. See [`doc/traffic-shaping.md`](../traffic-shaping.md) for what
it does and does not hide.
