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

Cryptokey routing runs both ways: `AllowedIPs` selects which peer an outbound
packet goes to, and an inbound packet whose source is outside a peer's
`AllowedIPs` is dropped. Peers roam (the return address follows each packet's
source), and replayed handshake initiations are rejected by their timestamp. A
veepin client rekeys on its own — re-running the handshake roughly every two
minutes and rotating the new keypair in without dropping traffic — so a tunnel
stays up indefinitely; see the note under
[What it does](../../README.md#what-it-does).
