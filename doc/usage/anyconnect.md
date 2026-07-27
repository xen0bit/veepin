# Running AnyConnect

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Connecting as an AnyConnect client

`veepin connect anyconnect` speaks the Cisco SSL VPN protocol to any AnyConnect
or ocserv server. Everything rides HTTPS, so only credentials are configured; the
address, DNS and MTU come back in the CONNECT response:

```sh
sudo ./veepin connect anyconnect \
  -server vpn.example.com -user alice -pass hunter2
```

`-insecure` skips certificate verification for a self-signed test server.

## Running an AnyConnect server

`veepin serve anyconnect` is the responder for the same protocol, and a stock
`openconnect` client connects to it unmodified:

```sh
sudo ./veepin serve anyconnect \
  -cert /etc/veepin/server.crt -key /etc/veepin/server.key \
  -user alice -pass hunter2 \
  -pool 10.11.0.0/24 -dns 1.1.1.1 -setup-nat -wan eth0
```

Clients are authenticated by password against the configured user, issued a
session cookie, and assigned an address from the pool. veepin implements the CSTP
(TLS) data channel; a client that would prefer DTLS falls back to it
automatically, and `openconnect --no-dtls` asks for it explicitly.

## Downstream flow shaping

`-shape <bytes>` pads the first N bytes of each inner flow out to the tunnel
MTU, so the size pattern of a TLS handshake made *inside* the tunnel does not
survive encapsulation:

```sh
sudo ./veepin serve anyconnect -shape 16384 ...
```

The filler goes after the inner IP packet in the CSTP data payload, whose
16-bit length field already delimits it. The receiver cuts back to the length the
inner IP header declares, as every IP stack does — Ethernet pads short frames the
same way — so **the client needs no support for it**; it is verified in Docker
against `openconnect`, whose ping replies could not come back from a mis-trimmed
packet.

Because the fingerprint it defends against targets handshakes, the budget is
spent per flow rather than per byte and bulk throughput is unaffected. It is off
by default and shapes the server's downstream direction only. See
[`doc/traffic-shaping.md`](../traffic-shaping.md) for what it does and does not
hide.
