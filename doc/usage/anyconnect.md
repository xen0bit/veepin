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
