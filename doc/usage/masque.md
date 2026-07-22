# Running MASQUE (CONNECT-IP and CONNECT-UDP)

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Connecting as a MASQUE client

`veepin connect masque` opens a CONNECT-IP tunnel to a MASQUE proxy over
HTTP/3. There is nothing to authenticate beyond the proxy's TLS certificate and
whatever the proxy itself requires; the address is assigned by the proxy:

```sh
# Against a proxy with a certificate your system trusts:
sudo ./veepin connect masque -server proxy.example.com

# Against a self-signed proxy (skips certificate verification — testing only):
sudo ./veepin connect masque -server 10.0.0.1 -insecure
```

The proxy assigns an address and advertises a full-tunnel route, so the default
is to route everything through it; `-no-route` brings the interface up without
touching the system routing table.

## Running a MASQUE proxy

`veepin serve masque` is the CONNECT-IP responder. It needs a TLS certificate
and key, since the tunnel is HTTP/3 and the client verifies the proxy the way it
verifies any HTTPS server:

```sh
sudo ./veepin serve masque \
  -cert /etc/veepin/proxy.crt -key /etc/veepin/proxy.key \
  -pool 10.30.0.0/24 -setup-nat -wan eth0
```

Each client is one QUIC connection; the proxy assigns it a `/24` address from
the pool, advertises a default route, and forwards its packets, checking that a
client only ever sources traffic from the address it was given. The data path
runs in **capsule mode** (see [security boundaries](../security.md)): correct
and interoperable, but reliable-and-ordered rather than the datagram profile a
production MASQUE VPN would use.

The same proxy also serves **CONNECT-UDP** (RFC 9298): it dispatches on the
request's `:protocol`, so no separate server is needed.

## Forwarding a UDP flow (CONNECT-UDP)

`veepin udp-proxy` is the CONNECT-UDP client. It is not a VPN — it binds a local
UDP socket and forwards its datagrams to one target through a MASQUE proxy, the
way you would tunnel DNS or a QUIC service:

```sh
# Forward local :5353 to 1.1.1.1:53 through the proxy, then `dig @127.0.0.1 -p 5353`.
./veepin udp-proxy -server proxy.example.com -listen 127.0.0.1:5353 -target 1.1.1.1:53
```

There is no TUN and no routing to configure: a datagram in one side comes out at
the target, and its reply comes back. Each local sender gets its own CONNECT-UDP
flow over a shared QUIC connection to the proxy, and an idle flow is reclaimed
after a couple of minutes.
