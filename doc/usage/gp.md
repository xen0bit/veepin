# Running GlobalProtect (Palo Alto Networks SSL VPN)

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Connecting as a GlobalProtect client

`veepin connect gp` speaks GlobalProtect to a real Palo Alto gateway or to the
veepin server. Authentication is a username and password; the 32-hex-digit
authentication cookie the gateway issues carries the session:

```sh
sudo ./veepin connect gp -server vpn.example.com -user alice -pass hunter2

# Against a self-signed test gateway (skips certificate verification):
sudo ./veepin connect gp -server 10.0.0.1 -user alice -pass hunter2 -insecure

# Stay on the SSL tunnel even where the gateway hands out ESP keys:
sudo ./veepin connect gp -server vpn.example.com -user alice -pass hunter2 -no-esp
```

The client tries **ESP first** wherever the gateway's configuration carried a
keying block, and falls back to the TLS tunnel if the datagrams do not get
through — the usual reason being UDP 4501 blocked somewhere in the path. The log
line says which carrier ended up in use:

```
gp: tunnel up over ESP, assigned 10.50.0.2
gp: ESP unavailable (gp: the gateway did not answer on the ESP path), falling back to the SSL tunnel
```

That order is not a preference, it is the protocol: opening the SSL tunnel
invalidates the SPIs the same configuration handed out, so there is no way back
the other way.

## Running a GlobalProtect gateway

`veepin serve gp` is the gateway for the same protocol; a stock
`openconnect --protocol=gp --usergroup=gateway` connects to it unmodified. It
needs a TLS certificate and key, since the control plane and the SSL tunnel are
both HTTPS:

```sh
sudo ./veepin serve gp \
  -cert /etc/veepin/server.crt -key /etc/veepin/server.key \
  -user alice -pass hunter2 \
  -pool 10.50.0.0/24 -dns 1.1.1.1 -setup-nat -wan eth0
```

Each client authenticates, is assigned an address from the pool, and is handed a
freshly generated keying block — two SPIs and four ESP keys — inside its
configuration document. The gateway binds UDP 4501 for the ESP data path
(`-esp-port` moves it, `-no-esp` leaves it unbound and serves the TLS tunnel
only). Clients that take the SSL tunnel instead have their keying block discarded
at that moment, which is what the protocol requires.

Behind a DNAT, tell the gateway the address clients actually reach it on, since
that address is both what it advertises for ESP and what the activation pings are
sent to:

```sh
sudo ./veepin serve gp -public 198.51.100.7 ...
```

Without `-public` the gateway uses the local address of each client's own control
connection, which is right whenever there is no address translation in front of
it.

## A note on this protocol's security

GlobalProtect performs **no key exchange**. The gateway generates the ESP keys
and sends them to the client inside the getconfig response, protected only by the
HTTPS session that carries it. There is no forward secrecy: anyone who can read
that one response can read the tunnel it describes for the tunnel's whole life,
and a rekey means fetching a new document over the same channel.

That is Palo Alto's design and veepin implements it faithfully, but it is worth
knowing before choosing this protocol over IKEv2 or WireGuard, both of which this
tree also speaks. See [`doc/security.md`](../security.md).

## Downstream flow shaping

`-shape <bytes>` pads the first N bytes of each inner flow out to the tunnel MTU,
so the size pattern of a TLS handshake made *inside* the tunnel does not survive
encapsulation:

```sh
sudo ./veepin serve gp -shape 16384 ...
```

It works on both data paths and **the client needs no support for it**. On ESP the
filler is RFC 4303 §2.7 traffic-flow-confidentiality padding; on the SSL tunnel it
is trailing bytes after the inner packet, which every IP stack trims by the
packet's own header length. Either way the receiver recovers exactly the packet
that was sent, which is what the Docker interop run against
`openconnect --protocol=gp` demonstrates — its ping replies could not come back
from a mis-trimmed packet.

Because the fingerprint it defends against targets handshakes, the budget is spent
per flow rather than per byte and bulk throughput is unaffected. It is off by
default and shapes the server's downstream direction only. See
[`doc/traffic-shaping.md`](../traffic-shaping.md) for what it does and does not
hide.
