# Running Ivanti Connect Secure (Pulse / Juniper)

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Connecting as an Ivanti client

`veepin connect pulse` speaks the protocol a real Ivanti Connect Secure gateway
speaks, and the one `openconnect --protocol=pulse` speaks. Authentication is a
username and password, carried as EAP inside IF-T/TLS:

```sh
sudo ./veepin connect pulse -server vpn.example.com -user alice -pass hunter2

# Against a self-signed test gateway (skips certificate verification):
sudo ./veepin connect pulse -server 10.0.0.1 -user alice -pass hunter2 -insecure

# Stay on the IF-T/TLS connection even where the gateway hands out ESP keys:
sudo ./veepin connect pulse -server vpn.example.com -user alice -pass hunter2 -no-esp
```

The client takes the ESP data path wherever the gateway offers one and the
datagrams get through, and stays on the IF-T/TLS connection otherwise — the
usual reason being UDP 4500 blocked somewhere in the path. The log line says
which carrier ended up in use:

```
pulse: ESP path up on UDP 4500
pulse: tunnel up over ESP, assigned 10.70.0.2
pulse: ESP unavailable (pulse: the server did not answer on the ESP path), staying on the IF-T/TLS data path
```

Unlike GlobalProtect, the choice is not one-way: the TLS connection stays open
as the control channel whichever path carries data, so nothing is lost by trying
ESP first.

`-shape N` turns on outbound traffic shaping. On either carrier a stock gateway
needs no support for it: over ESP it is RFC 4303 §2.7 traffic-flow padding, and
over IF-T/TLS it is trailing filler the receiver trims by the inner IP header's
own length.

## Running an Ivanti gateway

`veepin serve pulse` is the gateway for the same protocol; a stock
`openconnect --protocol=pulse` connects to it unmodified. It needs a TLS
certificate and key, since authentication, configuration and the fallback data
path are all on the one HTTPS port:

```sh
sudo ./veepin serve pulse \
  -cert /etc/veepin/server.crt -key /etc/veepin/server.key \
  -user alice -pass hunter2 \
  -pool 10.70.0.0/24 -dns 1.1.1.1 -domain corp.example \
  -setup-nat -wan eth0
```

Each client authenticates, is assigned an address from the pool, and is pushed a
configuration packet carrying its address, netmask, DNS, MTU and routes. Unless
`-no-esp` is given, the gateway also binds UDP 4500 (`-esp-port` moves it) and
pushes a freshly generated ESP keying block; the client answers with its own,
and the two directions are keyed independently.

`-split-include` adds the networks clients should route into the tunnel:

```sh
sudo ./veepin serve pulse ... -split-include 10.0.0.0/8,192.168.0.0/16
```

Like every other protocol here, that list is reported to the caller rather than
applied for it: `client.Result` has no field for per-destination routes, so the
CLI installs the safe default and logs what the gateway would have preferred.

## A note on this protocol's security

The ESP keys are **pushed, not negotiated**. Each end mints its own SPI and keys
and sends them to the other inside the TLS session, so there is no key exchange
for the data path and no forward secrecy for it: anyone who can read the
configuration exchange can read the ESP traffic it describes for as long as
those keys are in use.

That is better than GlobalProtect, where the gateway chooses both directions'
keys, and worse than IKEv2, where neither end can choose them alone. It is
Ivanti's design and veepin implements it faithfully — but the TLS session that
protects the exchange is the whole of the data path's confidentiality, so the
gateway's certificate and its private key matter more here than the protocol's
own cryptography does. See [`doc/security.md`](../security.md).
