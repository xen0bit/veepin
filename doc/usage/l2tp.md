# Running L2TP/IPsec

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Connecting as an L2TP/IPsec client

`veepin connect l2tp` runs the whole stack in userspace: IKEv1 Main Mode with the
pre-shared key, Quick Mode for the ESP transport SA, then L2TP and PPP inside it.
The address, netmask and DNS all come from IPCP, so only credentials are
configured:

```sh
sudo ./veepin connect l2tp \
  -server vpn.example.com -psk secret -user alice -pass hunter2
```

## Running an L2TP/IPsec server

`veepin serve l2tp` is the responder for the same stack. One UDP socket serves
every client, demultiplexed by source address into a per-peer IKEv1 responder,
ESP SA, L2TP tunnel and PPP session; a shared TUN is routed by inner destination
address.

```sh
sudo ./veepin serve l2tp \
  -psk secret -user alice -pass hunter2 \
  -pool 10.20.0.0/24 -dns 1.1.1.1 -setup-nat -wan eth0
```

Both sides speak NAT traversal (RFC 3947/3948): Main Mode starts on UDP/500 and
floats to UDP/4500, where IKE rides behind the non-ESP marker alongside
UDP-encapsulated ESP. veepin always forces that float — it advertises itself as
being behind a NAT, exactly as strongSwan's `encap = yes` does — because its data
path is a userspace UDP socket with no raw-ESP fallback. A peer that never
advertises NAT-T is therefore rejected during Main Mode rather than left to fail
silently later. Both directions are verified in Docker against strongSwan +
xl2tpd.

## Downstream flow shaping

`-shape <bytes>` pads the first N bytes of each inner flow out to the tunnel
MTU, so the size pattern of a TLS handshake made *inside* the tunnel does not
survive encapsulation:

```sh
sudo ./veepin serve l2tp -shape 16384 ...
```

L2TP/IPsec nests PPP inside L2TP inside ESP, and the filler goes in the
innermost of those — the PPP Information field, which RFC 1661 §5.1 explicitly
allows to be padded up to the MRU and leaves the carried protocol to delimit (IP
does that with Total Length). Padding there rather than with ESP's own TFC
padding is what keeps the shaper reading the inner 5-tuple. **The client needs
no support for it**; it is verified in Docker against strongSwan + xl2tpd +
pppd, whose ping replies could not come back from a mis-trimmed packet.

Because the fingerprint it defends against targets handshakes, the budget is
spent per flow rather than per byte and bulk throughput is unaffected. It is off
by default. See [`doc/traffic-shaping.md`](../traffic-shaping.md) for what it
does and does not hide.
