# Running Cisco IPsec (IKEv1 Aggressive Mode + XAuth + Mode-Config)

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs. This protocol additionally binds
UDP **500** and **4500**, which are privileged ports.

## Connecting as a Cisco IPsec client

`veepin connect cisco` speaks the exchange every "Cisco IPSec" client speaks — a
group key, then a user password:

```sh
sudo ./veepin connect cisco \
  -server vpn.example.com \
  -group engineering -group-psk 'the-group-secret' \
  -user alice -pass hunter2
```

There are two credentials because the protocol has two phases of authentication.
The **group** name and its pre-shared key authenticate phase 1 and are shared by
everyone in the group; the **user** name and password travel afterwards, inside
phase-1 encryption, through XAuth. A wrong group key and a wrong password fail at
different points and are reported differently:

```
cisco: IKE: cisco: authentication failed: ikev1: authentication failed: HASH_R verification failed (bad group password?)
cisco: IKE: cisco: authentication failed: ikev1: authentication failed: XAuth rejected the password
```

Once XAuth passes, the client pulls its address with Mode-Config and the gateway
answers with the address, netmask, DNS servers and — where the gateway sends
them — the Cisco Unity attributes: a login banner, a default search domain, and
the networks it would prefer you routed into the tunnel. The banner and the
suggested routes are logged:

```
cisco: gateway banner: Authorised users only
cisco: gateway suggests routing 10.0.0.0/8 into the tunnel
cisco: tunnel up, assigned 10.60.0.2
```

The suggestion is logged rather than applied: `client.Result` has no field for
per-destination routes, so the CLI installs the safe default (everything through
the tunnel) and a caller that wants split tunnelling installs the list itself.

`-shape N` turns on outbound traffic shaping, which pads each inner flow's first
N bytes towards the tunnel MTU using RFC 4303 §2.7 traffic-flow-confidentiality
padding. The gateway needs no support for it.

## Running a Cisco IPsec gateway

`veepin serve cisco` is the gateway for the same protocol. A stock strongSwan
client with `aggressive=yes`, `rightauth=psk`, `rightauth2=xauth` and
`leftsourceip=%config` connects to it unmodified:

```sh
sudo ./veepin serve cisco \
  -group engineering -group-psk 'the-group-secret' \
  -user alice -pass hunter2 \
  -pool 10.60.0.0/24 -dns 1.1.1.1 \
  -banner 'Authorised users only' -domain corp.example \
  -setup-nat -wan eth0
```

Each client presents the group name as its phase-1 identity, authenticates
through XAuth, and is assigned an address from the pool. `-split-include` adds
the Unity attribute telling clients which networks to route into the tunnel:

```sh
sudo ./veepin serve cisco ... -split-include 10.0.0.0/8,192.168.0.0/16
```

Behind a DNAT, tell the gateway the address clients actually reach it on: it is
hashed into the NAT-D payloads, and a gateway that cannot name its own address
will disagree with what the client observed.

```sh
sudo ./veepin serve cisco -public 198.51.100.7 ...
```

The NAT-T port is fixed at 4500 by RFC 3948 and is not configurable on either
side; `-port` moves only the phase-1 port, and a client looking for the float has
nowhere to be told otherwise.

`-shape N` shapes downstream traffic the same way the client flag shapes
outbound. Stock clients benefit unmodified: the padding is ordinary RFC 4303
traffic-flow confidentiality, which any conforming ESP receiver discards by
reading the inner IP header's own length.

## Interoperating with strongSwan

strongSwan refuses Aggressive Mode with a pre-shared key unless it is told to
allow it, which is a deliberate speed bump rather than a bug:

```
# /etc/strongswan.d/charon.conf
charon {
    i_dont_care_about_security_and_use_aggressive_mode_psk = yes
}
```

A client connection against a veepin gateway looks like:

```
conn veepin
    keyexchange=ikev1
    aggressive=yes
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
    left=%any
    leftid=keyid:engineering
    leftauth=psk
    leftauth2=xauth
    leftsourceip=%config
    xauth_identity=alice
    right=198.51.100.7
    rightid=%any
    rightauth=psk
    rightsubnet=0.0.0.0/0
    auto=add
```

with the group key in `ipsec.secrets` as
`%any : PSK "the-group-secret"` and the XAuth password as
`alice : XAUTH "hunter2"`.

## A note on this protocol's security

Aggressive Mode is **not identity-protecting**. Message 1 carries the group name
in the clear, and message 2 carries a hash that a passive observer can attack
offline against a weak group key. Every deployment of this protocol has that
property — it is what strongSwan makes you write
`i_dont_care_about_security_and_use_aggressive_mode_psk` to enable — so the group
key must be a high-entropy secret rather than a memorable one.

XAuth is a password over an authenticated channel and nothing more: it is not
exposed to a passive observer, but anyone holding the group key can stand a
gateway up and collect user passwords.

veepin implements this faithfully because it is what the deployed clients speak,
but IKEv2 and WireGuard — which this tree also speaks — have neither weakness.
See [`doc/security.md`](../security.md).
