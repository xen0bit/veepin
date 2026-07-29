# L2TPv3 Ethernet pseudowire

L2TPv3 (RFC 3931) carrying Ethernet frames (RFC 4719): the only **layer-2**
tunnel in veepin. The interface is a TAP device carrying Ethernet frames, not a
TUN carrying IP packets, so it joins a bridged segment and takes its address
from DHCP or ARP *inside* the tunnel rather than from the handshake.

veepin speaks the **static** pseudowire — sessions and cookies configured at both
ends, exactly as `ip l2tp add tunnel` / `ip l2tp add session` configure them on
Linux. There is no control plane; SCCRQ/ICRQ negotiation is not implemented.

> **L2TPv3 provides no authentication and no encryption.** The cookie is a check
> value against mis-delivery and blind insertion, not a key. Anyone who can reach
> the UDP port and guess the session ID and cookie can inject frames into the
> bridged segment. Run it over something, or on a network you trust. See
> [doc/security.md](../security.md).

## Server

```sh
veepin serve l2tpv3 -listen 0.0.0.0 -port 1701 \
    -session-id 200 -peer-session-id 100 \
    -cookie 1122334455667788 -peer-cookie aabbccddaabbccdd \
    -sublayer -tun tap0
```

## Client

```sh
veepin connect l2tpv3 -gateway peer.example.com -port 1701 \
    -session-id 100 -peer-session-id 200 \
    -cookie aabbccddaabbccdd -peer-cookie 1122334455667788 \
    -sublayer -tun tap0
```

Neither end assigns an address. Bring the interface up and address it yourself,
or bridge it:

```sh
ip link set tap0 up
ip addr add 10.0.0.2/24 dev tap0      # or: ip link set tap0 master br0
```

## The cookie direction

This is the one thing that is easy to get backwards, and getting it backwards is
invisible until you talk to a real peer.

RFC 3931 makes the cookie a property of the **receiver**: each end picks the
value it wants to see on packets arriving for its own session and tells the
peer. The two directions therefore carry *different* cookies, and either may
carry none.

| Flag | Meaning |
|---|---|
| `-cookie` | what **we** chose; verified on every packet we receive |
| `-peer-cookie` | what the **peer** chose; written into every packet we send |

So the two ends mirror each other: this end's `-cookie` is the other end's
`-peer-cookie`. Swap them at both ends and a veepin-to-veepin tunnel still works
perfectly — both halves are wrong the same way — and only a real peer notices.

**Against the Linux kernel, note that `ip l2tp` names them from the sender's
point of view, which is the opposite convention.** veepin's `-cookie` must equal
the kernel's `cookie`, and veepin's `-peer-cookie` must equal its `peer_cookie`.

Cookies are 0, 4 or 8 octets — nothing else is representable, and the length is
not on the wire, so both ends simply have to agree.

## Interoperating with Linux

```sh
ip l2tp add tunnel tunnel_id 1 peer_tunnel_id 1 \
    encap udp local 192.0.2.1 remote 192.0.2.2 \
    udp_sport 1701 udp_dport 1701
ip l2tp add session name l2tpeth0 tunnel_id 1 \
    session_id 200 peer_session_id 100 \
    cookie aabbccddaabbccdd peer_cookie 1122334455667788
ip link set l2tpeth0 up
```

`-sublayer` controls the Default L2-Specific Sublayer. **The kernel emits it as
four zero octets even with sequencing off**, so a session configured with it at
one end and without it at the other mis-frames every packet by four octets —
with no error, just corrupted frames. Presence is a configuration property; it is
never inferred from the packet.

## Keepalives (the quiescent control connection)

By default the pseudowire is entirely static and silent, which means a dead peer
looks exactly like an idle one. Setting a Control Connection ID at both ends
brings up the RFC 3931 control connection and starts HELLO keepalives, so
failure is detected:

```sh
veepin connect l2tpv3 -gateway peer.example.com \
    -session-id 100 -peer-session-id 200 \
    -ccid 1100 -peer-ccid 2200 -keepalive 30 ...
```

Control Connection IDs are **separate from Session IDs** and mirror the same way
(`-ccid` is ours, `-peer-ccid` is theirs). Both must be non-zero; 0 is reserved.
Control messages share the data port — only the T bit distinguishes them.

Against `ql2tpd`, set `hello_timeout` in its TOML to enable the same mode, and
map `tid`/`ptid` to `-peer-ccid`/`-ccid` respectively.

veepin implements the **quiescent** control connection only: HELLO, ACK and
StopCCN. There is no SCCRQ/ICRQ negotiation, because no open-source
implementation has one to test against — see `internal/l2tpv3/README.md`.

## Options

| Flag | Meaning |
|---|---|
| `-gateway` | peer host or IP (client only, required) |
| `-listen` | local IP to bind (server only, default `0.0.0.0`) |
| `-port` | UDP port (default 1701) |
| `-session-id` | our Session ID — what the peer sends to (required, non-zero) |
| `-peer-session-id` | the peer's Session ID — what we send to (required, non-zero) |
| `-cookie` | hex cookie we chose, verified inbound (0, 4 or 8 octets) |
| `-peer-cookie` | hex cookie the peer chose, written outbound |
| `-sublayer` | carry the Default L2-Specific Sublayer |
| `-tun` | TAP interface name (empty = kernel picks) |
| `-shape` | per-flow shaping budget in bytes (0 = off) |
| `-ccid` | our Control Connection ID; with `-peer-ccid`, enables HELLO keepalives |
| `-peer-ccid` | the peer's Control Connection ID |
| `-keepalive` | HELLO interval in seconds (default 30) |

## MTU

1500 outer, less 20 (IPv4 underlay) or 40 (IPv6), less 8 UDP, less the L2TPv3
header (8 + cookie + 4 if a sublayer), less the 14-octet Ethernet header inside:

| Cookie | Sublayer | MTU |
|---|---|---|
| none | yes | 1446 |
| 8 octets | yes | 1438 |
| none | no | 1450 |

## Shaping

`-shape` pads **only IP-bearing frames** (EtherType 0x0800 and 0x86DD). Ethernet
has no length field of its own, so padding works here for the same reason it
works everywhere else in veepin — the receiver trims by the inner IP header's
Total Length, with nothing negotiated. A padded ARP frame would have nothing to
trim by, so ARP, STP and everything else non-IP goes out unshaped. That is a real
gap in the defence and it is stated rather than hidden.
