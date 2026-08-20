# internal/hostnet

The host-side setup a veepin server needs and deliberately does not do for
itself: the TUN address, the link up, IPv4 forwarding, and the NAT/FORWARD
iptables rules that let a tunnel subnet reach the WAN.

This is the behaviour behind `veepin serve -setup-nat`, extracted so that the
single-protocol command and the supervisor configure a host identically rather
than by two similar-looking code paths.

```
Apply(name, cfg):
    ip addr add <gateway>/<bits> dev <tun>     (tolerates "File exists")
    ip link set <tun> up
    sysctl -w net.ipv4.ip_forward=1            (advisory; see below)
    iptables -t nat -A POSTROUTING -s <net> -o <wan> -j MASQUERADE  ┐
    iptables       -A FORWARD      -i <tun>          -j ACCEPT      ├ tagged
    iptables       -A FORWARD      -o <tun>          -j ACCEPT      ┘
```

Every rule carries `-m comment --comment veepin:<name>`. `Teardown` removes by
that tag, so a rebuilt or deleted listener takes its host state with it instead
of leaving a MASQUERADE line behind on every restart. `Apply` is idempotent —
each rule is `iptables -C`'d before it is added — so re-running it on a rebuild
leaves the host exactly as it found it.

`name` is `serve` for the bare command and the listener name under the
supervisor, which keeps the two visually distinct in `iptables -L` output.

## Two conditions that are not failures

**No WAN** (`ErrNoWAN`). The interface is addressed, up, and forwarding, but
nothing leaves it. That must be reported — an operator must not be told a tunnel
reaches the internet when it does not — but it is not a reason to refuse to
serve, so it is a distinguishable error the supervisor logs and carries on from
rather than an opaque one that used to abort the whole fleet.

**A layer-2 config** (`Network == nil`, i.e. L2TPv3). No subnet means no address
to assign and no NAT to install; the operator owns bridging. The link still comes
up, because a pseudowire over a down interface carries nothing.

## Caveats

**`sysctl net.ipv4.ip_forward=1` failing is ignored.** Forwarding is host-wide,
so a previous veepin instance or another VPN daemon may have set it, and a
container may not permit writing it at all. Treating the failure as fatal would
make a shared host unable to start any listener once forwarding was already on.
The cost is that a genuinely unset, unsettable forwarding flag produces a
listener that hands out addresses and routes nothing, with no error.

~~**Nothing is IPv6.**~~ Closed. Both families are configured: the v6 gateway
goes on the interface, `net.ipv6.conf.all.forwarding` is set, and the same
MASQUERADE and FORWARD rules are installed through `ip6tables` under the same
comment tag. `Config.Gateway6`/`Network6` carry it, and a server opts in through
`client.DualStackServer` — one protocol of seventeen has a v6 pool, so widening
`client.Server` would make sixteen facades answer a question they have no answer
to.

This entry described a real gap with a real consequence: `ikev2`'s
`Server.Gateway6`/`Network6` were documented as being "for routing and NAT rules"
and had **no caller anywhere in the tree**, while config mode handed every client
a v6 address out of a pool that *defaults*. So the v6 gateway never reached the
interface — the server could not answer a ping to its own tunnel address — and
client v6 traffic arrived at a host that would not forward it. Dual-stack worked
inside the tunnel and stopped at its edge.

**The v6 half degrades rather than failing.** `ErrNoIPv6` reports that v4 is
configured and v6 is not, because the host has no usable `ip6tables` or has IPv6
disabled. It is non-fatal for a reason `ErrNoWAN` does not have: ikev2's v6 pool
is on by default, so treating a missing `ip6tables` as fatal would stop every
existing v4 deployment on a v6-less host from serving at all, over a capability
its operator never asked for. Both callers log it and carry on.

**Teardown cannot always name the interface.** It runs after the server is
closed, so it re-derives the TUN name from the config's `tun` option. A listener
that let the kernel pick its name leaves the two FORWARD rules behind; the
MASQUERADE rule, which is keyed on the subnet rather than the interface, is
removed correctly.

**It shells out.** `ip`, `iptables`, and `sysctl` must be on `PATH` and runnable.
There is no netlink path and no nftables path, so a host with only `nft` and the
compatibility shims absent gets errors it cannot act on. `Commander` exists so
tests assert the exact command sequence without touching the host.
