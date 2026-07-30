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

**Nothing is IPv6.** No `ip6tables`, no IPv6 MASQUERADE, no forwarding sysctl for
it. A protocol that assigns IPv6 inside the tunnel gets no host-side NAT from
this package.

**Teardown cannot always name the interface.** It runs after the server is
closed, so it re-derives the TUN name from the config's `tun` option. A listener
that let the kernel pick its name leaves the two FORWARD rules behind; the
MASQUERADE rule, which is keyed on the subnet rather than the interface, is
removed correctly.

**It shells out.** `ip`, `iptables`, and `sysctl` must be on `PATH` and runnable.
There is no netlink path and no nftables path, so a host with only `nft` and the
compatibility shims absent gets errors it cannot act on. `Commander` exists so
tests assert the exact command sequence without touching the host.
