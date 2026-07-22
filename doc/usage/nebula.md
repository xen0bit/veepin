# Running Nebula

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Joining a Nebula mesh

Nebula has no client and no server, so both roles run the same command. A host
needs three files — the CA bundle it trusts, its own certificate, and the key
that certificate is bound to — all issued by `nebula-cert`:

```sh
nebula-cert ca   -name "example-mesh"
nebula-cert sign -name laptop -ip 10.42.0.7/24
```

The host's overlay address comes from its certificate, not from a flag or a
server, so there is nothing to assign:

```sh
sudo ./veepin connect nebula \
  -ca /etc/nebula/ca.crt -cert /etc/nebula/laptop.crt -key /etc/nebula/laptop.key \
  -static-hosts "10.42.0.1=lighthouse.example.com:4242" \
  -lighthouses 10.42.0.1 \
  -full-tunnel=false
```

Only the lighthouse needs a static entry: every other host is discovered through
it. `-full-tunnel=false` is the usual choice, since a mesh carries the overlay
prefix rather than a default route.

## Running a Nebula lighthouse

`veepin serve nebula` runs the directory the mesh finds itself through. It is an
ordinary member with an ordinary certificate — it just also answers questions
about where other members are, and helps two NATed hosts punch towards each
other. It needs a stable, directly reachable address:

```sh
sudo ./veepin serve nebula \
  -ca /etc/nebula/ca.crt -cert /etc/nebula/lighthouse.crt -key /etc/nebula/lighthouse.key \
  -listen 0.0.0.0:4242
```

There is no address pool and no user list: a host's address and identity are
whatever its certificate says, so the CA is the only thing that grants access.
Revocation is by certificate expiry — veepin does not implement blocklists.
