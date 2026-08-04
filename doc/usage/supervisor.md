# Running the supervisor

The supervisor mode runs a fleet of VPN server listeners in one process, with
each listener configured by a single JSON file under a config directory. It is
the management plane: the supervisor exposes a localhost management API and an
embedded HTML panel, and lets you start / stop / rebuild listeners without
restarting the daemon.

This is additive to the bare `veepin serve <protocol>` command (which still
verifies one protocol at a time and remains the surface the interop matrix
exercises). Supervisor mode is for the operator running more than one VPN
server on a single host.

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` /
`setcap` setup that every TUN-based protocol needs.

## Layout

The directory you pass to `-config` holds the listener files directly, and the
supervisor keeps its own state in a `mgmt/` subdirectory of it — so one
directory is the whole of the supervisor's on-disk state:

```
/etc/veepin/            <- the -config directory
  site-a.json           one JSON file per listener
  branch-office.json
  profiles/             client profiles the panel manages (from `-profiles`)
    home.json           one JSON file per profile
  mgmt/
    hostnet/            what hostnet.Apply installed per listener (for teardown)
    token               0600 bearer token for the API and panel (auto-generated)
```

Each listener file is `encoding/json` of:

```json
{
  "name": "site-a",
  "protocol": "wireguard",
  "options": {
    "private-key": "<base64>",
    "address": "10.10.0.1/24",
    "listen-port": "51820",
    "peer-public-key": "<base64>",
    "peer-allowed-ips": "10.10.0.2/32"
  },
  "setup_nat": true,
  "wan": "eth0",
  "enabled": true
}
```

`options` is the same map<string,string> the bare `veepin serve <protocol>`
flags produce. Each protocol's `Opt*` consts are the keys; the help text for
each is available at `GET /api/protocols` on the management API (see
[Running the management CLI](mgmt.md)).

**Every option value is a JSON string**, including the numeric ones — the map is
`map[string]string` and the protocol parses each value itself, exactly as it
parses the flag the value came from. `"listen-port": 51820` without the quotes
does not decode and the supervisor refuses the file.

`enabled` may be omitted; it defaults to `true`. A file that names a protocol
and its options describes a listener you want running.

`name` must match `[a-z0-9][a-z0-9-]{0,31}` -- it is used verbatim as the
`iptables --comment veepin:<name>` tag the supervisor's `setup_nat` path
installs, so an unsafe character in `name` would be an unsafe shell fragment
when teardown runs.

## Starting the supervisor

```sh
sudo mkdir -p /etc/veepin
sudo ./veepin serve -config /etc/veepin -listen 127.0.0.1:8443
```

On first start, the supervisor:

1. Reads `/etc/veepin/*.json`, building one `client.Server` per file.
2. For each listener with `setup_nat: true`, installs the host iptables /
   forwarding / interface configuration, tagged `veepin:<name>` so a rebuild
   or delete takes its rules with it.
3. Starts a localhost management API at `-listen`.
4. Generates a 32-byte hex bearer token at `/etc/veepin/mgmt/token` (mode
   `0600`) if one is not already present, and logs that fact exactly once.

The dashboard is at `http://127.0.0.1:8443/`. Status, the listeners list, and
restart / delete actions are there; new and existing listener forms are
server-rendered directly from each protocol's option metadata. Each row expands
to show the listener's redacted config and its connected peers (for a protocol
that reports them), and the page shows the fleet's recent activity from the
audit log. The *client config* button on a row generates a ready-to-dial client
profile for that listener (see [Generating a client config](mgmt.md#generating-a-client-config)).
Client connection profiles are a second entity type the panel
manages — see [Client profiles](mgmt.md#client-profiles) and the `-profiles`
flag below.

## Reaching the panel from anywhere but the host

The panel is unauthenticated by necessity — it is the thing that hands the
browser the token — so its boundary is the `Host` header. `mgmt.RequireHost`
answers 403 unless `Host` names loopback, `localhost`, or the exact `-listen`
address. That is what stops a page the operator visits from rebinding its own
hostname to `127.0.0.1`, becoming same-origin with the panel, and reading the
token out of the DOM.

Seeding the allow-list from `-listen` alone makes any non-loopback bind
unusable, because the Host a browser sends is a name and the bind is a literal:

```sh
veepin serve -config /etc/veepin -listen 0.0.0.0:8443
# Host: vpn.example:8443  -> 403.  Host: 0.0.0.0:8443 -> nobody sends that.
```

`-allow-host` is the escape hatch, repeatable:

```sh
veepin serve -config /etc/veepin -listen 0.0.0.0:8443 \
  -allow-host vpn.example.com -allow-host 203.0.113.4
```

Name the hosts operators will actually type — including the one a reverse proxy
forwards, or the one on the near side of an `ssh -L` tunnel. Loopback stays
allowed regardless. This does not make a routable bind *safe*: the transport is
still plaintext HTTP and the token still crosses the wire in the clear, so put
TLS in front of it. See [doc/security.md](../security.md).

## Profiles

`-profiles <dir>` points the panel's profile endpoints at a directory of client
connection profiles (default `<config>/profiles`). The profile form renders from
each protocol's client option metadata, exactly as the listener form does from
its server metadata; a profile saved there is dialable on the supervisor host
with `veepin connect <name>` (profiles under a per-user `~/.config/veepin`
remain CLI-managed and are not visible here — this surface is for the operator's
provisioning, not the end user's laptop).

## Reconfiguring a listener

To change a listener, edit its JSON file and `POST /api/listeners/<name>/restart`
(or click *restart* in the panel, or `veepin mgmt restart <name>`). The
supervisor cold-rebuilds that one listener -- Close the old server, build a new
one, ListenAndServe again -- leaving other listeners' goroutines untouched.
This honours the `client.Server` interface immutability contract: there are no
runtime mutation methods on a Server, so reconfiguration is rebuild by design.

## Disabling vs deleting

- `enabled: false` keeps the file on disk but the supervisor stops running the
  listener. The status page shows it as `disabled`, and the log says so at
  startup, so it is never confused with a listener that failed to start; a later
  patch flipping it back to `true` rebuilds it.
- `DELETE /api/listeners/<name>` (or `veepin mgmt rm <name>`) stops the server
  and removes its file AND its `veepin:<name>`-tagged iptables rules. Use it
  when the listener is gone for good.

## What the supervisor does *not* do

- It does not generate or rotate protocol keys. Key material arrives in the
  `options` map and is written to disk mode `0600`, root-only, the same posture
  PEM files and the IKEv2 EAP user file already rely on.
- It does not hot-add peers to a running WireGuard server by hand. WireGuard's
  peer set is fixed at `NewServer` time, so a peer change is a rebuild — which
  is exactly what client-config generation does for you: it appends the peer to
  the listener's `peers` option and cold-rebuilds, so a generated config works
  the moment it is downloaded. Hand-editing remains: edit the `peers` JSON (or
  the wg-quick `-config` file) and `POST .../restart`.
- It does not tear down interface addresses or `ip_forward=1` on shutdown --
  only its own tagged iptables rules. The TUN release itself is implicit via
  `Close` and `ip_forward=1` is host-wide and shared with other VPN daemons.
- See [security notes](security.md) for the threat model of binding the panel
  off localhost.