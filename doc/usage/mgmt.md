# The `veepin mgmt` CLI

`veepin mgmt` is the command-line client of the supervisor's management API.
It reads two environment variables:

- `VEEPIN_MGMT_URL` — base URL of the supervisor (default
  `http://127.0.0.1:8443`).
- `VEEPIN_MGMT_TOKEN` — the bearer token from `<config>/mgmt/token`.

The token does not have to be exported: when `VEEPIN_MGMT_TOKEN` is unset, the
CLI reads `/etc/veepin/mgmt/token` (or the path in `VEEPIN_MGMT_TOKEN_FILE`)
directly — so `sudo veepin mgmt ls` works with no setup. The token file is the
same one the embedded panel uses for its fetches, so if the supervisor generated
one on first run, copy it from disk only when the CLI runs as a non-root user:

```sh
export VEEPIN_MGMT_TOKEN=$(sudo cat /etc/veepin/mgmt/token)
```

Every subcommand takes `-json` to emit compact, single-line JSON for scripting
(`ls` also takes `-q` for names only). The subcommands map 1:1 to the API
endpoints, so the CLI is the bottom of the management stack rather than a
parallel interface:

| subcommand                   | API                                        | action                                             |
|------------------------------|--------------------------------------------|----------------------------------------------------|
| `ls`                         | `GET /api/listeners`                       | list running listeners                             |
| `status <name>`              | `GET /api/listeners/<name>`                | status + redacted config                           |
| `protocols`                  | `GET /api/protocols`                       | list server + client protocols and their schemas  |
| `add` (config on stdin)      | `POST /api/listeners`                      | create a listener from a JSON file                 |
| `edit <name>` (config on stdin) | `PATCH /api/listeners/<name>`          | update fields, cold-rebuild                         |
| `restart <name>`             | `POST /api/listeners/<name>/restart`       | rebuild from the existing on-disk config           |
| `rm <name>`                  | `DELETE /api/listeners/<name>`             | stop listener + remove its file                    |
| `audit`                      | `GET /api/audit`                           | recent management-plane activity, newest first     |
| `client-config <name>`       | `POST /api/listeners/<name>/client-config` | generate a client profile for a listener           |

## Examples

List listeners, names only, for a script:

```sh
$ veepin mgmt ls -q
site-a
```

List with status:

```sh
$ veepin mgmt ls
{
  "listeners": [
    { "name": "site-a", "protocol": "wireguard", "state": "running",
      "tun": "tun0", "gateway": "10.10.0.1", "network": "10.10.0.0/24" }
  ]
}
```

Add a listener from a JSON file:

```sh
$ sudo cat > /tmp/site-b.json << 'EOF'
{
  "name": "site-b",
  "protocol": "ikev2",
  "options": { "psk": "secret", "id": "vpn.example.com", "pool": "10.20.0.0/24" },
  "enabled": true
}
EOF
$ veepin mgmt add < /tmp/site-b.json
{
  "status": { "name": "site-b", "protocol": "ikev2", "state": "running", ... },
  "generated": { "psk": "3f2a…" }
}
```

Note the envelope: `POST /api/listeners` wraps the listener status under
`status` so it can return `generated` alongside it. A script reading the state
wants `.status.state`, not `.state`.

A create that auto-generates key material (an empty PSK, a WireGuard keypair)
surfaces the parts the operator must act on — the WireGuard server's public key
— once, in the create response as `generated`. It is shown once and never
again: the config file stores it, but every later read of that listener redacts
the private half and the panel's form does not render the public one.

Restart one after editing its file:

```sh
$ veepin mgmt restart site-b
```

See the [supervisor usage](supervisor.md) for the file format and the lifecycle
of rebuild / disable / delete.

## Generating a client config

`veepin mgmt client-config <name>` produces a ready-to-use client connection
profile for a listener — the same JSON `veepin connect <name>` dials — with the
secrets filled in from the listener's own config (never the redacted API
values):

```sh
$ veepin mgmt client-config site-a -endpoint vpn.example.com -o ./site-a-client
wrote ./site-a-client/profile.json (and any companion files)

$ VEEPIN_PROFILE_DIR=./site-a-client veepin connect site-a   # or: veepin profile add < ./site-a-client/profile.json
```

What the operator must supply is the **endpoint** — the address clients dial —
because the supervisor cannot know its own public hostname. Everything else
derives from the listener: the PSK/password, the server identity, and any
file-path credentials (CA, server cert) are bundled as companion files next to
`profile.json` with the profile's paths rewritten to their names. `-set k=v`
overrides any client option.

**WireGuard and AmneziaWG** are the one case that provisions rather than
assembles: generation mints a fresh client keypair, allocates the next free
address from the server's subnet, appends the peer to the listener, and
cold-rebuilds it — so the generated config connects as soon as it is downloaded.
Each generation allocates a new address; the listener's `peers` option is the
source of truth for what is taken. A listener whose address pool is exhausted
fails loudly rather than reusing an address.

The panel's *client config* button on a listener row is the same call, with the
endpoint prompted in the browser and the profile offered as a downloadable file.

Caveats: a generated config snapshots the listener's secrets, so rotating the
PSK invalidates every config generated before it; re-generate to refresh.
OpenVPN configs carry the CA (and any tls-auth/tls-crypt) but the client
certificate/key remain an operator override — signing client certs from the
listener's CA is not built yet.

## Client profiles

Profiles are the client side of the same shape: named connection configurations
the `veepin connect <name>` command dials. Manage them with `veepin profile`:

```sh
$ veepin profile add home ikev2 -server vpn.example.com -psk secret -id client.example.com
saved "home" (protocol ikev2)

$ veepin profile ls
home                      ikev2

$ veepin profile show home          # secrets redacted; -secrets prints them
$ veepin connect home -set gateway=other.example.com   # one-off override
$ veepin profile rm home
```

The flag form takes exactly what `veepin connect <protocol>` takes; the older
`veepin profile add < a-profile.json` (stdin) still works. The supervisor's
panel manages a *server-side* profile set (`serve -config ... -profiles <dir>`,
default `<config>/profiles`) for provisioning; per-user profiles under
`~/.config/veepin/profiles/` stay on the machine that dials.
