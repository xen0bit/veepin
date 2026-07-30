# The `veepin mgmt` CLI

`veepin mgmt` is the command-line client of the supervisor's management API.
It reads two environment variables:

- `VEEPIN_MGMT_URL` — base URL of the supervisor (default
  `http://127.0.0.1:8443`).
- `VEEPIN_MGMT_TOKEN` — the bearer token from `<config>/mgmt/token`. Required.

The token file is the same one the embedded panel uses for its fetches, so if
the supervisor generated one on first run, copy it from disk:

```sh
export VEEPIN_MGMT_TOKEN=$(sudo cat /etc/veepin/mgmt/token)
```

The subcommands map 1:1 to the API endpoints, so the CLI is the bottom of the
management stack rather than a parallel interface:

| subcommand                   | API                                        | action                                             |
|------------------------------|--------------------------------------------|----------------------------------------------------|
| `ls`                         | `GET /api/listeners`                       | list running listeners                             |
| `status <name>`              | `GET /api/listeners/<name>`                | status + redacted config                           |
| `protocols`                  | `GET /api/protocols`                       | list server protocols + their option schema       |
| `add` (config on stdin)      | `POST /api/listeners`                      | create a listener from a JSON file                 |
| `edit <name>` (config on stdin) | `PATCH /api/listeners/<name>`          | update fields, cold-rebuild                         |
| `restart <name>`             | `POST /api/listeners/<name>/restart`       | rebuild from the existing on-disk config           |
| `rm <name>`                  | `DELETE /api/listeners/<name>`             | stop listener + remove its file                    |

## Examples

List listeners:

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
{ "name": "site-b", "protocol": "ikev2", "state": "running", ... }
```

Restart one after editing its file:

```sh
$ veepin mgmt restart site-b
```

See the [supervisor usage](supervisor.md) for the file format and the lifecycle
of rebuild / disable / delete.