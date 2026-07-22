# Running SSH

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Connecting as an SSH client

`veepin connect ssh` forwards IP over an SSH tunnel channel — the equivalent of
`ssh -w`, but with the data path in Go. It needs a server with `PermitTunnel yes`
and a statically chosen tunnel address (SSH assigns none):

```sh
# Against a stock sshd (which binds a pre-created tun device — request its unit):
sudo ./veepin connect ssh \
  -server vpn.example.com -user alice -identity ~/.ssh/id_ed25519 \
  -known-hosts ~/.ssh/known_hosts \
  -address 10.200.0.2/30 -peer 10.200.0.1 -peer-unit 0

# Against the veepin SSH server (it assigns the unit itself; -insecure skips
# host-key verification for a throwaway/self-signed host key):
sudo ./veepin connect ssh -server 10.0.0.1 -user alice \
  -identity ~/.ssh/id_ed25519 -insecure -address 10.200.0.2/30 -peer 10.200.0.1
```

## Running an SSH server

`veepin serve ssh` is an SSH server scoped to tunnel forwarding: it accepts
`tun@openssh.com` channels (rejecting shells and other channel types),
authenticates with an `authorized_keys` file or a username/password, and routes a
shared TUN to each client by the inner address it uses.

```sh
sudo ./veepin serve ssh \
  -host-key /etc/ssh/ssh_host_ed25519_key \
  -authorized-keys ~/.ssh/authorized_keys \
  -pool 10.200.0.0/24 -setup-nat -wan eth0
```

A stock `ssh -w 0:0 -N user@host` also connects to it. Clients pick addresses
within `-pool` (statically); the server accepts and routes any in-range address.
It is verified in Docker against both `ssh -w` and the veepin client.
