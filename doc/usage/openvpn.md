# Running OpenVPN

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Connecting as an OpenVPN client

`veepin connect openvpn` dials an OpenVPN server as a UDP client. It takes a
standard `.ovpn` profile, individual flags, or both:

```sh
# From an .ovpn profile (remote, ca/cert/key, cipher, tls-auth/tls-crypt — inline
# blocks or paths):
sudo ./veepin connect openvpn -config /etc/openvpn/client.ovpn

# Or from flags with PEM files:
sudo ./veepin connect openvpn \
  -remote vpn.example.com -port 1194 \
  -ca ca.crt -cert client.crt -key client.key

# A server that wraps the control channel with tls-crypt, or tls-auth:
sudo ./veepin connect openvpn -config client.ovpn -tls-crypt ta.key
sudo ./veepin connect openvpn -config client.ovpn -tls-auth ta.key -key-direction 1 -auth SHA256

# An older server whose data channel is AES-256-CBC rather than AES-GCM:
sudo ./veepin connect openvpn -config client.ovpn -cipher AES-256-CBC -auth SHA256
```

The client runs mutual-TLS with the server (verifying the server certificate
chains to the CA), negotiates the data cipher (AES-256-GCM or AES-256-CBC),
optionally protects the control channel with `--tls-auth` or `--tls-crypt`, pulls
its address and routes from the server's `PUSH_REPLY`, and applies them the same
way the other protocols do (`-full-tunnel`/`-no-route` behave identically). All
four control/data combinations are covered by the Docker interop tests; see the
boundaries under [What it does](../../README.md#what-it-does). Add
`-username`/`-password` for servers that require `auth-user-pass`.

## Running an OpenVPN server

`veepin serve openvpn` is the responder: mutual-TLS against a CA, key method 2,
and subnet-topology `PUSH_REPLY` address assignment from a pool. It serves the
certificate-authenticated AES-256-GCM profile that a stock `openvpn --client`
speaks:

```sh
sudo ./veepin serve openvpn \
  -ca ca.crt -cert server.crt -key server.key \
  -pool 10.8.0.0/24 -dns 1.1.1.1 -setup-nat -wan eth0
```

`-setup-nat` assigns the pool gateway (`10.8.0.1`) to the TUN and installs the
masquerade rule for `-wan`; without it, the command prints the `ip`/`iptables`
lines to run by hand. Each client is assigned the next free pool address and a
peer-id, and inbound data packets are demuxed by that peer-id. It is verified in
Docker against both a real `openvpn` client and the veepin client.
