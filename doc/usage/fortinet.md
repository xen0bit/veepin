# Running Fortinet (FortiOS SSL VPN)

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Connecting as a Fortinet client

`veepin connect fortinet` speaks the FortiOS SSL VPN to a real FortiGate or to
the veepin server. Authentication is a username and password (the SVPNCOOKIE the
server issues carries the session; there is no PPP-level login):

```sh
sudo ./veepin connect fortinet -server vpn.example.com -user alice -pass hunter2

# Against a self-signed test gateway (skips certificate verification):
sudo ./veepin connect fortinet -server 10.0.0.1 -user alice -pass hunter2 -insecure

# Stay on the TLS tunnel even where the gateway offers the DTLS data channel:
sudo ./veepin connect fortinet -server vpn.example.com -user alice -pass hunter2 -no-dtls

# Against a gateway that wants a second factor: -token is one code, good once;
# -totp is the shared secret, so codes are generated as often as asked.
sudo ./veepin connect fortinet -server vpn.example.com -user alice -pass hunter2 -token 123456
sudo ./veepin connect fortinet -server vpn.example.com -user alice -pass hunter2 -totp JBSWY3DPEHPK3PXP
```

## Running a Fortinet server

`veepin serve fortinet` is the gateway for the same protocol; a stock
`openconnect --protocol=fortinet` connects to it unmodified. It needs a TLS
certificate and key, since the control plane and tunnel are HTTPS:

```sh
sudo ./veepin serve fortinet \
  -cert /etc/veepin/server.crt -key /etc/veepin/server.key \
  -user alice -pass hunter2 \
  -pool 10.40.0.0/24 -dns 1.1.1.1 -setup-nat -wan eth0
```

`-totp <base32-secret>` makes the server demand a second factor from that user:
the password earns a challenge rather than a cookie, and only the right one-time
code completes the login.

Each client authenticates, is assigned an address from the pool over IPCP, and
its packets are relayed over PPP. The server binds the same port number on UDP
for the DTLS data channel and advertises it; the certificate must carry an ECDSA
key for that (an RSA gateway serves the TLS tunnel only). `-no-dtls` leaves the
UDP port unbound.
