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

### A dual-stack tunnel

`-pool6` adds an IPv6 prefix, and every client is then pushed `ifconfig-ipv6`
beside `ifconfig`:

```sh
sudo ./veepin serve openvpn -ca ca.crt -cert server.crt -key server.key \
  -pool 10.8.0.0/24 -pool6 fd00:8::/64 -setup-nat -wan eth0
```

A client's v6 address is **derived** from its v4 one — the v4 address's offset
within `-pool`, added to the prefix's base, so `10.8.0.2` becomes `fd00:8::2`.
That is a deliberate departure from OpenVPN's own `--ifconfig-ipv6-pool`, and
the reason is lifecycle rather than taste: a second allocator is a second thing
to release, on a path that gets exactly one chance to run and has no peer to
confirm it with. Derivation is one-to-one with the v4 assignment by
construction, so releasing the v4 address releases both, and it makes the
mapping legible.

### When a client goes away

A UDP client never says goodbye; it stops answering. The server pushes
`ping 10,ping-restart 60` and holds itself to the same bound in the other
direction: a client whose last authenticated packet — data **or** keepalive —
is more than 60 seconds old is torn down, and its address, its tunnel and its
session are released. Reaping no sooner than the client's own `ping-restart`
is deliberate, so a peer that is still trying is never disconnected by the
server first.

Until this existed the server simply never released anything: an established
client that vanished kept its pool address for the life of the process, and a
server that had handed out its whole `-pool` stayed exhausted.

`-setup-nat` installs the server's own `fd00:8::1` on the interface along with
v6 forwarding and the `ip6tables` rules, the same way it does the v4 half.

A stock `openvpn --client` needs no configuration for any of this: `ifconfig-ipv6`
is a pushed option, so the client's v6 address comes entirely from the server.
The interop cell pings the *client's* derived address from the server, which is
the only direction that proves anything — see the note in
`tests/interop/interop_test.go`.

### Protecting the control channel

The server accepts the same `--tls-crypt` and `--tls-auth` static-key wrappings
the client offers, and the flags mirror the client's:

```sh
# tls-crypt: every control packet authenticated and encrypted.
sudo ./veepin serve openvpn -ca ca.crt -cert server.crt -key server.key \
  -tls-crypt ta.key -pool 10.8.0.0/24 -setup-nat -wan eth0

# tls-auth: an HMAC only. -key-direction is the *client's* value; the server
# takes the opposite slot pair automatically.
sudo ./veepin serve openvpn -ca ca.crt -cert server.crt -key server.key \
  -tls-auth ta.key -key-direction 1 -auth SHA256 -pool 10.8.0.0/24
```

Two reasons to use one. The wrapping is **not negotiated**, so a client
configured with `tls-crypt` cannot talk to a server without it — the two sides
have to agree. And it is what makes the server unanswerable to a stranger:
without it, a bare `P_CONTROL_HARD_RESET_CLIENT_V2` from any source is answered
with a server hard reset and then the whole certificate flight, which is the
active-probe stage of *OpenVPN is Open to VPN Fingerprinting*
([USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/xue-diwen)).
With a key configured, an opener that fails the HMAC is dropped before any
session state exists and nothing is sent back.

That closes the *active* half of that paper's method. The passive half — the
cleartext opcode byte and OpenVPN's distinctive ACK pattern and packet sizes —
is unaffected, because `tls-crypt` leaves the opcode, session ID, packet ID and
timestamp in the clear by design.

## Downstream flow shaping

`-shape <bytes>` pads the first N bytes of each inner flow out to the tunnel
MTU, so the size pattern of a TLS handshake made *inside* the tunnel does not
survive encapsulation:

```sh
sudo ./veepin serve openvpn -shape 16384 ...
```

The filler goes after the inner IP packet in the data-channel payload, which is
length-delimited; the receiver cuts back to the length the inner IP header
declares. On the AES-256-CBC channel it sits before the PKCS#7 trailer, so that
trailer stays valid. **The client needs no support for it** — it is verified in
Docker against a stock `openvpn`, whose ping replies could not come back from a
mis-trimmed packet.

`veepin connect openvpn -shape` covers the upstream direction when both ends are
veepin; a stock server accepts the padding but does not reciprocate.

This is a different defence from `-tls-crypt`: that one hides the tunnel's own
handshake from an active probe, this one hides the size pattern of what the
tunnel carries.

Because the fingerprint it defends against targets handshakes, the budget is
spent per flow rather than per byte and bulk throughput is unaffected. It is off
by default. See [`doc/traffic-shaping.md`](../traffic-shaping.md) for what it
does and does not hide.
