# Running IKEv2/ESP

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Running an IKEv2 server

Start the server (auto-configuring the tunnel interface and NAT):

```sh
sudo ./veepin serve ikev2 \
  -listen 0.0.0.0 \
  -public YOUR.PUBLIC.IP \
  -psk 'a-strong-preshared-key' \
  -id vpn.example.com \
  -pool 10.10.10.0/24 \
  -dns 1.1.1.1,8.8.8.8 \
  -setup-nat -wan eth0
```

`-setup-nat` runs the equivalent of:

```sh
ip addr add 10.10.10.1/24 dev tun0
ip link set tun0 up
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -o tun0 -j ACCEPT
```

If you omit `-setup-nat`, the server prints these commands so you can run them
yourself. UDP ports 500 and 4500 must be reachable from clients.

## Username/password authentication (EAP-MSCHAPv2)

To let clients log in with a username and password instead of the machine PSK,
create a credential file (one `username:password` per line; `#` comments and
blank lines allowed):

```
# /etc/ikev2/users
alice:wonderland
bob:hunter2
```

and pass it with `-eap-users`:

```sh
sudo ./veepin serve ikev2 \
  -public YOUR.PUBLIC.IP \
  -psk 'a-strong-preshared-key' \
  -id vpn.example.com \
  -eap-users /etc/ikev2/users \
  -setup-nat -wan eth0
```

The server still authenticates *itself* to clients with the PSK; each client
then authenticates with its username/password. This is the standard
"IKEv2 EAP-MSCHAPv2" setup that Windows, macOS/iOS, Android and strongSwan all
support out of the box. Note that MSCHAPv2 requires the server to hold
recoverable passwords (challenge/response cannot verify against a salted one-way
hash); protect the credential file accordingly.

## Connecting a client

`veepin connect ikev2` is the bundled client; see
[Using the bundled client](../../README.md#using-the-bundled-client) for the full
walk-through. On a Linux desktop, the
[NetworkManager plugin](../networkmanager-plugin.md) brings the tunnel up from the
native VPN UI — and it configures every veepin protocol, not just IKEv2.

## Connecting a stock OS client to the veepin server

The server authenticates with a machine PSK plus an identity, and assigns the
client an address — the standard "IKEv2 PSK" road-warrior setup that OS built-in
VPN clients speak natively.

**Linux (NetworkManager / strongSwan)** — with strongSwan `swanctl`:

```
connections {
  home {
    remote_addrs = YOUR.PUBLIC.IP
    version = 2
    proposals = aes256gcm16-prfsha256-curve25519
    local { auth = psk  id = client.example.com }
    remote { auth = psk  id = vpn.example.com }
    children { home { esp_proposals = aes256gcm16 } }
  }
}
secrets { ike-home { secret = "a-strong-preshared-key" } }
```

**Windows** — Settings → VPN → Add: type "IKEv2", pre-shared key, then in the
adapter properties set authentication to "Use preshared key".

**macOS / iOS** — Settings → VPN → Add IKEv2. Set Server and Remote ID to
`vpn.example.com`, choose "None" for user auth, and enter the PSK under the
machine authentication / shared-secret field.

**Android** — built-in "IKEv2/IPSec PSK": server address, IPSec identifier =
`vpn.example.com`, and the pre-shared key.

Match the client's `id`/PSK to the server's `-id`/`-psk`. By default the server
offers AES-GCM (256- and 128-bit) with Curve25519, ECP-256/384 and MODP-2048,
ordered so the fastest mutually supported options win — every current OS client
finds a match.

For **username/password** login, configure the OS client for "IKEv2 with
EAP / username & password" (rather than machine PSK): it still needs the server
PSK/identity for the machine authentication step, plus the per-user credentials.
On Windows and macOS/iOS this is the "Username and password" user-authentication
option on an IKEv2 profile; strongSwan uses `leftauth=psk` / `rightauth=eap-mschapv2`
with `eap_identity` and a password secret.

## Roaming (MOBIKE)

The server supports MOBIKE (RFC 4555), so a client that changes network — phone
leaving Wi-Fi for cellular, laptop switching APs — keeps its tunnel instead of
re-handshaking. It is negotiated automatically (a `MOBIKE_SUPPORTED` notify in
`IKE_AUTH`) and needs no configuration; native macOS/iOS and Windows IKEv2
clients and strongSwan (`mobike=yes`, their default) all use it. When the client
moves, it sends a protected `UPDATE_SA_ADDRESSES` from its new address and the
server relocates the SA — including the ESP return path — to the address it
actually observes, after echoing the client's `COOKIE2` return-routability
probe. The veepin client initiates the same move through `Client.Roam` when its
local address changes.

## IKE fragmentation (RFC 7383)

When both ends advertise `IKE_FRAGMENTATION_SUPPORTED` in `IKE_SA_INIT` (veepin
does automatically, as do strongSwan and the native OS clients), a peer may send
a large protected message — a certificate-bearing `IKE_AUTH`, or a peer
configured to always fragment (`fragmentation=force`) — split into several
`SKF` fragments instead of relying on IP fragmentation, which some middleboxes
drop. veepin reassembles those fragments; it never fragments its own output, as
its PSK/EAP messages are always small. This needs no configuration and lets
veepin interoperate with a peer set to force fragmentation.

## Smoke-testing without an OS client

`veepin probe` is a minimal built-in initiator for verifying a running server end
to end (handshake, address assignment, one ESP packet). It needs no TUN device
and no privileges:

```sh
# PSK auth:
./veepin probe ikev2 -server 127.0.0.1:500 -esp 127.0.0.1:4500 \
    -psk 'a-strong-preshared-key' -id roadwarrior

# EAP username/password auth:
./veepin probe ikev2 -server 127.0.0.1:500 -esp 127.0.0.1:4500 \
    -psk 'a-strong-preshared-key' -id alice -user alice -pass wonderland
```

It prints the internal address it was assigned and confirms the ESP data path.
