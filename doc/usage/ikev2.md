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

## Post-quantum key exchange (RFC 9370)

`-post-quantum` offers ML-KEM-768 as an *additional* key exchange alongside the
classical group, carried in an IKE_INTERMEDIATE exchange (RFC 9242) between
IKE_SA_INIT and IKE_AUTH:

```sh
veepin connect ikev2 -server vpn.example.com -psk secret \
    -id client.example.com -post-quantum
```

The result is hybrid: Curve25519 still runs and still contributes, so breaking
either primitive alone recovers nothing. A server that does not offer it is not
an error — the handshake proceeds classically, and the client logs that the
server declined.

The server needs no flag. It accepts the additional key exchange whenever a
client both proposes an ADDKE transform it supports and advertises
INTERMEDIATE_EXCHANGE_SUPPORTED.

Only ML-KEM-768 is implemented, and only as the first (ADDKE1) round. RFC 9370
permits up to seven, but one post-quantum KEM beside the classical group is the
whole point of a hybrid.

Interoperates with strongSwan 6.x configured with `ke1_mlkem768` in its
proposal — note that a strongSwan built before OpenSSL 3.5 knows the keyword but
has no implementation behind it and answers INVALID_SYNTAX. What this does and
does not protect is in [`doc/security.md`](../security.md).

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

## TCP encapsulation (RFC 8229, updated by RFC 9329)

Some networks pass TCP and drop UDP — captive hotel and airline Wi-Fi, corporate
guest networks, a few mobile carriers. IPsec is UDP, so on those networks it
simply does not come up. RFC 8229 answers that by putting IKE **and** ESP on one
TCP connection to port 4500, each message length-prefixed, with the six ASCII
octets `IKETCP` sent once by whoever opened the connection.

Server — additive, not a mode:

```sh
sudo ./veepin serve ikev2 -tcp -psk 'a-strong-preshared-key' -id vpn.example.com
```

The UDP sockets stay bound. Every existing client keeps working exactly as
before and a client reaching the server over TCP is answered over TCP, so this
is safe to turn on everywhere rather than something to switch between. The
banner says which are live:

```
ikev2: listening on 0.0.0.0 (IKE :500, NAT-T/ESP :4500, TCP :4500)
```

Client:

```sh
sudo ./veepin connect ikev2 -tcp -server vpn.example.com     -psk 'a-strong-preshared-key' -id roadwarrior
```

Three things change with `-tcp`, and each follows from the stream:

- **`-port` names the TCP port, and defaults to 4500.** RFC 8229 §3 has no
  port-500 phase and no NAT-T float — the exchange is on one port from the first
  octet — so the flag has nothing else to mean. On a network that permits only
  443 outbound, `-port 443` is the whole configuration change.
- **MOBIKE is not negotiated.** The TCP connection *is* the address binding. An
  address change breaks it, and the answer is to reconnect rather than to send
  `UPDATE_SA_ADDRESSES` over a socket that no longer exists.
- **There is no fallback to UDP.** `-tcp` means use TCP. The deployments this
  exists for are the ones where UDP does not work, so a client that quietly
  dropped back to UDP would report a tunnel that cannot carry anything.
  Choosing between them is the caller's job, not a hidden retry.

Everything else is unchanged: the same PSK/EAP/certificate authentication, the
same suites, the same shaping, the same rekey timers.

**Use it only where UDP does not work.** A datagram protocol on a reliable
ordered stream blocks head-of-line, the frame lengths still expose the packet
sizes, and the `IKETCP` prefix is trivially distinguishable from TLS. See
[`doc/security.md`](../security.md) for the full statement.

On a desktop it is a checkbox rather than a flag: the NetworkManager editor's
IKEv2 form carries *Tunnel over TCP (for networks that block UDP)*, which writes
the same `tcp` key the CLI's `-tcp` sets. That is deliberate — the networks this
exists for are hotel, airline and corporate-guest Wi-Fi, and the person on one is
in a GUI with no tunnel and no obvious reason why.

Interoperability is with **libreswan**, which is the only open-source
implementation of either role (strongSwan implements none of it):

```
conn vpn
    enable-tcp=yes          # or fallback: try UDP, then TCP
    tcp-remoteport=4500
```

Both directions are in the interop matrix, and each cell removes UDP rather than
merely not using it — the responder cell runs pluto with `--no-listen-udp`, the
initiator cell drops outbound UDP 500 and 4500 in iptables. A TCP cell against a
peer that also answers UDP passes either way and proves nothing.

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

## Downstream flow shaping

`-shape <bytes>` pads the first N bytes of each inner flow out to the tunnel
MTU, so the size pattern of a TLS handshake made *inside* the tunnel does not
survive encapsulation:

```sh
sudo ./veepin serve ikev2 -shape 16384
```

It uses RFC 4303 §2.7 traffic-flow-confidentiality padding, which a conforming
receiver ignores, so **stock OS clients need no support for it**. Because the
fingerprint it defends against targets handshakes, the budget is spent per flow
rather than per byte and bulk throughput is unaffected. It is off by default;
`veepin connect ikev2 -shape` covers the upstream direction when both
ends are veepin. See [`doc/traffic-shaping.md`](../traffic-shaping.md) for what
it does and does not hide.
