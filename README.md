# veepin

A **working userspace VPN in Go** — both a server (responder) and a client
(initiator) — written from scratch, with `golang.org/x/crypto` the only
dependency. It speaks five protocols, **client and server for every one**:
**IKEv2/ESP**, **WireGuard**, **OpenVPN**, **SSTP**, and **SSH**.
The SSTP side runs Microsoft's Secure Socket Tunneling Protocol over TLS — the
`SSTP_DUPLEX_POST` HTTP handshake, the CALL_CONNECT crypto binding, MS-CHAPv2
authentication and a PPP/IPCP data path — as both client and server, verified
against SoftEther and the sstp-client `sstpc`/pppd reference. The IKEv2 side
performs the full key exchange with pre-shared-key or EAP-MSCHAPv2
authentication, NAT traversal, and configuration mode (address assignment), then
runs an ESP-in-UDP data path over a TUN device — so a standards-compliant OS VPN
client can connect to the server, and the bundled client can connect to it (or
any RFC 7296 responder). The WireGuard side performs the Noise_IKpsk2 handshake
and transport data path as both initiator and responder, and interoperates with
a real `wg` peer. The OpenVPN side is a UDP client that speaks the TLS control
channel — plain, tls-auth, or tls-crypt — and an AES-256-GCM or AES-256-CBC data
channel, and interoperates with a stock `openvpn` server.

Every layer is covered by tests, including full VPN integration tests:
`TestFullVPNFlow` drives a client through the handshake and verifies a real IP
packet traverses the ESP data path onto the server's TUN, and `TestClientConnectPSK`
drives the production client against the live server and checks bidirectional ESP.

## What it does

- **IKEv2 handshake** (RFC 7296): `IKE_SA_INIT`, `IKE_AUTH`, `CREATE_CHILD_SA`,
  `INFORMATIONAL`.
- **PSK authentication** in both directions (`AUTH` method 2, RFC 7296 §2.15).
- **EAP-MSCHAPv2 username/password auth** (RFC 7296 §2.16, RFC 2759, RFC 3079):
  the server authenticates itself with PSK, clients authenticate with a
  username/password from a credential file, and the final AUTH is keyed by the
  EAP-derived MSK.
- **NAT traversal** (RFC 3947/7296 §2.23): `NAT_DETECTION_*` payloads, floating
  to UDP 4500, ESP-in-UDP encapsulation, the non-ESP marker demux.
- **Configuration mode / CP** (RFC 7296 §3.15): hands each client an internal
  address, netmask and DNS from a pool via `CFG_REQUEST`/`CFG_REPLY`.
- **Userspace data path**: a TUN device plus an ESP engine (RFC 4303) with a
  64-packet anti-replay window; packets are demuxed by SPI and routed by the
  client's assigned address.
- **WireGuard client and server**: the Noise_IKpsk2 handshake (both initiator and
  responder), the ChaCha20-Poly1305 transport data path with a counter nonce and
  an RFC 6479 sliding-window anti-replay filter, cryptokey routing by AllowedIPs
  in both directions, multi-peer servers, roaming, replay-checked handshake
  timestamps, persistent keepalives, and client-initiated rekeying that keeps a
  tunnel up indefinitely by rotating a fresh keypair in before the current one
  reaches its ~180 s rejection age. It reads a wg-quick config file (with
  per-field flag overrides) and is verified against the reference `wireguard-go`
  in Docker, both ways. Rekey is client-initiated only (the server answers new
  initiations but starts none of its own), and neither role answers cookie
  replies under load — both fail loudly rather than silently.
- **OpenVPN client**: the full UDP client path — the hard-reset and reliable
  control channel (packet IDs, ACKs, retransmission, in-order delivery), the TLS
  control channel with mutual certificate authentication, the key method 2
  exchange and TLS 1.0 PRF key derivation, cipher negotiation, the
  `PUSH_REQUEST`/`PUSH_REPLY` config pull, and the `P_DATA_V2` data channel with
  a sliding-window anti-replay filter and keepalive pings. The control channel
  can be plain, `--tls-auth` (an HMAC over every control packet) or `--tls-crypt`
  (authenticated encryption of every control packet), and the data channel is
  AES-256-GCM or the older AES-256-CBC (encrypt-then-MAC with an `--auth` HMAC).
  It reads the common `.ovpn` profile (or flags) and is verified against a stock
  `openvpn` server in Docker across all four control/data combinations.
  Compression and the older net30 topology are not implemented, and a profile it
  cannot speak fails at dial rather than silently.
- **OpenVPN server**: the responder side of the same profile — one UDP socket
  serving many clients, the server-role TLS control channel with
  `RequireAndVerifyClientCert` against the CA, the key method 2 server exchange,
  subnet-topology `PUSH_REPLY` address assignment from a pool with server-assigned
  peer-ids, and the AES-256-GCM data path demuxed by peer-id. It is verified in
  Docker both against a real `openvpn` client and against the veepin client
  itself. TLS is capped at 1.2 (OpenVPN's control channel does not carry TLS 1.3
  post-handshake tickets cleanly), and it serves the certificate-authenticated
  GCM profile; `--tls-auth`/`--tls-crypt` and the CBC data channel are
  client-only for now.
- **SSH client and server**: IP forwarding over OpenSSH's layer-3 tunnel channel
  (`tun@openssh.com`, what `ssh -w` opens under a server's `PermitTunnel`), built
  on `golang.org/x/crypto/ssh` — already the module's only dependency, so this
  protocol adds none. The client opens the channel and forwards IP over a
  userspace TUN; the server accepts tunnel channels, learns each client's inner
  address from its traffic, and routes a shared TUN by it. Both roles are verified
  in Docker against stock OpenSSH — the veepin client against `sshd`
  (`PermitTunnel yes`), the veepin server against `ssh -w` — and against each
  other. SSH forwarding carries no addressing in-band, so tunnel addresses are
  static (from config, as the reference sshvpn script sets them); only layer-3
  (point-to-point) tunnels are implemented, not layer-2/TAP.

## Cryptography

| Category | Supported |
|----------|-----------|
| DH groups | Curve25519 (31), ECP-256/384/521 (19/20/21), MODP-2048 (14) |
| PRF | HMAC-SHA1, HMAC-SHA2-256/384/512 |
| IKE/ESP ciphers | AES-GCM-16 (AEAD, RFC 5282), AES-CBC + HMAC-SHA2 (encrypt-then-MAC) |
| Integrity | HMAC-SHA1-96, HMAC-SHA2-256-128/384-192/512-256 |

All from the standard library. (ChaCha20-Poly1305's transform ID is defined but
not yet wired in for IKEv2. The cipher itself now lives in `cryptoutil` — see
below — so wiring it is one case in `internal/ikev2/transform`: the negotiated
transform ID selects the algorithm, so nothing else has to change.)

### Dependencies

The module depends on `golang.org/x/crypto` (and `golang.org/x/sys`, which it
pulls in for CPU feature detection). Nothing else.

That dependency exists for exactly one reason: **WireGuard fixes its crypto and
does not negotiate it.** It mandates ChaCha20-Poly1305 and BLAKE2s, and Go ships
neither in the standard library, so — unlike IKEv2, which negotiates algorithms
and happens to negotiate ones `crypto/aes` and `crypto/sha256` cover — WireGuard
cannot be built on stdlib alone.

The alternative was hand-rolling both. That was rejected: `x/crypto` is the Go
team's own module and carries the AVX2/NEON assembly, which measures **~1.9 GB/s**
for ChaCha20-Poly1305 on the data path against the several-times-slower pure-Go
implementation we would have written — and an AEAD protecting every packet is a
far larger security surface than the bundled MD4 in `internal/ikev2/eap`, which
is a legacy hash confined to one corner of MSCHAPv2.

Everything is still CGO-free, and the `nm/` plugin remains a separate module so
the core does not inherit its D-Bus and GTK dependencies.

EAP-MSCHAPv2 additionally uses MD4 (for the NT password hash) and single-DES
(for the challenge response), as the protocol mandates. Go's standard library
has DES but not MD4, so a compact RFC 1320 MD4 is included in `internal/ikev2/eap`;
these legacy primitives are used only where MSCHAPv2 requires them, never for
transport security.

## Architecture

The tree separates machinery any VPN protocol needs from what is specific to one
protocol. IKEv2 is the first protocol; others become siblings under `internal/`.

```
cmd/veepin               CLI: connect / serve / probe subcommands, flags, routing
client                   protocol registry (client + server) + the Session/Result/Server contracts
ikev2                    public IKEv2 entry point: Dial + NewServer, Config
wireguard                public WireGuard entry point: Dial + NewServer, Config, wg-quick parser
openvpn                  public OpenVPN entry point: Dial + NewServer, Config, .ovpn parser
sstp                     public SSTP entry point: Dial + NewServer, Config, crypto binding
ssh                      public SSH entry point: Dial + NewServer, Config (x/crypto/ssh)

dataplane                TUN device, address pool, packet pump (demux + routing), client routing
internal/cryptoutil      DH, PRF + prf+, integrity, SK/ESP ciphers, ChaCha20-Poly1305, BLAKE2s

internal/ikev2/payload   wire codec: header, payloads, SA/KE/Nonce/Notify/ID/AUTH/TS/Delete/CP
internal/ikev2/transform IANA transform ID -> cryptoutil primitive
internal/ikev2/eap       EAP packet codec + EAP-MSCHAPv2 (MD4/DES/SHA1, MSK derivation)
internal/ikev2/esp       ESP encapsulate/decapsulate + anti-replay
internal/ikev2/ike       negotiation, SK seal/open, NAT-T, CP, exchange handlers, keymat, Client

internal/wireguard/wire      message codec: the four types, fixed layouts, demux, TAI64N
internal/wireguard/noise     Noise_IKpsk2 handshake (initiator), KDF, MAC
internal/wireguard/transport type-4 transport crypto: counter nonce, padding, replay window

internal/openvpn/wire        packet codec: opcode byte, session IDs, control/ACK framing
internal/openvpn/reliable    control-channel reliability: window, retransmit, reorder, ACKs
internal/openvpn/control     TLS control channel: a net.Conn over the reliability layer
internal/openvpn/tlswrap     tls-auth/tls-crypt: static-key HMAC and AES-256-CTR control wrapping
internal/openvpn/keys        key method 2 exchange + TLS 1.0 PRF key derivation
internal/openvpn/data        P_DATA_V2 seal/open (AES-256-GCM and AES-256-CBC) + anti-replay window

internal/sstp/wire           SSTP packet codec: control/data framing, attributes, crypto binding
internal/ppp                 PPP client + server: LCP, MS-CHAPv2 auth, IPCP (transport-neutral)
internal/mschap              MS-CHAPv2 primitives + MPPE/HLAK key derivation

internal/sshtun              OpenSSH tun@openssh.com framing: channel-open data + AF packet frames
```

`dataplane` and `internal/cryptoutil` are protocol-agnostic: neither imports anything
else in this module, and neither knows IKEv2 exists. The crypto primitives are named
for what they are (`NewAESGCMSKCipher`, `NewECDH`) rather than for IKEv2's transform-ID
registry, and the pump moves packets between a TUN device and a set of `Tunnel`s,
demuxing inbound packets with a `Demux` the protocol supplies:

```go
type Demux func(pkt []byte) (key uint32, ok bool)

func SPIDemux(pkt []byte) (uint32, bool) // ESP: the SPI in the first four octets
```

IKEv2 passes `SPIDemux`; a protocol that identifies tunnels differently (WireGuard's
receiver index lives at offset 4, and only on transport-data messages) passes its own.

Outbound, a packet goes to the tunnel whose route matches its destination most
specifically, and a packet matching no route is dropped. One mechanism covers every
case: an IKEv2 server's tunnel carries its peer's assigned address as a `/32`, an
IKEv2 client's carries `0.0.0.0/0` because everything on its TUN belongs to the one
server, and a WireGuard peer carries its AllowedIPs.

`internal/ikev2/transform` is the single place that translates IANA transform IDs into
primitives. Those seams are what keep the boundary honest.

Data flow once a client is connected:

```
client app → client OS ESP → UDP:4500 → veepin serve → decapsulate → TUN → kernel routing → internet
internet → kernel → TUN → veepin serve → encapsulate → UDP:4500 → client OS → client app
```

## Build

Requires Go 1.21+ (developed against Go 1.26).

```sh
go build ./...
go test ./...
go build -o veepin ./cmd/veepin
```

One binary does everything, dispatching on a subcommand and a protocol:

```
veepin connect <protocol> [flags]   bring up a tunnel to a server
veepin serve   <protocol> [flags]   run a VPN server
veepin probe   <protocol> [flags]   diagnostic: handshake + one data packet
```

IKEv2 (`connect`/`serve`), WireGuard (`connect`/`serve`), OpenVPN (`connect`) and
SSTP (`connect`) are the built-in protocols; `veepin` with no arguments lists
what is registered.

## Run

Creating a TUN device needs `CAP_NET_ADMIN`. Either run as root, or grant the
binary the capability once:

```sh
sudo setcap cap_net_admin+ep ./veepin
```

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

### Username/password authentication (EAP-MSCHAPv2)

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

### Connecting as a WireGuard client

`veepin connect wireguard` dials a WireGuard peer as an initiator. It takes a
wg-quick config file, individual flags, or both — a flag overrides the file's
value for the same field, so a checked-in config can carry a per-run override:

```sh
# From a wg-quick file (the same format `wg-quick` and the mobile apps use):
sudo ./veepin connect wireguard -config /etc/wireguard/wg0.conf

# Or entirely from flags:
sudo ./veepin connect wireguard \
  -private-key "$(wg genkey | tee privkey)" \
  -public-key SERVER_PUBLIC_KEY_BASE64 \
  -endpoint vpn.example.com:51820 \
  -address 10.0.0.2/32 \
  -allowed-ips 0.0.0.0/0 \
  -persistent-keepalive 25
```

The config's `AllowedIPs` become the tunnel's routes: a packet leaving the TUN
goes to the peer whose AllowedIPs match its destination most specifically, the
same cryptokey-routing rule WireGuard defines. As with IKEv2, `connect` applies
addressing and routing to the system, and `-no-route` brings the tunnel up
without touching either (useful for diagnostics).

### Running a WireGuard server

`veepin serve wireguard` is the responder. It reads a wg-quick server config —
one `[Peer]` per client — or a single peer from flags, and (with `-setup-nat`)
assigns the gateway address and installs the masquerade rule:

```sh
sudo ./veepin serve wireguard -config /etc/wireguard/wg0.conf -setup-nat -wan eth0
```

where `wg0.conf` is the standard server form:

```ini
[Interface]
PrivateKey = <server private key>
Address    = 10.10.0.1/24
ListenPort = 51820

[Peer]
PublicKey  = <client public key>
AllowedIPs = 10.10.0.2/32
```

Cryptokey routing runs both ways: `AllowedIPs` selects which peer an outbound
packet goes to, and an inbound packet whose source is outside a peer's
`AllowedIPs` is dropped. Peers roam (the return address follows each packet's
source), and replayed handshake initiations are rejected by their timestamp. A
veepin client rekeys on its own — re-running the handshake roughly every two
minutes and rotating the new keypair in without dropping traffic — so a tunnel
stays up indefinitely; see the note under [What it does](#what-it-does).

### Connecting as an OpenVPN client

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
boundaries under [What it does](#what-it-does). Add `-username`/`-password` for
servers that require `auth-user-pass`.

### Running an OpenVPN server

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

### Connecting as an SSTP client

`veepin connect sstp` dials a Microsoft SSTP server over TLS on port 443:

```sh
sudo ./veepin connect sstp \
  -server vpn.example.com -user alice -pass secret

# For a server with a self-signed certificate (SSTP still mutually authenticates
# via MS-CHAPv2, so the tunnel is not unauthenticated):
sudo ./veepin connect sstp -server 10.0.0.1 -user alice -pass secret -insecure
```

The client opens the TLS carrier, performs the `SSTP_DUPLEX_POST` HTTP handshake,
exchanges CALL_CONNECT with the server's crypto-binding nonce, authenticates the
inner PPP link with MS-CHAPv2 (deriving the HLAK and sending the CALL_CONNECTED
compound MAC over the server's certificate), and negotiates IPCP for its address
and DNS. Only SHA-256 crypto binding is implemented. The client-vs-SoftEther path
is covered end to end by the Docker interop tests. Set `VEEPIN_SSTP_DEBUG=1` to
trace the control and PPP exchange.

### Running an SSTP server

`veepin serve sstp` is the responder: it terminates TLS with the given
certificate, answers the `SSTP_DUPLEX_POST` handshake, sends the CALL_CONNECT_ACK
nonce, authenticates the inner PPP link as the MS-CHAPv2 authenticator, verifies
the client's CALL_CONNECTED crypto binding against its own certificate, and
assigns an address over IPCP. Each client rides its own TLS/TCP connection.

```sh
sudo ./veepin serve sstp \
  -cert server.crt -key server.key \
  -user alice -pass secret \
  -pool 10.9.0.0/24 -dns 1.1.1.1 -setup-nat -wan eth0
```

The certificate is what the crypto binding hashes, so it must be the one clients
connect to (a real deployment terminates TLS here directly, not behind a proxy).
It is verified in Docker against both the sstp-client `sstpc`/pppd reference and
the veepin client.

### Connecting as an SSH client

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

### Running an SSH server

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

## Connecting an OS client

The server authenticates with a machine PSK plus an identity, and assigns the
client an address — the standard "IKEv2 PSK" road-warrior setup.

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

### Smoke-testing without an OS client

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

## Using the bundled client

`veepin connect` is a full VPN client: it connects to a server, obtains an
address, brings up a local TUN, installs routes, and tunnels the host's traffic.
Like the server it needs `CAP_NET_ADMIN` (for the TUN device and routing table):

```sh
sudo ./veepin connect ikev2 -server vpn.example.com -psk 'a-strong-preshared-key' \
    -id client.example.com -server-id vpn.example.com
```

By default it installs a full-tunnel default route (all traffic through the VPN)
plus a host route to the server via the existing gateway, so the encapsulated
ESP packets don't recurse into the tunnel. On disconnect (Ctrl-C) the routes are
reverted. Useful flags:

- `-user` / `-pass` — authenticate with EAP-MSCHAPv2 username/password instead of
  the client PSK (the server PSK still authenticates the server).
- `-full-tunnel=false` — only bring up the interface/address; add your own routes.
- `-no-route` — connect and establish the data path but make no routing changes
  (useful for testing, or when another process manages routes).
- `-server-id` — verify the server presents this identity in its IDr.

The client speaks the same PSK and EAP-MSCHAPv2 flows the server accepts, so
`veepin connect` ↔ `veepin serve` interoperate directly, and the client also works
against other RFC 7296 responders that accept these authentication methods.

### Embedding the client

The handshake and data path are a reusable library. Dial
performs the handshake and brings up the ESP data path over a TUN **without**
installing routes, returning the assigned address/DNS/gateway for the caller to
apply; `veepin connect` is a thin wrapper over it.

There are two ways in. Go code that knows which protocol it wants imports the
protocol package and gets a typed config:

```go
import "github.com/xen0bit/veepin/ikev2"

sess, res, err := ikev2.Dial(ctx, ikev2.Config{
    Server: "vpn.example.com", PSK: "…", LocalID: "client.example.com",
})
defer sess.Close()
// apply res.AssignedIP / res.DNS / res.Gateway yourself
```

Callers whose parameters arrive as strings — a CLI's flags, NetworkManager's
settings dictionary — dial by name instead, selecting protocols by importing
them:

```go
import (
    "github.com/xen0bit/veepin/client"
    _ "github.com/xen0bit/veepin/ikev2" // registers "ikev2"
)

sess, res, err := client.Dial(ctx, "ikev2", map[string]string{
    "gateway": "vpn.example.com", "psk": "…", "local-id": "client.example.com",
})
```

`client.Result` and `client.Session` are protocol-agnostic, so code that applies
a Result or manages a Session does not change when a protocol is added. Running
a server is the same shape: `ikev2.NewServer(ikev2.ServerConfig{…})` wires the
TUN, address pool and data path, and leaves host routing/NAT to the caller.

### Desktop integration (NetworkManager)

A NetworkManager VPN plugin lets a Linux desktop (GNOME / Pop!\_OS) bring the
tunnel up and down from its native VPN UI, with **no** dependency on strongSwan.
It lives in the nested `nm/` module, kept out of the core build so the `veepin`
binary does not inherit its D-Bus and GTK dependencies:

```sh
cd nm && make build && sudo make install
sudo systemctl reload NetworkManager
nmcli connection add type vpn con-name home-veepin ifname '*' \
  vpn-type org.freedesktop.NetworkManager.veepin \
  vpn.data 'protocol=ikev2, gateway=vpn.example.com, local-id=client.example.com, full-tunnel=yes'
nmcli connection modify home-veepin vpn.secrets 'psk=a-strong-preshared-key'
nmcli connection up home-veepin
```

See [`doc/networkmanager-plugin.md`](doc/networkmanager-plugin.md) for the full
design, the D-Bus contract, the runbook, and the roadmap (a graphical *Add VPN*
form is the remaining phase).

## Testing

```sh
go test -race ./...        # correctness
./bench.sh                 # performance (see Benchmarks below)
```

Highlights:

- `internal/ikev2/ike` — `TestEndToEndHandshake` (full IKE_SA_INIT + IKE_AUTH +
  liveness with a real initiator against the live dual-socket server),
  `TestFullVPNFlow` (handshake + NAT-T + CP address assignment + a real IP
  packet delivered through ESP onto the server's TUN), and
  `TestEAPMSCHAPv2Flow` / `TestEAPWrongPassword` (the full multi-round EAP
  username/password exchange, accepting correct and rejecting wrong credentials),
  and `TestClientConnectPSK` / `TestClientConnectEAP` / `TestClientWrongPSK`
  (the production client driven against the live server, including bidirectional
  ESP through the negotiated Child SA).
- `internal/ikev2/eap` — MD4 against RFC 1320 vectors, MSCHAPv2 key derivation against
  the RFC 3079 test vectors, and a full server exchange with a simulated client
  (matching MSKs on success, rejection on wrong password/unknown user).
- `dataplane` — `TestPumpRoundTrip` (TUN → ESP → demux → decap round
  trip), address-pool allocation/exhaustion/reuse, unknown-SPI drop.
- `internal/cryptoutil` — DH agreement across all five groups, the RFC 5903 point
  prefix, prf+, GCM/CBC round trips with tamper detection.
- `internal/ikev2/transform` — every negotiable transform ID resolves to a
  primitive, unsupported IDs are rejected, and the negotiated ID (not a guess
  from key length) selects the ESP algorithm.
- `internal/ikev2/esp` — ESP round trips and anti-replay.
- `internal/ikev2/payload` — header/payload/SA/TS/CP codec round trips.

### Interoperability matrix

The Docker interop tests (`make interop`, build tag `interop`) prove each protocol
against a real third-party implementation and against itself. Every protocol has
both roles, so all three cells below are exercised.

| Protocol  | veepin client ↔ real server | real client ↔ veepin server | veepin ↔ veepin (self) |
|-----------|-----------------------------|-----------------------------|------------------------|
| IKEv2     | ✓ strongSwan                | ✓ strongSwan                | ✓                      |
| WireGuard | ✓ wireguard-go              | ✓ wireguard-go              | ✓                      |
| OpenVPN   | ✓ `openvpn` (×4 variants)   | ✓ `openvpn`                 | ✓                      |
| SSTP      | ✓ SoftEther                 | ✓ `sstpc`/pppd              | ✓                      |
| SSH       | ✓ `sshd` (PermitTunnel)     | ✓ `ssh -w`                  | ✓                      |

Both roles share one API: a client registers with `client.Register` and is dialed
by `client.Dial`; a server registers with `client.RegisterServer` and is built by
`client.NewServer`, so `veepin connect <proto>` and `veepin serve <proto>` dispatch
generically. Every protocol now has both roles, and each cell above is a Docker
interop test.

## Benchmarks

The suite includes detailed benchmarks covering the two performance-critical
paths — per-packet data-plane throughput and per-connection handshake cost — plus
the underlying primitives. Run them all with:

```sh
./bench.sh                 # all benchmarks
./bench.sh -benchtime 3s   # longer runs for stable numbers
BENCH=ESP ./bench.sh       # only ESP data-plane benchmarks
```

or directly with `go test -bench . -benchmem ./...`.

What's measured:

- **Data plane** (`internal/ikev2/esp`, `dataplane`) — ESP encapsulate,
  decapsulate and full round-trip, and the pump's inbound demux+decap+TUN path,
  across 64/576/1400-byte packets for AES-GCM (128/256) and AES-CBC+HMAC.
  Reported in MB/s via `b.SetBytes`.
- **WireGuard transport** (`internal/wireguard/transport`) — the type-4 seal and
  open paths (ChaCha20-Poly1305 with a counter nonce, padding, and the anti-replay
  window) across the same packet sizes. Seal is a single allocation (the output
  packet, with padding and the nonce folded into it) and Open decrypts in place
  with none, ~1.9 GB/s at 1400 B — on par with the AES-GCM ESP path.
- **OpenVPN data channel** (`internal/openvpn/data`) — AES-256-GCM P_DATA_V2 seal
  and open (packet-ID nonce, tag-first wire order, replay window) across the same
  sizes. Same profile: Seal one allocation, Open zero, ~1.9 GB/s seal / ~2.9 GB/s
  open at 1400 B.
- **Handshake** (`internal/ikev2/ike`) — SK message seal/open, and a full PSK
  handshake (IKE_SA_INIT + IKE_AUTH) over real UDP loopback against the live
  server.
- **Asymmetric crypto** (`internal/cryptoutil`, `internal/ikev2/ike`) — DH key generation
  and shared-secret computation for each group, prf+ expansion and raw cipher seal,
  plus IKE/Child key derivation.
- **Login** (`internal/ikev2/eap`) — NT hashing, MSCHAPv2 challenge response, MSK
  derivation, and a full server-side authentication.
- **Codec** (`internal/ikev2/payload`) — message parse/build and SA/TS round-trips.

Representative results (Intel Xeon @ 2.8 GHz, Go 1.26, single core):

| Benchmark | Throughput / latency | Allocs | Notes |
|-----------|---------------------|--------|-------|
| ESP decap AES-256-GCM, 1400 B | ~2030 MB/s | 1 | inbound data-plane cipher |
| ESP encap AES-256-GCM, 1400 B | ~1640 MB/s | 2 | outbound data-plane cipher |
| Pump inbound AES-256-GCM, 1400 B | ~1990 MB/s | 1 | demux + decap + TUN write |
| ESP decap AES-256-CBC+SHA256, 1400 B | ~190 MB/s | 3 | ~10× slower than GCM |
| DH Curve25519 (generate + compute) | ~53 µs each | — | handshake asymmetric cost |
| DH MODP-2048 compute | ~3.9 ms | — | ~70× slower than Curve25519 |
| Full PSK handshake | ~370 µs | 406 | end-to-end over UDP loopback |
| Full EAP-MSCHAPv2 auth | ~16 µs | — | per-login CPU cost |
| Parse IKE_SA_INIT message | ~270 ns | 4 | codec |

Two takeaways the numbers make concrete: AES-GCM is dramatically faster than
AES-CBC+HMAC on this data path (hence the GCM-first default), and the elliptic-
curve groups are orders of magnitude cheaper than MODP-2048 for the handshake
(hence Curve25519 first).

### Data-plane optimization

The data path was tuned using these benchmarks as the guide — measuring, changing
one thing, and re-measuring. The ESP cipher was moved off the handshake-oriented
`SKCipher` (which rebuilds `aes.NewCipher`/`cipher.NewGCM` on every call) onto a
prepared `crypto.ESPCrypter` that constructs its keyed AEAD once and then seals
and opens packets by appending into a caller-supplied buffer. Combined with a
reused GCM nonce buffer (avoiding a heap escape through the AEAD interface), a
pooled plaintext scratch buffer, a cached HMAC for the CBC path, and removing a
redundant packet copy in the pump, this took the AES-256-GCM 1400-byte paths
from roughly 517→1640 MB/s (encap) and 910→2030 MB/s (decap), and cut
allocations from 10→2 and 5→1 per packet respectively.

A later pass closed the remaining gap on the AES-GCM path so that **both encap
and decap are a single allocation per packet** — the returned packet buffer.
Encapsulate had been writing the ESP header into a stack array and passing it as
the AEAD's additional data; because that argument crosses the `cipher.AEAD`
interface it escaped to the heap, a second allocation. Writing the header into
the (already heap-allocated) output buffer and reusing that prefix as the AAD
removes the escape. On the inbound side the decapsulate reject paths (unknown
SPI, replay, malformed trailer) were switched from `fmt.Errorf` to pre-allocated
sentinel errors, so dropping a flood of duplicate or misrouted datagrams now
allocates nothing on the unknown-SPI path (and only the decrypt buffer on the
replay path). `TestDataPathAllocationsGCM` asserts these counts (via
`testing.AllocsPerRun`) so they cannot silently regress.

The `ESPCrypter` is intended to be driven by one goroutine per SA direction
(matching the pump); across multiple clients, work scales across cores, as
`BenchmarkESPDecapParallel` exercises.

The WireGuard and OpenVPN data paths were held to the same standard, guarded by
`TestDataPathAllocations` in each package. The recurring cost the AEAD interface
imposes is the 12-byte nonce: passing a stack array through `cipher.AEAD`'s
`[]byte` parameter escapes it to the heap, one allocation per packet. Both seal
paths avoid it by building the nonce in unused tail bytes of the output buffer
they already allocate — no shared scratch, so seal stays safe to call
concurrently with keepalives. The open paths go further to zero allocations by
decrypting in place: WireGuard reuses the packet's own header bytes as the nonce
(the counter already sits where the nonce needs it, and the demuxed receiver
index is zeroed to supply the four leading zeros), while OpenVPN reuses a
per-`Cipher` receive-nonce buffer (safe because open runs on the single inbound
pump goroutine) and rotates the tag-first wire layout into Go's tag-last order in
place. Seal is a single allocation (the returned packet), open none.

## Scope and limitations

- **Client and server, Linux data path.** Both roles are implemented. The TUN
  data path and the client's routing use the Linux drivers/iproute2; other
  platforms compile but `OpenTUN` and route installation return errors. The
  IKE/handshake code is portable.
- **PSK and EAP-MSCHAPv2 auth.** Certificate-based authentication is not
  implemented. EAP is limited to MSCHAPv2 (the method OS clients use); other EAP
  methods (TLS, PEAP, GTC) are out of scope. MSCHAPv2 is cryptographically dated
  and requires recoverable passwords server-side, but it is the interoperable
  username/password choice.
- **No DoS cookies, no IKE fragmentation, no MOBIKE.** `CREATE_CHILD_SA` treats
  rekey as a fresh child; the message-ID window accepts only the next expected
  request (retransmits are dropped, not replayed from cache).
- **Client liveness is basic.** The client sends NAT keepalives to hold the NAT
  binding, but does not yet initiate DPD liveness checks or rekey the IKE/Child
  SA before their lifetimes expire, so very long-lived client sessions will
  eventually need to reconnect. The handshake, data path, and routing are
  complete; these are the natural next additions.
- **IPv4 tunneling.** The data path routes IPv4; IPv6 inner traffic is not
  forwarded.
- **Single IKE SA per Child.** Sufficient for road-warrior clients; not a
  site-to-site multi-SA gateway.

These are deliberate boundaries for a readable, self-contained implementation,
not accidental gaps — each is a localized extension point rather than a
structural rework.
