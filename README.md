# veepin

A **working userspace IKEv2 VPN in Go** — both a server (responder) and a client
(initiator) — written from scratch with no external dependencies beyond the Go
standard library. It performs the full IKEv2 key exchange with pre-shared-key or
EAP-MSCHAPv2 authentication, NAT traversal, and IKEv2 configuration mode (address
assignment), then runs an ESP-in-UDP data path over a TUN device — so a
standards-compliant OS VPN client can connect to the server, and the bundled
client can connect to it (or any RFC 7296 responder) and tunnel a host's traffic.

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

## Cryptography

| Category | Supported |
|----------|-----------|
| DH groups | Curve25519 (31), ECP-256/384/521 (19/20/21), MODP-2048 (14) |
| PRF | HMAC-SHA1, HMAC-SHA2-256/384/512 |
| IKE/ESP ciphers | AES-GCM-16 (AEAD, RFC 5282), AES-CBC + HMAC-SHA2 (encrypt-then-MAC) |
| Integrity | HMAC-SHA1-96, HMAC-SHA2-256-128/384-192/512-256 |

All from the standard library. (ChaCha20-Poly1305's transform ID is defined but
not wired in, because Go ships that cipher only in `golang.org/x/crypto`. If that
dependency is acceptable, adding it is a `cryptoutil` constructor plus a case in
`internal/ikev2/transform` — the negotiated transform ID selects the algorithm, so
nothing else has to change.)

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
client                   protocol registry + the Session/Result contract
ikev2                    public IKEv2 entry point: Dial, NewServer, Config

dataplane                TUN device, address pool, packet pump (demux + routing), client routing
internal/cryptoutil      DH, PRF + prf+, integrity, SK/ESP ciphers

internal/ikev2/payload   wire codec: header, payloads, SA/KE/Nonce/Notify/ID/AUTH/TS/Delete/CP
internal/ikev2/transform IANA transform ID -> cryptoutil primitive
internal/ikev2/eap       EAP packet codec + EAP-MSCHAPv2 (MD4/DES/SHA1, MSK derivation)
internal/ikev2/esp       ESP encapsulate/decapsulate + anti-replay
internal/ikev2/ike       negotiation, SK seal/open, NAT-T, CP, exchange handlers, keymat, Client
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
`internal/ikev2/transform` is the single place that translates IANA transform IDs into
primitives. Those two seams are what keep the boundary honest.

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

IKEv2 is currently the only protocol; `veepin` with no arguments lists what is
registered.

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

The handshake and data path are a reusable, dependency-free library. Dial
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
It lives in the nested `nm/` module (the only part that uses a third-party
dependency and is kept out of the core build so the `veepin` binary stays
CGO-free and stdlib-only):

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
