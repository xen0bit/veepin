# veepin

A **working userspace VPN in Go** — both server (responder) and client
(initiator), written from scratch and depending only on the pure-Go
`golang.org/x` modules (`x/crypto`, and `x/net` for QUIC), no cgo. It speaks
**sixteen production protocols, client and server for every one** — IKEv2/ESP,
WireGuard, OpenVPN, SSTP, SSH, L2TP/IPsec, L2TPv3 Ethernet pseudowire,
AnyConnect, Nebula, MASQUE (CONNECT-IP and CONNECT-UDP over HTTP/3), Fortinet,
GlobalProtect, Cisco IPsec, Ivanti Connect Secure, SoftEther VPN (SE-VPN) and
AmneziaWG — each verified in Docker against a real third-party implementation
and against itself.

Every layer is covered by tests, including full VPN integration tests:
`TestFullVPNFlow` drives a client through the handshake and verifies a real IP
packet traverses the ESP data path onto the server's TUN, and `TestClientConnectPSK`
drives the production client against the live server and checks bidirectional ESP.

## Contents

- [What it does](#what-it-does) — the protocol capability table
- [Cryptography](#cryptography) — algorithms, [dependencies](#dependencies), [security boundaries](#what-veepin-does-not-protect-against)
- [Architecture](#architecture) — the package tree and the protocol-agnostic boundary
- [Install](#install) — apt repository and packaged releases
- [Build](#build) and [Run](#run) — building the binary; per-protocol runbooks
- [The example protocol](#the-example-protocol) — TOY, the insecure teaching example
- [Using the bundled client](#using-the-bundled-client) — CLI client, [embedding](#embedding-the-client), [NetworkManager](#desktop-integration-networkmanager)
- [Testing](#testing) — highlights and the live [interop matrix](#interoperability-matrix)
- [Benchmarks](#benchmarks) — representative numbers (full table in [`doc/benchmarks.md`](doc/benchmarks.md))
- [Scope and limitations](#scope-and-limitations)

Deeper docs live under [`doc/`](doc/): per-protocol [usage](doc/usage/),
[architecture](doc/architecture.md), [security](doc/security.md),
[testing](doc/testing.md) and [benchmarks](doc/benchmarks.md). What might be
added next, and what was considered and rejected, is in
[`doc/protocol-roadmap.md`](doc/protocol-roadmap.md).

## What it does

veepin speaks sixteen production protocols — **client and server for every one** —
plus one deliberately insecure teaching example. Each protocol is verified in
Docker against a real third-party implementation *and* against itself (see the
[Interoperability matrix](#interoperability-matrix)). The table is the summary;
each row links to that protocol's own package documentation, which carries the
wire detail, caveats and API surface.

| Protocol | Authentication | Data path | Verified against | Docs |
|----------|----------------|-----------|------------------|------|
| **IKEv2/ESP** | PSK, EAP-MSCHAPv2, X.509 certificate (RFC 7427) | ESP-in-UDP, RFC 4303 (NAT-T, dual-stack v4/v6 CP address assignment) | strongSwan | [ikev2](internal/ikev2/ike/README.md) |
| **WireGuard** | Noise_IKpsk2 static keys | ChaCha20-Poly1305, cryptokey routing, client rekey | wireguard-go | [wireguard](internal/wireguard/) |
| **OpenVPN** | mutual TLS certificates | AES-256-GCM / -CBC; plain, `tls-auth`, `tls-crypt` (both roles) | `openvpn` | [openvpn](internal/openvpn/) |
| **SSTP** | MS-CHAPv2 over PPP | PPP/IPCP over TLS, SHA-256 crypto binding | SoftEther, `sstpc`/pppd | [sstp](internal/sstp/wire/README.md) |
| **SSH** | public key / password | IP over `tun@openssh.com` (layer-3) | OpenSSH `sshd` / `ssh -w` | [ssh](internal/sshtun/README.md) |
| **L2TP/IPsec** | IKEv1 PSK + MS-CHAPv2 | L2TP/PPP inside an ESP transport SA (NAT-T) | strongSwan + xl2tpd | [l2tp](internal/l2tp/README.md) |
| **L2TPv3** | none — static config, cookie is a check value | Ethernet frames over UDP/1701 on a TAP device (RFC 3931 + 4719), **layer 2** | Linux kernel (`ip l2tp`) | [l2tpv3](internal/l2tpv3/README.md) |
| **AnyConnect** | password | CSTP over TLS, with DTLS 1.2 PSK fallback | ocserv, openconnect | [anyconnect](internal/anyconnect/README.md) |
| **Nebula** | certificate PKI, per host | Noise IX mesh, AES-GCM / ChaCha20 | slackhq/nebula | [nebula](internal/nebula/README.md) |
| **MASQUE** | proxy TLS | IP (CONNECT-IP) and UDP (CONNECT-UDP) over HTTP/3, capsule mode | aioquic | [masque](internal/masque/README.md) |
| **Fortinet** | password, optional 2FA (TOTP) | PPP over TLS, with cert-based DTLS 1.2 fallback | openconnect | [fortinet](internal/fortinet/README.md) |
| **GlobalProtect** | password | RFC 4303 ESP over UDP, keyed by the config document, with a framed layer-3 TLS tunnel as fallback | openconnect | [gp](internal/gp/README.md) |
| **Cisco IPsec** | group PSK + XAuth password | IKEv1 Aggressive Mode, Mode-Config, tunnel-mode ESP-in-UDP | strongSwan | [cisco](internal/cisco/README.md) |
| **Ivanti Connect Secure** | password (EAP over IF-T/TLS) | RFC 4303 ESP over UDP, with the IF-T/TLS connection as fallback | openconnect | [pulse](internal/pulse/README.md) |
| **SoftEther VPN** | password | Ethernet frames over TLS (PACK control), layer-2 TAP | not yet — see `‡` below | [softether](internal/softether/README.md) |
| **AmneziaWG** | Noise_IKpsk2 static keys | WireGuard's ChaCha20-Poly1305 unchanged; obfuscated headers, padding and junk packets | `amneziawg-go` | [amneziawg](wireguard/obfuscate.go) |

Both roles share one registry API (`client.Register`/`client.RegisterServer`),
so `veepin connect <proto>` and `veepin serve <proto>` dispatch generically and
adding a protocol changes no caller. A seventeenth registered protocol, **TOY**,
provides **no security** — it is a worked example of the protocol shape, not a
real protocol; see [The example protocol](#the-example-protocol).

## Cryptography

| Category | Supported |
|----------|-----------|
| DH groups | Curve25519 (31), ECP-256/384/521 (19/20/21), MODP-2048 (14) |
| PRF | HMAC-SHA1, HMAC-SHA2-256/384/512 |
| IKE/ESP ciphers | AES-GCM-16 (AEAD, RFC 5282), ChaCha20-Poly1305 (AEAD, RFC 7634), AES-CBC + HMAC-SHA2 (encrypt-then-MAC) |
| Integrity | HMAC-SHA1-96, HMAC-SHA2-256-128/384-192/512-256 |

AES from the standard library; ChaCha20-Poly1305 from `x/crypto` (the same AEAD
WireGuard already pulls in). ChaCha20-Poly1305 for IKEv2/ESP shares AES-GCM-16's
exact framing — a 4-octet implicit salt, an 8-octet explicit IV and a 16-octet
tag — so both run through one generic AEAD path in `cryptoutil`, and it is
offered after AES-GCM (which is faster where the CPU has AES-NI) and ahead of
AES-CBC.

### Dependencies

The module depends only on the pure-Go `golang.org/x` modules: `x/crypto`,
`x/net` (for QUIC), and `x/sys` and `x/text` that those pull in. Nothing outside
the `golang.org/x` namespace, and no cgo.

`x/crypto` exists first for **WireGuard, which fixes its crypto and does not
negotiate it.** It mandates ChaCha20-Poly1305 and BLAKE2s, and Go ships neither
in the standard library, so WireGuard cannot be built on stdlib alone. IKEv2
reaches the same `x/crypto` ChaCha20-Poly1305 for its own RFC 7634 suite — an
AEAD Go's standard library still omits — but everything else IKEv2 negotiates is
covered by `crypto/aes` and `crypto/sha256`, so that one AEAD is the whole of
its dependency beyond stdlib.

`x/net` exists for a second: **MASQUE runs over HTTP/3, and Go ships no QUIC.**
`x/net/quic` is the Go team's own pure-Go implementation, so the alternative —
hand-rolling a QUIC stack or vendoring a third-party one — is avoided the same
way `x/crypto` avoids hand-rolling ChaCha20. (`x/net/http3` is *not* used: its
public surface exports nothing and it has no CONNECT/datagram/capsule support,
so the HTTP/3 layer MASQUE needs is built from scratch on the `quic` package —
see `internal/masque/http3`.) Only MASQUE imports it; the other nine protocols
still reach no further than `x/crypto`.

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

### What veepin does not protect against

Three boundaries are worth stating outright, because each is the kind of thing a
reader may otherwise assume is handled — and none is an oversight:

- **Key material is not zeroed after use.** veepin does not claim protection
  against an attacker who can read process memory (core dump, debugger, swap).
- **Throughput is bounded by one core per direction.** The data path runs one
  TUN-reader goroutine and one socket-reader goroutine per server, shared across
  all clients — a scaling ceiling, not a correctness problem.
- **MASQUE carries every inner packet on one reliable QUIC stream** (capsule
  mode), so it reintroduces head-of-line blocking on a lossy path.

The reasoning behind each — why Go's memory model makes zeroization unreliable,
and why the MASQUE boundary is a performance limit rather than a correctness one —
is in [`doc/security.md`](doc/security.md).

## Architecture

The tree separates machinery any VPN protocol needs from what is specific to one
protocol. Each protocol is a sibling under `internal/`, with a thin public
package exposing `Dial` and `NewServer`; the shared machinery — TUN handling,
address pools, the packet pump, admission control, MTU derivation — lives in
`dataplane` and `internal/cryptoutil` and is written once.

```
cmd/veepin               CLI: connect / serve / probe subcommands, flags, routing
client                   protocol registry (client + server) + the Session/Result/Server contracts
ikev2                    public IKEv2 entry point: Dial + NewServer, Config
wireguard                public WireGuard entry point: Dial + NewServer, Config, wg-quick parser
openvpn                  public OpenVPN entry point: Dial + NewServer, Config, .ovpn parser
sstp                     public SSTP entry point: Dial + NewServer, Config, crypto binding
ssh                      public SSH entry point: Dial + NewServer, Config (x/crypto/ssh)
l2tp                     public L2TP/IPsec entry point: Dial + NewServer, Config
anyconnect               public AnyConnect entry point: Dial + NewServer, Config
nebula                   public Nebula entry point: Dial + NewServer (lighthouse), Config
masque                   public MASQUE entry point: Dial + NewServer (CONNECT-IP proxy), Config
fortinet                 public Fortinet entry point: Dial + NewServer (SSL VPN gateway), Config
toy                      public TOY entry point: Dial + NewServer — an INSECURE teaching example

dataplane                TUN device, address pool, packet pump (demux + routing), client routing
                         admission control, ICMP/PMTU, MTU derivation, source-preserving PacketConn
                         downstream flow shaping (padding away the inner traffic's size pattern)
internal/cryptoutil      DH, PRF + prf+, integrity, SK/ESP ciphers, ChaCha20-Poly1305, BLAKE2s
internal/replay          the anti-replay window shared by nebula and toy

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

internal/anyconnect          CSTP framing, the config-auth XML exchange, the DTLS channel, and the client/server engines
internal/dtls                DTLS 1.2 PSK: record layer, handshake flights, fragmentation, anti-replay

internal/nebula              minimal protobuf codec, v1 certificates + CA pool, Noise IX, 16-octet header,
                             AEAD data path with anti-replay, the mesh host engine and the lighthouse protocol

internal/masque              CONNECT-IP + CONNECT-UDP: capsules, the HTTP-Datagram payload, the TUN
                             client/server engines, and the CONNECT-UDP relay + local UDP forwarder
internal/masque/http3        from-scratch HTTP/3 on x/net/quic: varints, minimal QPACK (zero dynamic table),
                             SETTINGS/control streams, Extended CONNECT, capsules over DATA frames

internal/toy                 the TOY example protocol + SPEC.md — NO SECURITY; the smallest complete
                             illustration of a veepin protocol (handshake, Tunnel, pump, both roles)

internal/ikev1               ISAKMP/IKEv1: payload codec, Main + Quick mode, SKEYID/KEYMAT, CBC IV chaining
internal/l2tp                RFC 2661 header/AVP codec, reliable control channel, PPP data channel,
                             plus the client/server engines binding IKEv1 + ESP + L2TP + PPP to a TUN
internal/fortinet            FortiOS SSL VPN: the 6-octet PPP framing, the logincheck/SVPNCOOKIE
                             login, the fortisslvpn_xml config, the PPP-over-TLS client/server,
                             and the DTLS data channel with its GFtype cookie exchange
internal/udpmux              one UDP socket demultiplexed into per-peer net.Conns, shared by the
                             AnyConnect and Fortinet DTLS listeners
internal/otp                 HOTP (RFC 4226) and TOTP (RFC 6238), generation and constant-time
                             verification — the second factor behind Fortinet's ret=2 challenge
```

`dataplane` and `internal/cryptoutil` are protocol-agnostic: neither imports
anything else in this module, and neither knows IKEv2 exists. That boundary — how
the pump demuxes inbound packets with a protocol-supplied `Demux`, how outbound
routing picks a tunnel by most-specific route, and how a packet flows end to end —
is written up in [`doc/architecture.md`](doc/architecture.md).

## Install

On Debian/Ubuntu — any Debian release architecture (amd64, arm64, armhf, armel,
i386, ppc64el, riscv64, s390x) — the signed APT repository tracks the latest
release:

```sh
sudo curl -fsSL https://xen0bit.github.io/veepin/veepin-archive-keyring.gpg \
     -o /usr/share/keyrings/veepin-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/veepin-archive-keyring.gpg] https://xen0bit.github.io/veepin stable main" \
     | sudo tee /etc/apt/sources.list.d/veepin.list
sudo apt update && sudo apt install veepin veepin-nm
```

`veepin` is the CLI (server + client, no runtime dependencies); `veepin-nm`
adds the NetworkManager desktop integration (built for the same architectures;
the amd64/arm64 builds load on Ubuntu 22.04+, the cross-built rest on
Debian 12+ / Ubuntu 24.04+). The repository signing
key's fingerprint is pinned in [packaging/apt-signing-key.asc](packaging/apt-signing-key.asc).
The package ships a systemd template unit — drop arguments in
`/etc/veepin/<name>.conf` and `systemctl enable --now veepin@<name>` (see
`/usr/share/doc/veepin/veepin.conf.example`); it grants the daemon the
capabilities it needs, so no root shell or setcap step.

`.deb`/`.rpm`/`.apk` packages and plain tarballs for every version are on
[GitHub Releases](https://github.com/xen0bit/veepin/releases)
(`apt install ./veepin_<ver>_linux_<arch>.deb` works directly).

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

Every protocol — the sixteen production ones and the TOY example — is registered
for both `connect` and `serve`; `veepin` with no
arguments lists what is registered.

## Run

Creating a TUN device needs `CAP_NET_ADMIN`. Either run as root, or grant the
binary the capability once:

```sh
sudo setcap cap_net_admin+ep ./veepin
```

On any `serve` subcommand, `-setup-nat -wan <iface>` auto-configures the tunnel
interface, enables IP forwarding, and installs a MASQUERADE rule for that WAN
interface; omit it and the server prints the exact `ip`/`iptables` lines to run
by hand. Each protocol's `connect`/`serve` runbook — its flags, config-file
formats, and what it interoperates with — has its own page:

| Protocol | Runbook |
|----------|---------|
| IKEv2/ESP (incl. EAP-MSCHAPv2) | [doc/usage/ikev2.md](doc/usage/ikev2.md) |
| WireGuard | [doc/usage/wireguard.md](doc/usage/wireguard.md) |
| OpenVPN | [doc/usage/openvpn.md](doc/usage/openvpn.md) |
| SSTP | [doc/usage/sstp.md](doc/usage/sstp.md) |
| SSH | [doc/usage/ssh.md](doc/usage/ssh.md) |
| L2TP/IPsec | [doc/usage/l2tp.md](doc/usage/l2tp.md) |
| AnyConnect | [doc/usage/anyconnect.md](doc/usage/anyconnect.md) |
| Nebula | [doc/usage/nebula.md](doc/usage/nebula.md) |
| MASQUE (CONNECT-IP + CONNECT-UDP) | [doc/usage/masque.md](doc/usage/masque.md) |
| Fortinet | [doc/usage/fortinet.md](doc/usage/fortinet.md) |
| GlobalProtect | [doc/usage/gp.md](doc/usage/gp.md) |
| Cisco IPsec | [doc/usage/cisco.md](doc/usage/cisco.md) |
| Ivanti Connect Secure | [doc/usage/pulse.md](doc/usage/pulse.md) |
| SoftEther VPN | [doc/usage/softether.md](doc/usage/softether.md) |
| AmneziaWG | [doc/usage/amneziawg.md](doc/usage/amneziawg.md) |
| L2TPv3 Ethernet pseudowire | [doc/usage/l2tpv3.md](doc/usage/l2tpv3.md) |

To run **a fleet of servers** in one process with a localhost management API
and embedded web panel, the supervisor mode is additive to the bare
single-protocol command: see [Running the supervisor](doc/usage/supervisor.md)
and [the `veepin mgmt` CLI](doc/usage/mgmt.md).

To use veepin **as a client**, the
[NetworkManager plugin](#desktop-integration-networkmanager) is the simplest path
on a Linux desktop — it configures all sixteen protocols from the native VPN UI. The
[Using the bundled client](#using-the-bundled-client) section below walks the CLI
client through end to end. Stock OS built-in VPN clients (Windows, macOS/iOS,
Android, strongSwan) can also connect to the veepin IKEv2 server directly — see
[doc/usage/ikev2.md](doc/usage/ikev2.md).

## The example protocol

**TOY provides no security** — its "encryption" is a repeating XOR pad and its
"authentication" is a hash-table hash, so anyone who can see the traffic can read
and forge it. It is not one of the ten real protocols; it is the *shape* of a
veepin protocol with the cryptography replaced by placeholders simple enough to
read in one sitting — a handshake producing a `client.Result`, a `dataplane.Pump`
data path, and both roles on the client registry. Its interop cells talk to an
**independent Python implementation** written from the spec, so they test the
document rather than the code.

If you are adding a real protocol, start here:
[`internal/toy/README.md`](internal/toy/README.md) and
[`internal/toy/SPEC.md`](internal/toy/SPEC.md), which document the wire format,
enumerate the concrete ways the cryptography fails, and map each to what a real
protocol here does instead.

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

The handshake and data path are a reusable library: `Dial` performs the handshake
and brings up the ESP data path over a TUN **without** installing routes,
returning the assigned address/DNS/gateway for the caller to apply. `veepin
connect` is a thin wrapper over it. Go code that knows which protocol it wants
imports the protocol package for a typed config:

```go
import "github.com/xen0bit/veepin/ikev2"

sess, res, err := ikev2.Dial(ctx, ikev2.Config{
    Server: "vpn.example.com", PSK: "…", LocalID: "client.example.com",
})
defer sess.Close()
// apply res.AssignedIP / res.DNS / res.Gateway yourself
```

Callers whose parameters arrive as strings (a CLI's flags, NetworkManager's
settings dictionary) dial by name, selecting protocols by importing them:

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
a Result or manages a Session does not change when a protocol is added. A server
is the same shape: `ikev2.NewServer(ikev2.ServerConfig{…})` wires the TUN,
address pool and data path, and leaves host routing/NAT to the caller.

### Desktop integration (NetworkManager)

A NetworkManager VPN plugin brings the tunnel up and down from a Linux desktop's
native VPN UI (GNOME / Pop!\_OS), with **no** dependency on strongSwan. It lives
in the nested `nm/` module — kept out of the core build so the `veepin` binary
does not inherit its D-Bus and GTK dependencies — and registers **all sixteen
protocols as separate VPN types**, so each is its own entry in the desktop's
*Add VPN* list rather than a "veepin" entry that asks which protocol next:

```sh
cd nm && make build && sudo make install && sudo systemctl reload NetworkManager
nmcli connection add type vpn con-name home-veepin ifname '*' \
  vpn-type org.freedesktop.NetworkManager.veepin.ikev2 \
  vpn.data 'protocol=ikev2, gateway=vpn.example.com, local-id=client.example.com, full-tunnel=yes'
nmcli connection modify home-veepin vpn.secrets 'psk=a-strong-preshared-key'
nmcli connection up home-veepin
```

Switching protocol is the same command with a different `vpn-type` suffix, a
matching `protocol=` key and that protocol's own option names; graphically it is
a different entry in the *Add VPN* list, each with only its own fields.
See [`doc/networkmanager-plugin.md`](doc/networkmanager-plugin.md) for
the full design, the D-Bus contract, the per-protocol key reference, and the
runbook.

## Testing

```sh
go test -race ./...        # correctness
./bench.sh                 # performance (see Benchmarks below)
make interop               # Docker interop suite (build tag `interop`)
```

Per-package test highlights — the end-to-end IKEv2 and production-client flows,
the EAP/MD4 vectors, the dataplane round-trips and the codec coverage — are
collected in [`doc/testing.md`](doc/testing.md).

### Interoperability matrix

The Docker interop tests prove each protocol against a real third-party
implementation and against itself, both roles. The matrix is regenerated by CI
from the live interop run on every push to main — each ✓ is a Docker test that
passed in that run, not a claim.

<!-- livingreadme:interop:start -->
| Protocol   | veepin client ↔ real server | real client ↔ veepin server | veepin ↔ veepin (self) |
|------------|-----------------------------|-----------------------------|------------------------|
| IKEv2 | ✓ strongSwan (PSK + pubkey, AES-GCM + ChaCha20, dual-stack, v6 underlay, ML-KEM-768) | ✓ strongSwan (+ EAP-MSCHAPv2, RFC 7383 frag, v6 underlay, TFC-padded, ML-KEM-768) | ✓ |
| WireGuard | ✓ wireguard-go | ✓ wireguard-go (+ padded) | ✓ |
| OpenVPN | ✓ `openvpn` (×4 variants) | ✓ `openvpn` (+ tls-auth, tls-crypt, padded) | ✓ |
| SSTP | ✓ SoftEther | ✓ `sstpc`/pppd (+ PPP-padded) | ✓ |
| SSH | ✓ `sshd` (PermitTunnel) | ✓ `ssh -w` | ✓ |
| L2TP/IPsec | ✓ strongSwan + xl2tpd | ✓ strongSwan + xl2tpd (+ PPP-padded) | ✓ |
| AnyConnect | ✓ ocserv | ✓ openconnect (TLS, DTLS, CSTP-padded) | ✓ |
| Nebula | ✓ `nebula` (lighthouse) | ✓ `nebula` (host) | ✓ (via lighthouse) |
| MASQUE-IP | ✓ aioquic CONNECT-IP | ✓ aioquic CONNECT-IP | ✓ |
| MASQUE-UDP | ✓ aioquic CONNECT-UDP | ✓ aioquic CONNECT-UDP | ✓ |
| Fortinet | —† | ✓ openconnect (TLS, DTLS, 2FA, PPP-padded) | ✓ (over DTLS) |
| GlobalProtect | —† | ✓ openconnect (SSL tunnel, ESP, padded) | ✓ (over ESP) |
| Cisco IPsec | ✓ strongSwan (aggressive + XAuth) | ✓ strongSwan (Mode-Config, TFC-padded) | ✓ |
| Ivanti Connect Secure | —† | ✓ openconnect (IF-T/TLS, ESP, padded) | ✓ (over ESP) |
| SoftEther VPN | —‡ | —‡ | —‡ |
| AmneziaWG | ✓ amneziawg-go | ✓ amneziawg-go | ✓ (H1-H4, S1-S4, junk) |
| L2TPv3 | ✗ Linux kernel (`ip l2tp`, 8-octet asymmetric cookies) — needs `l2tp_eth` on the host | ✗ Linux kernel (`ip l2tp`) — needs `l2tp_eth` on the host | ✓ (shaped) |
| TOY* | ✓ independent Python peer | ✓ independent Python peer | ✓ |

_Generated by the `interop` workflow from `0742ec3` on 2026-08-02._
<!-- livingreadme:interop:end -->

`*` TOY is a **deliberately insecure example protocol**, not a real one (see
[The example protocol](#the-example-protocol)). `†` Fortinet is asymmetric — no
open-source FortiOS gateway exists for the client direction, so the openconnect
*client* against the veepin server is the independent proof. `‡` marks a cell
that is work outstanding rather than a limitation: an open-source peer exists
(SoftEther VPN Server) but the Docker cell is not built yet. SoftEther cannot
have one until its TAP data path lands — see
[`internal/softether/README.md`](internal/softether/README.md). The full
rationale,
the registry API behind the cells, and the interop harness are in
[`doc/testing.md`](doc/testing.md) and
[`tests/interop/README.md`](tests/interop/README.md).

#### Tunnel throughput (iperf3, live)

The same matrix, but measured: during each interop run an `iperf3` flow is pushed
across every tunnel that came up, and the received rate is committed back here on
push to main. The numbers are relative — a shared CI runner, a short window, one
TCP stream — so read them as an order-of-magnitude comparison between carriers,
not a benchmark of the wire.

A **dash** means iperf3 does not apply to that cell: a peer with no bindable
tunnel address (SoftEther's SecureNAT gateway), the CONNECT-UDP datagram cells
(which forward datagrams rather than route IP), or the untested Fortinet client.
A **✗** means it does apply, was attempted across a tunnel that came up, and
produced no number — a measurement that is broken rather than absent. The two
used to render identically, which presented a broken measurement as a deliberate
omission; the interop harness now logs the difference.

<!-- livingreadme:interop-benchmark:start -->
| Protocol   | veepin client ↔ real server | real client ↔ veepin server | veepin ↔ veepin (self) |
|------------|----------------------------:|----------------------------:|-----------------------:|
| IKEv2 | 217 Mbit/s | 779 Mbit/s | 406 Mbit/s |
| WireGuard | 407 Mbit/s | 917 Mbit/s | 614 Mbit/s |
| OpenVPN | 586 Mbit/s | 478 Mbit/s | 433 Mbit/s |
| SSTP | — | 192 Mbit/s | 364 Mbit/s |
| SSH | 319 Mbit/s | 118 Mbit/s | 113 Mbit/s |
| L2TP/IPsec | 368 Mbit/s | 328 Mbit/s | 522 Mbit/s |
| AnyConnect | 471 Mbit/s | 505 Mbit/s | 315 Mbit/s |
| Nebula | 1.68 Gbit/s | 2.31 Gbit/s | 1.34 Gbit/s |
| MASQUE-IP | 22.3 Mbit/s | 39.6 Mbit/s | 321 Mbit/s |
| MASQUE-UDP | — | — | — |
| Fortinet | — | 558 Mbit/s | 308 Mbit/s |
| GlobalProtect | — | 528 Mbit/s | 446 Mbit/s |
| Cisco IPsec | 265 Mbit/s | 673 Mbit/s | 449 Mbit/s |
| Ivanti Connect Secure | — | 521 Mbit/s | 410 Mbit/s |
| SoftEther VPN | — | — | — |
| AmneziaWG | 568 Mbit/s | — | 626 Mbit/s |
| L2TPv3 | — | — | — |
| TOY* | 16.8 Mbit/s | 19.5 Mbit/s | 391 Mbit/s |

_Generated by the `interop` workflow from `0742ec3` on 2026-08-02._
<!-- livingreadme:interop-benchmark:end -->

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

They measure the data plane (ESP/pump, WireGuard, OpenVPN, Nebula and DTLS across
64/576/1400-byte packets), the per-protocol framing paths, the IKEv2/IKEv1
handshakes, and the asymmetric/login/codec primitives. Representative results
(Intel Xeon @ 2.8 GHz, Go 1.26, single core):

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

The **complete `go test -bench` result set** — regenerated by CI on every push to
main — the per-package breakdown of what each benchmark covers, and the data-plane
allocation-tuning writeup are in [`doc/benchmarks.md`](doc/benchmarks.md).

## Scope and limitations

These are deliberate boundaries for a readable, self-contained implementation —
each a localized extension point, not a structural rework:

- **Client and server, Linux data path.** Both roles are implemented, but the TUN
  data path and route installation are Linux-only (other platforms compile;
  `OpenTUN` and routing return errors). The IKE/handshake code is portable.
- **PSK, EAP-MSCHAPv2 and X.509 certificate auth.** Certificate authentication
  is the RFC 7427 Digital Signature (AUTH method 14) with RSA or ECDSA, plus the
  legacy RSA method (1) for a peer that does not offer RFC 7427 — client and
  server, mutually verified against a CA and bound to the peer's IKE identity;
  it interoperates with strongSwan's `pubkey` auth. The classic per-curve ECDSA
  methods (9/10/11) and RSA-PSS are not produced, and EAP remains MSCHAPv2 only
  (TLS/PEAP/GTC out of scope). MSCHAPv2 is dated and needs recoverable passwords
  server-side, but it is the interoperable username/password choice.
- **Child SA rekey is fresh-only.** `CREATE_CHILD_SA` treats rekey as a fresh
  child and the message-ID window accepts only the next expected request. IKEv2
  *does* implement MOBIKE (RFC 4555 `UPDATE_SA_ADDRESSES`, so a roaming peer
  survives an address change without re-handshaking), IKE fragmentation
  reassembly (RFC 7383 — it negotiates and reassembles inbound SKF fragments but
  never fragments its own, always-small output) and the RFC 7296 §2.6 cookie
  exchange; every server bounds unauthenticated work through `dataplane.Gate`.
- **Client liveness and SA rekey are unified across protocols.** A
  cross-protocol monitor (`client.Prober`, applied automatically by
  `client.Dial`) detects a dead peer and tears the tunnel down for a clean
  re-dial. IKEv2 runs RFC 7296 dead-peer detection (an empty `INFORMATIONAL` the
  server must answer); WireGuard probes with a handshake, which doubles as a
  rekey; pump-based protocols expose an authenticated-idle signal
  (`dataplane.Pump.IdleFor`), which TOY uses. Reliable-transport protocols
  (SSTP, SSH, AnyConnect, MASQUE, Fortinet) surface a dead peer through the
  transport's own read failure, so they need no probe. IKEv2 also rekeys both
  its SAs proactively before their soft lifetimes: the **Child SA** with a
  `CREATE_CHILD_SA` whose fresh keys are swapped into the data path before the
  old SA is deleted, and the **IKE SA** itself (RFC 7296 §2.18) with a fresh
  Diffie-Hellman exchange for a new control channel — the Child SAs inherited
  unchanged, so the data path never pauses. Neither lets a long-lived tunnel
  expire in place.
- **Dual-stack inner traffic, IPv4 or IPv6 underlay; single IKE SA per Child.**
  IKEv2 carries both IPv4 and IPv6 inner traffic over one Child SA: the server
  assigns a v4 and a v6 address via config mode (`INTERNAL_IP4_*` and the
  `INTERNAL_IP6_ADDRESS` address+prefix, RFC 7296 3.15), offers v4+v6 traffic
  selectors, and the data path tags each packet with the ESP next-header its
  version implies (4 or 41); oversized inner v6 gets an ICMPv6 Packet Too Big,
  the v6 counterpart of the IPv4 fragmentation-needed path. The *outer* transport
  runs over either family too: the client dials a v4 or v6 server, and the server
  binds the family of its `-listen` address (`0.0.0.0` for IPv4 by default, `::`
  for an IPv6/dual-stack socket that serves both). Serving both families
  simultaneously is what the one `::` dual-stack socket provides; separate v4+v6
  sockets per port are not added. This is one IKE SA per Child, sufficient for
  road-warrior clients rather than a site-to-site multi-SA gateway.
- **Downstream flow shaping is opt-in, and covers sizes rather than timing.**
  One inner packet becomes one outer datagram, so the size pattern of an inner
  TLS handshake otherwise survives encapsulation — the fingerprint of
  [USENIX Security '24](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting),
  which byte-level obfuscation does not address. `veepin serve <protocol> -shape
  <bytes>` pads the first N bytes of each inner flow out to the tunnel MTU on
  seven of the nine protocols — RFC 4303 §2.7 TFC padding for ESP, trailing
  octets for WireGuard, the RFC 1661 §5.1 PPP Information field for SSTP,
  Fortinet and L2TP/IPsec, and the length-delimited data payload for AnyConnect
  and OpenVPN. All are inert to a conforming receiver, which delimits the real
  packet by the inner IP header, so **stock clients benefit unmodified**; and
  because the attack targets handshakes, the cost is per-flow rather than
  per-byte, leaving bulk throughput untouched. It does not shape packet counts
  or timing (that would need constant-rate padding), does not cover the upstream
  direction unless the client is also veepin, and is not probe resistance.
  Interop cells prove strongSwan, wireguard-go, `openvpn`, pppd and openconnect
  all accept the padding *and* trim it correctly; it stays off by default
  because the vendor OS stacks it is meant to protect are untested —
  [`doc/verifying-shaping.md`](doc/verifying-shaping.md) is the procedure for
  changing that, and it needs a person with a device rather than more code. See
  [`doc/traffic-shaping.md`](doc/traffic-shaping.md) for the design and for what
  it does not hide.
- **AnyConnect's DTLS needs TLS 1.3 or Extended Master Secret** (RFC 7627) — Go's
  `crypto/tls` will not run the RFC 5705 exporter otherwise, so against such a
  peer the client stays on TLS. Only PSK-NEGOTIATE mode; auth is
  username/password only (no client certificates or SSO flows).
- **L2TP/IPsec requires UDP-encapsulated ESP.** No raw IP-protocol-50 path, so it
  always forces the NAT-T float to UDP/4500. IKEv1 is Main Mode + PSK only (no
  Aggressive Mode, certificates, or Quick-Mode PFS), one child SA with no phase-2
  rekey, MS-CHAPv2 only.

The **security boundaries** — no key zeroization, single-core throughput, and
MASQUE's capsule-mode head-of-line blocking — are stated separately in
[`doc/security.md`](doc/security.md).
