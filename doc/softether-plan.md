# veepin: SoftEther native protocol (SE-VPN)

## What this is

SoftEther's own protocol: **Ethernet frames over HTTPS on TCP/443**, with an
optional UDP acceleration path. It is the protocol SoftEther's own client speaks
to its own server, distinct from the OpenVPN / L2TP / SSTP compatibility layers
the same server also offers — two of which veepin already interoperates with.

Apache 2.0, developed at the University of Tsukuba, with **client and server
both open source**. That last point is why it heads the roadmap: it is the only
serious candidate where the interop matrix can have a real third-party peer in
*both* directions, which is the strongest form of verification this project has.

## Why it is worth the effort: veepin has no layer 2

Every one of the thirteen protocols in the tree is layer 3. This was checked, not
assumed — the `EtherType` constants in `internal/gp/frame.go` and
`internal/anyconnect/wire.go` only *name* the payload family inside a framing
header; nothing anywhere constructs or parses an Ethernet header, and
`dataplane` opens a TUN.

SoftEther carries **real Ethernet frames**. That forces genuinely new machinery
into the shared layer rather than another protocol package beside the existing
ones:

- **TAP support in `dataplane`.** `tun_linux.go` already references the
  `IFF_TAP` constants; the device is opened as a TUN. A TAP mode is a small
  change to the ioctl and a large change to everything that assumes the first
  nibble of a buffer is an IP version.
- **MAC learning on the server.** Today every server routes inbound packets by
  *inner IP address* (`sessions[netip.Addr]`, `byIP`, or the pump's route
  table). A layer-2 server routes by **destination MAC**, learned from source
  MACs as frames arrive, with an ageing table and a broadcast/multicast flood
  path for unknown destinations. That is a switch.
- **ARP and DHCP inside the tunnel.** With no IP-level address assignment, a
  client discovers its neighbours by ARP. SoftEther's server has a built-in
  DHCP server and NAT ("SecureNAT") for exactly this reason. A minimal veepin
  server needs at least to answer ARP for its own address and either run DHCP or
  document that the caller supplies addressing.

None of that is reusable from the existing thirteen. That is the argument for
doing it, and equally the argument for its cost.

## Wire details — status: **not yet verified**

This section is deliberately thin, and that is the most important thing about
this plan. Unlike the Fortinet, GlobalProtect and Pulse plans — where the wire
format was read out of openconnect's source before a line was written — **no
equivalent reading has been done for SE-VPN**, and the published specification is
a capabilities overview rather than a byte-level format.

What is known from the specification pages:

- TLS 1.0–1.3 over TCP/443, framed as extended HTTPS so it passes as web traffic.
- Ethernet as the payload, any protocol inside it.
- A TCP/UDP hybrid transport: multiple TCP connections per session for
  throughput, with an optional UDP acceleration path.
- zlib compression is available.
- Authentication supports password, RADIUS, certificate and anonymous.

**Before any implementation begins**, the first task is to read
`github.com/SoftEtherVPN/SoftEtherVPN` — `src/Cedar/Protocol.c`, `src/Cedar/Session.c`
and `src/Mayaqua/Pack.c` — and write the byte-level format into this document,
the way `doc/fortinet-plan.md` records openconnect's. In particular the "PACK"
serialisation SoftEther uses for its control messages is a self-describing
key/value format that will need its own codec and its own fuzz target.

Estimate the reading at a day before the first commit. A plan that skips it will
be wrong, and the lesson is recent: the Pulse plan's *summarised* cipher
identifiers were wrong, and reading `pulse.c` directly was what caught it.

## Phases

1. **Read the source; fill in the wire section above.** Deliverable is this
   document, not code.
2. **`internal/softether/pack.go`** — the PACK key/value codec, both directions,
   with a truncation-rejection test and a fuzz target. This is the foundation
   everything else parses through.
3. **`dataplane`: TAP mode.** `OpenTAP`, and an audit of every place that
   assumes an IP header at offset 0 (`TrimToIP`, `destOf`/`sourceOf` equivalents,
   the pump's route table). Do this as its own commit with its own tests, because
   it touches shared code that thirteen protocols depend on.
4. **`internal/softether/switch.go`** — the learning bridge: MAC table with
   ageing, flood for unknown/broadcast, per-session port. Testable entirely in
   memory with no sockets.
5. **`internal/softether/{auth,session,link}.go`** — the control exchange, the
   multi-connection session, the frame path.
6. **Both roles end to end** over a real TLS listener, mirroring
   `internal/pulse/e2e_test.go`.
7. **Facade, CLI, docs, NM, fuzz, interop** — the standard checklist in
   `CLAUDE.md`.

## Interop

The prize, and the reason this is ranked first: **both directions get a real
peer.**

- `compose.softether.yml` — veepin client → SoftEther server (`vpnserver`).
- `compose.softether-server.yml` — SoftEther client (`vpnclient`) → veepin
  server. No other candidate on the roadmap can have this cell.
- `compose.softether-self.yml` — the attribution check.

The Docker image is a source build; SoftEther publishes no Debian package of the
stable branch worth relying on. Budget for the build in the image, cached.

## Risks, stated plainly

- **Largest surface on the roadmap.** A learning switch, a serialisation format,
  a multi-connection session layer and TAP support in shared code. This is
  several times the size of any of the three protocols added in v0.8.0.
- **TAP changes shared code.** The blast radius reaches every existing protocol.
  Phase 3 must land green on the full interop matrix before phase 4 starts.
- **Layer 2 changes the `client.Result` contract.** `AssignedIP`/`Netmask`
  assume the protocol assigns an address. A DHCP-inside-the-tunnel model does
  not. Decide early whether `client.Result` grows a layer-2 variant or whether
  the SoftEther facade runs a DHCP client itself and fills in the existing
  fields — the second is less invasive and probably right.
- **Compression is a side channel.** zlib on attacker-influenced plaintext inside
  TLS is CRIME/BREACH-shaped. Implement it as *off*, and if it is implemented at
  all, `doc/security.md` must say why enabling it is a bad idea.
