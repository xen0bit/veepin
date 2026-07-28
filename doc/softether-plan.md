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

## Wire details — verified from the source

The byte-level wire format has been read from `SoftEtherVPN/src/Mayaqua/Pack.c`
and `src/Mayaqua/Pack.h`. All integers are **little-endian**.

### PACK serialisation

SoftEther control messages use a self-describing key/value format called PACK:

```
Pack {
    element-count: uint32           // number of ELEMENTs (max 262144)
    elements:     ELEMENT[count]    // in order
}

ELEMENT {
    name:     NUL-terminated ASCII  // max 63 chars + NUL
    type:     uint32                // 0=INT, 1=DATA, 2=STR, 3=UNISTR, 4=INT64
    count:    uint32                // number of values (max 262144)
    values:   VALUE[count]          // depending on type
}

VALUE {
    // For type INT:      uint32 (4 bytes)
    // For type INT64:    uint64 (8 bytes)
    // For type DATA:     length uint32, then length bytes of raw data
    // For type STR:      length uint32, then length bytes of ASCII (no NUL terminator on wire)
    // For type UNISTR:   length uint32, then length bytes of UTF-8
}
```

Maximum sizes: per-VALUE data 384 MB, serialised PACK 512 MB, element name 63 chars.

### Connection flow

The SoftEther native protocol operates over TLS (TCP/443). The exchange is:

1. **TCP connect** to port 443 (default).
2. **TLS handshake**, presenting the SNI for the virtual hub.
3. **Client sends a PACK** containing `method="hello"`, client version, build info.
4. **Server responds** with a PACK containing server version, build info, and a `random` field (20 bytes, used for password hashing).
5. **Client sends a PACK** containing authentication method (`"login"`), username, hub name, and password proof (SHA1 of SHA1 of password XOR'd with random).
6. **Server responds** with a PACK containing auth result, assigned IP, and session parameters.
7. **Ethernet frames** are exchanged raw over the TLS connection, with a 4-byte length prefix before each frame.

### Data path

After authentication, the client and server exchange raw Ethernet frames. Each
frame is prefixed with a 4-byte little-endian length (the frame's length
excluding the prefix). There is no type/length/value wrapping beyond this
4-byte length header — the bytes between length prefixes are a complete Ethernet
frame (14-byte header + payload, with FCS usually absent as the encapsulating
link is assumed reliable).

### UDP acceleration

An optional UDP path sends raw Ethernet frames over UDP/4500 with a
connection-ID-based demux. Each UDP datagram carries an 8-byte header (session
ID + sequence number) followed by the Ethernet frame. Implementation deferred
until the TCP-only data path is verified.

### PACK codec implementation

The PACK codec lives in `internal/softether/pack.go` and has been implemented
with a truncation-rejection test suite and a subslice-zero-allocation decoder.
The initial implementation covers all five value types; the UNISTR type stores
UTF-8 on the wire (the same as STR; the difference is in how the SoftEther peer
interprets the result, which is the caller's responsibility).

## Phases

1. **Read the source; fill in the wire section above.** ✓ DONE.
2. **`internal/softether/pack.go`** — the PACK key/value codec, both directions,
   with a truncation-rejection test and a fuzz target. ✓ DONE.
3. **`dataplane`: TAP mode.** `OpenTAP` added to `dataplane/tun_linux.go` and
   `tun_other.go`. Remaining: audit of every place that assumes an IP header at
   offset 0 (`TrimToIP`, `innerDest`, `flowKeyOf`, the pump's route table).
4. **`internal/softether/switch.go`** — the learning bridge: MAC table with
   ageing, flood for unknown/broadcast, per-session port. NOT YET IMPLEMENTED.
5. **`internal/softether/{auth,session,link}.go`** — the control exchange, the
   multi-connection session, the frame path. NOT YET IMPLEMENTED.
6. **Both roles end to end** over a real TLS listener, mirroring
   `internal/pulse/e2e_test.go`. NOT YET IMPLEMENTED.
7. **Facade, CLI, docs, NM, fuzz, interop** — the standard checklist in
   `AGENTS.md`. NOT YET IMPLEMENTED.

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
