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

Every one of the then-thirteen protocols in the tree was layer 3. That was
checked, not assumed — the `EtherType` constants in `internal/gp/frame.go` and
`internal/anyconnect/wire.go` only *name* the payload family inside a framing
header; nothing anywhere constructs or parses an Ethernet header, and
`dataplane` opened a TUN. L2TPv3's Ethernet pseudowire has since landed as the
tree's first layer-2 carrier, and it is exactly the "genuinely new machinery"
this plan predicted.

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

None of that was reusable from the then-existing thirteen. That is the argument for
doing it, and equally the argument for its cost.

## Wire details — corrected, after a real peer disagreed

> **This section was wrong, and the code written from it was wrong with it.**
> It claimed to be "verified from the source" and said the integers are
> little-endian; they are big-endian. It described the connection as opening
> with a PACK; it opens with an HTTP POST. It described the data path as one
> length-prefixed frame at a time; frames are written in counted blocks. Those
> errors survived from the day this file was written until a cell against
> SoftEther VPN Server was finally built, because the only thing testing them
> was a veepin talking to another veepin that had read the same wrong page.
>
> The corrected format is below, and the authority for it is named per field.
> The lesson is the one `AGENTS.md` already states and this is now the best
> example of: reading the reference implementation means reading the functions
> that touch the wire — `WritePack`, `WriteElement`, `WriteValue`,
> `WriteBufStr`, `WriteBufInt` — not a paragraph summarising them.

The byte-level wire format, from `SoftEtherVPN/src/Mayaqua/Pack.c` and
`src/Mayaqua/Memory.c`. All integers are **big-endian**: every one goes through
`WriteBufInt`/`ReadBufInt`, which call `Endian32`, which byte-swaps on a
little-endian host.

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

The SoftEther native protocol operates over TLS (TCP/443), and **every control
message is an HTTP body**. From `ClientUploadSignature`, `ServerDownloadSignature`,
`ServerUploadHello`, `ClientUploadAuth` and `HttpClientSend`/`HttpServerSend`:

1. **TCP connect** to port 443 (default), then the **TLS handshake**.
2. **Client POSTs `/vpnsvc/connect.cgi`** with `Content-Type: image/jpeg` and a
   body that is either the watermark blob or the exact string `VPNCONNECT`
   (`HTTP_VPN_TARGET_POSTDATA`). The server accepts either.
3. **Server responds `200 OK`** with a PACK: `hello` (its version string),
   `version`, `build`, and `random` (20 octets). The client sends no hello of
   its own — this response is unprompted.
4. **Client POSTs `/vpnsvc/vpn.cgi`** with the login PACK: `method="login"`,
   `hubname`, `username`, `authtype`, `secure_password`, **and the session
   parameters** — `max_connection`, `use_encrypt`, `use_compress`,
   `half_connection`. The session parameters are not optional: a login without
   `max_connection` is answered with a welcome and then disconnected.
5. **Server responds `200 OK`** with the welcome PACK (`session_name`,
   `connection_name`, `session_key`, policy, timeouts) or with an `error`
   element — 9 is `ERR_AUTH_FAILED`.
6. **The connection shifts to tunnelling mode** (`StartTunnelingMode`) and
   carries blocks from then on.

Every PACK crossing HTTP also carries a `pencore` element of random length
(`CreateDummyValue`), whose purpose is to keep the control exchange from being
a sequence of fixed-size TLS records.

### Password hashing

From `Account.c` (`HashPassword`) and `Sam.c` (`SecurePassword`), and **not**
SHA-1:

```
stored  = SHA0(password ‖ UPPER(username))
on-wire = SHA0(stored ‖ server_random)
```

SHA-0, the withdrawn predecessor of SHA-1. `Mayaqua/Encrypt.c`'s
`MY_SHA0_Transform` omits SHA-1's `ROTL1` in the message schedule via a C comma
expression — `W[t] = (1, W[t-3] ^ ...)` — which discards the `1`. Compiling
that function verbatim reproduces the published SHA-0 vectors, which is how
that reading was settled rather than argued.

### Data path

After the welcome, both directions write **counted blocks**, from
`Connection.c`'s send path and its mode-0/1/3 receive machine:

```
uint32be  block count
  count × { uint32be size, size octets of Ethernet frame }
```

Two counts are not counts: `0` means no frames follow (a tick), and
`0xffffffff` (`KEEP_ALIVE_MAGIC`) introduces one length and that many octets of
random padding, discarded. Per-block size is bounded by `MAX_PACKET_SIZE * 2`.

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
