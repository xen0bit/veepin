# internal/openvpn

The OpenVPN engine: the client session and the multi-client server. The public
[`openvpn`](../../openvpn) package reads `.ovpn` profiles and options and hands
this package a `ClientConfig` or `ServerConfig` with the key material read and
the server resolved; nothing here parses a profile. Beneath it are
[`wire`](wire), [`reliable`](reliable), [`control`](control),
[`tlswrap`](tlswrap), [`keys`](keys) and [`data`](data), each with its own
README.

## Specification

OpenVPN has no RFC. The wire behaviour is the reference implementation's —
`ssl.c`, `ssl_pkt.c`, `push.c` and `forward.c` in
[OpenVPN 2.6](https://github.com/OpenVPN/openvpn) — against which veepin
interoperates in both directions.

## The two roles

```mermaid
sequenceDiagram
    participant C as Client (client.go, session.go)
    participant S as Server (server.go)
    C->>S: P_CONTROL_HARD_RESET_CLIENT_V2 (wrapped: plain, tls-auth or tls-crypt)
    S->>C: P_CONTROL_HARD_RESET_SERVER_V2
    Note over C,S: TLS over the control channel; mutual certificates
    C->>S: key method 2 (random, options, optional user/pass)
    S->>C: key method 2
    C->>S: PUSH_REQUEST
    S->>C: PUSH_REPLY (ifconfig, ifconfig-ipv6, peer-id, cipher, ping)
    Note over C,S: P_DATA_V2 under the derived keys, keyed by peer-id
```

On the client one socket is demultiplexed by opcode (`session.go`'s muxer):
control packets to the channel, data packets to the pump. On the server one
socket carries every client, and data packets demux by the P_DATA_V2 peer-id the
server assigned.

## API surface

- `Dial(ctx, ClientConfig) (client.Session, client.Result, error)` — a refusal of
  the credentials comes back as `*AuthError`, for the caller to report as
  `client.ErrAuth`.
- `NewServer(ServerConfig) (*Server, error)` — opens the TUN, binds nothing;
  `ListenAndServe` binds. `ServerConfig.Validate` is what `NewServer` checks
  first.
- `CipherGCM`, `CipherCBC`, `DefaultCipher` — the data ciphers implemented.

## Implementation notes & caveats

- **UDP only.** TCP transport is refused at profile parse; there is no
  stream framing here.
- **No compression.** The client's peer info advertises none (no `IV_LZO`, no
  `IV_COMP_STUB`), and a profile's `compress` or `comp-lzo` line is ignored like
  every directive this client does not use. A server that compresses anyway
  produces a data channel this end cannot decode, which surfaces as a tunnel
  that comes up and carries nothing.
- **The data path still allocates per packet.** ESP and WireGuard build their
  datagrams in the pump's buffers (`dataplane.AppendTunnel`) and open in place;
  OpenVPN's `data.Cipher` does neither yet, so both directions allocate one
  buffer per packet. The same two changes apply, and are the next step for this
  engine's throughput across cores.
- **The server reaps a silent client after ping-restart (60 s)** — the bound it
  pushes to the client, held in the other direction too.
- **Post-quantum is the TLS 1.3 key exchange and ML-DSA certificates** under the
  `pq-openvpn` name; the static tls-auth / tls-crypt keys are symmetric and are
  what they are. See doc/security.md.
