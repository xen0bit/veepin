# Running SSTP

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Connecting as an SSTP client

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

## Running an SSTP server

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

## Downstream flow shaping

`-shape <bytes>` pads the first N bytes of each inner flow out to the tunnel
MTU, so the size pattern of a TLS handshake made *inside* the tunnel does not
survive encapsulation:

```sh
sudo ./veepin serve sstp -shape 16384 ...
```

The filler goes in the PPP Information field, which RFC 1661 §5.1 explicitly
allows to be padded — the carried protocol distinguishes padding from data, and
IP does so with its Total Length. So **the client needs no support for it**; it
is verified in Docker against the `sstpc`/pppd reference client, whose ping replies could not come back from a
mis-trimmed packet.

Because the fingerprint it defends against targets handshakes, the budget is
spent per flow rather than per byte and bulk throughput is unaffected. It is off
by default and shapes the server's downstream direction only. See
[`doc/traffic-shaping.md`](../traffic-shaping.md) for what it does and does not
hide.
