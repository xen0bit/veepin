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
