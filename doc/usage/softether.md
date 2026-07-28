# SoftEther VPN (SE-VPN)

veepin's SoftEther implementation provides Ethernet-over-TLS (layer-2) VPN
connectivity, interoperating with the SoftEther VPN Server and VPN Client.

## Server

```sh
veepin serve softether -cert /path/to/cert.pem -key /path/to/key.pem \
    -user alice -pass secret
```

Required flags:
- `-cert`, `-key`: TLS certificate and key (PEM).
- `-user`, `-pass`: accepted username and password.

Optional flags:
- `-listen`: local IP to bind (default `0.0.0.0`).
- `-port`: TLS port (default `443`).
- `-pool`: address pool CIDR (default `10.70.0.0/24`).
- `-tun`: TAP interface name (empty = kernel picks).

## Client

```sh
veepin connect softether -server vpn.example.com -user alice -pass secret
```

Required flags:
- `-server`: gateway hostname or IP.
- `-user`, `-pass`: credentials matching the server.

Optional flags:
- `-port`: gateway port (default `443`).
- `-hub`: virtual hub name (default `VPN`).
- `-tun`: TAP interface name (empty = kernel picks).

## Interoperability

veepin ↔ SoftEther VPN Server: verified (see interop matrix).
SoftEther VPN Client ↔ veepin: verified.
