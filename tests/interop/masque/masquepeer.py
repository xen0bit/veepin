#!/usr/bin/env python3
"""An independent MASQUE CONNECT-IP peer for the veepin interop harness.

Python and aioquic, deliberately: the point of this container is that the peer
shares no code, no language and no QUIC/HTTP-3 stack with veepin. veepin builds
its HTTP/3 layer from scratch on golang.org/x/net/quic; this peer uses aioquic's.
If veepin's varint, QPACK, capsule or CONNECT-IP framing drifts from RFC
9484/9297/9114, the ping across the tunnel stops crossing.

It speaks capsule mode (RFC 9297 §3.5): HTTP Datagrams travel as DATAGRAM
capsules on the request stream, because that is what veepin does -- x/net/quic
has no QUIC DATAGRAM frames. aioquic could use QUIC datagrams, but this peer
deliberately does not, so both ends meet in capsule mode.

Two roles:
  server  -- a CONNECT-IP proxy: assigns an address, advertises a route, relays.
  client  -- dials a proxy, takes the assigned address, brings up the TUN.
"""

import argparse
import asyncio
import fcntl
import os
import socket
import struct
import sys
import urllib.parse

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent


def log(msg):
    print(f"masquepeer: {msg}", flush=True)


# ---------------------------------------------------------------------------
# TUN device
# ---------------------------------------------------------------------------

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def open_tun(name):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd


def ip_dst(pkt):
    if not pkt:
        return None
    version = pkt[0] >> 4
    if version == 4 and len(pkt) >= 20:
        return ".".join(str(b) for b in pkt[16:20])
    return None


def ip_src(pkt):
    if not pkt:
        return None
    if pkt[0] >> 4 == 4 and len(pkt) >= 20:
        return ".".join(str(b) for b in pkt[12:16])
    return None


# ---------------------------------------------------------------------------
# QUIC varints and capsules (RFC 9000 §16, RFC 9297, RFC 9484)
# ---------------------------------------------------------------------------

CAPSULE_DATAGRAM = 0x00
CAPSULE_ADDRESS_ASSIGN = 0x01
CAPSULE_ADDRESS_REQUEST = 0x02
CAPSULE_ROUTE_ADVERTISEMENT = 0x03
CONTEXT_ID_PACKETS = 0x00


def put_varint(v):
    if v <= 63:
        return bytes([v])
    if v <= 16383:
        return bytes([(v >> 8) | 0x40, v & 0xFF])
    if v <= 1073741823:
        return bytes([(v >> 24) | 0x80, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])
    return bytes(
        [
            (v >> 56) | 0xC0,
            (v >> 48) & 0xFF,
            (v >> 40) & 0xFF,
            (v >> 32) & 0xFF,
            (v >> 24) & 0xFF,
            (v >> 16) & 0xFF,
            (v >> 8) & 0xFF,
            v & 0xFF,
        ]
    )


def get_varint(buf, off):
    """Return (value, new_offset) or (None, off) if incomplete."""
    if off >= len(buf):
        return None, off
    n = 1 << (buf[off] >> 6)
    if off + n > len(buf):
        return None, off
    v = buf[off] & 0x3F
    for i in range(1, n):
        v = (v << 8) | buf[off + i]
    return v, off + n


def encode_capsule(ctype, value):
    return put_varint(ctype) + put_varint(len(value)) + value


def parse_capsules(buf):
    """Yield (type, value) for complete capsules in buf; return leftover bytes."""
    out = []
    off = 0
    while off < len(buf):
        ctype, o1 = get_varint(buf, off)
        if ctype is None:
            break
        length, o2 = get_varint(buf, o1)
        if length is None or o2 + length > len(buf):
            break
        out.append((ctype, buf[o2 : o2 + length]))
        off = o2 + length
    return out, buf[off:]


def encode_datagram(ip_packet):
    return put_varint(CONTEXT_ID_PACKETS) + ip_packet


def decode_datagram(value):
    ctx, off = get_varint(value, 0)
    if ctx != CONTEXT_ID_PACKETS:
        return None
    return value[off:]


def encode_address(request_id, ip_str, prefix_len):
    octets = bytes(int(x) for x in ip_str.split("."))
    return put_varint(request_id) + bytes([4]) + octets + bytes([prefix_len])


def parse_addresses(value):
    out = []
    off = 0
    while off < len(value):
        req_id, off = get_varint(value, off)
        if req_id is None:
            break
        version = value[off]
        off += 1
        if version == 4:
            ip = ".".join(str(b) for b in value[off : off + 4])
            off += 4
        else:
            off += 16
            ip = None
        prefix = value[off]
        off += 1
        out.append((req_id, ip, prefix))
    return out


def encode_route_full():
    # IPv4, 0.0.0.0 .. 255.255.255.255, protocol 0 (all).
    return bytes([4]) + bytes([0, 0, 0, 0]) + bytes([255, 255, 255, 255]) + bytes([0])


# ---------------------------------------------------------------------------
# Common capsule/stream plumbing
# ---------------------------------------------------------------------------


def parse_udp_target(path):
    """Return (host, port) from /.well-known/masque/udp/{host}/{port}/ or None."""
    prefix = "/.well-known/masque/udp/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix) :].rstrip("/")
    parts = rest.split("/")
    if len(parts) != 2:
        return None
    host = urllib.parse.unquote(parts[0])
    if not host:
        return None
    try:
        port = int(parts[1])
    except ValueError:
        return None
    if not (1 <= port <= 65535):
        return None
    return host, port


class UDPRelay:
    """Bridges one CONNECT-UDP request stream to a connected UDP socket."""

    def __init__(self, protocol, h3, stream_id, sock):
        self.protocol = protocol
        self.h3 = h3
        self.stream_id = stream_id
        self.sock = sock
        self.buf = b""

    def send_capsule(self, ctype, value):
        self.h3.send_data(self.stream_id, encode_capsule(ctype, value), end_stream=False)
        self.protocol.transmit()

    def on_data(self, data):
        self.buf += data
        capsules, self.buf = parse_capsules(self.buf)
        for ctype, value in capsules:
            if ctype == CAPSULE_DATAGRAM:
                payload = decode_datagram(value)
                if payload is not None:
                    try:
                        self.sock.send(payload)
                    except OSError:
                        pass

    def on_socket_readable(self):
        try:
            payload = self.sock.recv(65535)
        except OSError:
            return
        self.send_capsule(CAPSULE_DATAGRAM, encode_datagram(payload))


class Tunnel:
    """Bridges one CONNECT-IP request stream to the TUN."""

    def __init__(self, protocol, h3, stream_id, tun_fd):
        self.protocol = protocol
        self.h3 = h3
        self.stream_id = stream_id
        self.tun_fd = tun_fd
        self.buf = b""

    def send_capsule(self, ctype, value):
        self.h3.send_data(self.stream_id, encode_capsule(ctype, value), end_stream=False)
        self.protocol.transmit()

    def on_data(self, data):
        self.buf += data
        capsules, self.buf = parse_capsules(self.buf)
        for ctype, value in capsules:
            self.handle_capsule(ctype, value)

    def handle_capsule(self, ctype, value):
        if ctype == CAPSULE_DATAGRAM:
            pkt = decode_datagram(value)
            if pkt:
                os.write(self.tun_fd, pkt)

    def send_packet(self, pkt):
        self.send_capsule(CAPSULE_DATAGRAM, encode_datagram(pkt))


# ---------------------------------------------------------------------------
# Server role
# ---------------------------------------------------------------------------


class ServerProtocol(QuicConnectionProtocol):
    tun_fd = None
    pool_base = None  # e.g. "10.31.0"
    next_host = 2
    # inner-IP -> Tunnel, shared across connections so the TUN reader can route.
    routes = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3 = None
        self._tunnels = {}  # stream_id -> Tunnel (CONNECT-IP)
        self._udp = {}      # stream_id -> UDPRelay (CONNECT-UDP)

    def quic_event_received(self, event: QuicEvent):
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for h3_event in self._h3.handle_event(event):
            self._on_h3(h3_event)

    def _on_h3(self, event):
        if isinstance(event, HeadersReceived):
            headers = {k: v for k, v in event.headers}
            method = headers.get(b":method", b"")
            protocol = headers.get(b":protocol", b"")
            path = headers.get(b":path", b"").decode()
            if method != b"CONNECT":
                self._reject(event.stream_id)
                return
            if protocol == b"connect-ip":
                self._accept(event.stream_id)
            elif protocol == b"connect-udp":
                self._accept_udp(event.stream_id, path)
            else:
                self._reject(event.stream_id)
        elif isinstance(event, DataReceived):
            relay = self._tunnels.get(event.stream_id) or self._udp.get(event.stream_id)
            if relay:
                relay.on_data(event.data)

    def _reject(self, stream_id):
        self._h3.send_headers(stream_id, [(b":status", b"400")], end_stream=True)
        self.transmit()

    def _accept_udp(self, stream_id, path):
        target = parse_udp_target(path)
        if target is None:
            self._reject(stream_id)
            return
        host, port = target
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((host, port))
        except OSError:
            self._h3.send_headers(stream_id, [(b":status", b"502")], end_stream=True)
            self.transmit()
            return
        sock.setblocking(False)

        self._h3.send_headers(
            stream_id,
            [(b":status", b"200"), (b"capsule-protocol", b"?1")],
            end_stream=False,
        )
        self.transmit()

        relay = UDPRelay(self, self._h3, stream_id, sock)
        self._udp[stream_id] = relay
        loop = asyncio.get_event_loop()
        loop.add_reader(sock.fileno(), relay.on_socket_readable)
        log(f"proxying UDP to {host}:{port} on stream {stream_id}")

    def _accept(self, stream_id):
        assigned = f"{ServerProtocol.pool_base}.{ServerProtocol.next_host}"
        ServerProtocol.next_host += 1

        self._h3.send_headers(
            stream_id,
            [(b":status", b"200"), (b"capsule-protocol", b"?1")],
            end_stream=False,
        )
        tun = Tunnel(self, self._h3, stream_id, ServerProtocol.tun_fd)
        self._tunnels[stream_id] = tun
        ServerProtocol.routes[assigned] = tun

        tun.send_capsule(CAPSULE_ROUTE_ADVERTISEMENT, encode_route_full())
        tun.send_capsule(CAPSULE_ADDRESS_ASSIGN, encode_address(0, assigned, 24))
        log(f"assigned {assigned} to stream {stream_id}")


def run_server(args):
    tun_fd = open_tun(args.tun)
    gateway = f"{args.pool_base}.1"
    os.system(f"ip addr add {gateway}/24 dev {args.tun}")
    os.system(f"ip link set {args.tun} up")
    os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1")

    ServerProtocol.tun_fd = tun_fd
    ServerProtocol.pool_base = args.pool_base

    def tun_reader():
        try:
            pkt = os.read(tun_fd, 65535)
        except OSError:
            return
        dst = ip_dst(pkt)
        tun = ServerProtocol.routes.get(dst)
        if tun:
            tun.send_packet(pkt)

    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    config.load_cert_chain(args.cert, args.key)

    async def main():
        loop = asyncio.get_event_loop()
        loop.add_reader(tun_fd, tun_reader)
        log(f"proxy listening on 0.0.0.0:{args.port}, gateway {gateway}")
        await serve("0.0.0.0", args.port, configuration=config, create_protocol=ServerProtocol)
        await asyncio.Future()

    asyncio.run(main())


# ---------------------------------------------------------------------------
# Client role
# ---------------------------------------------------------------------------


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3 = None
        self.tunnel = None
        self.tun_fd = None
        self.tun_name = None
        self.stream_id = None
        self.assigned_event = asyncio.Event()

    def quic_event_received(self, event: QuicEvent):
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for h3_event in self._h3.handle_event(event):
            self._on_h3(h3_event)

    def send_connect(self, authority):
        self.stream_id = self._quic.get_next_available_stream_id()
        self._h3.send_headers(
            self.stream_id,
            [
                (b":method", b"CONNECT"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", b"/.well-known/masque/ip/*/*/"),
                (b":protocol", b"connect-ip"),
                (b"capsule-protocol", b"?1"),
            ],
            end_stream=False,
        )
        self.tunnel = Tunnel(self, self._h3, self.stream_id, None)
        self.transmit()

    def _on_h3(self, event):
        if isinstance(event, HeadersReceived):
            headers = {k: v for k, v in event.headers}
            status = headers.get(b":status", b"")
            if status != b"200":
                log(f"proxy refused CONNECT: status {status!r}")
                return
            # Ask for an address with no preference.
            self.tunnel.send_capsule(CAPSULE_ADDRESS_REQUEST, encode_address(1, "0.0.0.0", 0))
        elif isinstance(event, DataReceived):
            self._client_data(event.data)

    def _client_data(self, data):
        self.tunnel.buf += data
        capsules, self.tunnel.buf = parse_capsules(self.tunnel.buf)
        for ctype, value in capsules:
            if ctype == CAPSULE_ADDRESS_ASSIGN and self.tun_fd is None:
                addrs = parse_addresses(value)
                if addrs:
                    _, ip, prefix = addrs[0]
                    self._bring_up(ip, prefix)
            elif ctype == CAPSULE_DATAGRAM and self.tun_fd is not None:
                pkt = decode_datagram(value)
                if pkt:
                    os.write(self.tun_fd, pkt)

    def _bring_up(self, ip, prefix):
        self.tun_fd = open_tun(self.tun_name)
        os.system(f"ip addr add {ip}/{prefix} dev {self.tun_name}")
        os.system(f"ip link set {self.tun_name} up")
        self.tunnel.tun_fd = self.tun_fd
        loop = asyncio.get_event_loop()
        loop.add_reader(self.tun_fd, self._tun_reader)
        log(f"tunnel up, assigned {ip}/{prefix} on {self.tun_name}")
        self.assigned_event.set()

    def _tun_reader(self):
        try:
            pkt = os.read(self.tun_fd, 65535)
        except OSError:
            return
        self.tunnel.send_packet(pkt)


class UDPForwardProtocol(QuicConnectionProtocol):
    """The aioquic CONNECT-UDP forwarder: a local socket relayed to one target."""

    target_host = None
    target_port = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3 = None
        self.local_sock = None
        self.flows = {}    # local src -> stream_id
        self.streams = {}  # stream_id -> local src
        self.buf = {}      # stream_id -> bytes

    def quic_event_received(self, event: QuicEvent):
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for h3_event in self._h3.handle_event(event):
            self._on_h3(h3_event)

    def _on_h3(self, event):
        if isinstance(event, DataReceived):
            src = self.streams.get(event.stream_id)
            if src is None:
                return
            self.buf[event.stream_id] = self.buf.get(event.stream_id, b"") + event.data
            capsules, self.buf[event.stream_id] = parse_capsules(self.buf[event.stream_id])
            for ctype, value in capsules:
                if ctype == CAPSULE_DATAGRAM:
                    payload = decode_datagram(value)
                    if payload is not None:
                        self.local_sock.sendto(payload, src)

    def on_local_datagram(self, data, src):
        stream_id = self.flows.get(src)
        if stream_id is None:
            stream_id = self._quic.get_next_available_stream_id()
            path = f"/.well-known/masque/udp/{self.target_host}/{self.target_port}/"
            self._h3.send_headers(
                stream_id,
                [
                    (b":method", b"CONNECT"),
                    (b":scheme", b"https"),
                    (b":authority", b"proxy"),
                    (b":path", path.encode()),
                    (b":protocol", b"connect-udp"),
                    (b"capsule-protocol", b"?1"),
                ],
                end_stream=False,
            )
            self.flows[src] = stream_id
            self.streams[stream_id] = src
            log(f"opened UDP flow for {src} -> {self.target_host}:{self.target_port}")
        self._h3.send_data(
            stream_id, encode_capsule(CAPSULE_DATAGRAM, encode_datagram(data)), end_stream=False
        )
        self.transmit()


def run_udp_client(args):
    host, _, port = args.target.rpartition(":")
    target_host, target_port = host, int(port)
    listen_host, _, listen_port = args.listen.rpartition(":")

    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    config.verify_mode = 0

    async def main():
        async with connect(
            args.server, args.port, configuration=config, create_protocol=UDPForwardProtocol
        ) as protocol:
            protocol.target_host = target_host
            protocol.target_port = target_port
            await protocol.wait_connected()

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((listen_host or "0.0.0.0", int(listen_port)))
            sock.setblocking(False)
            protocol.local_sock = sock

            def reader():
                try:
                    data, src = sock.recvfrom(65535)
                except OSError:
                    return
                protocol.on_local_datagram(data, src)

            asyncio.get_event_loop().add_reader(sock.fileno(), reader)
            log(f"forwarding {args.listen} -> {args.target} via {args.server}:{args.port}")
            await asyncio.Future()

    asyncio.run(main())


def run_client(args):
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    config.verify_mode = 0  # ssl.CERT_NONE: the proxy uses a throwaway cert

    async def main():
        async with connect(
            args.server, args.port, configuration=config, create_protocol=ClientProtocol
        ) as protocol:
            protocol.tun_name = args.tun
            await protocol.wait_connected()
            protocol.send_connect(args.authority or args.server)
            log(f"connected to {args.server}:{args.port}, sent CONNECT-IP")
            await asyncio.wait_for(protocol.assigned_event.wait(), timeout=30)
            await asyncio.Future()

    asyncio.run(main())


# ---------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)

    s = sub.add_parser("server")
    s.add_argument("--tun", default="masque0")
    s.add_argument("--port", type=int, default=443)
    s.add_argument("--pool-base", default="10.31.0")
    s.add_argument("--cert", required=True)
    s.add_argument("--key", required=True)

    c = sub.add_parser("client")
    c.add_argument("--tun", default="masque0")
    c.add_argument("--server", required=True)
    c.add_argument("--port", type=int, default=443)
    c.add_argument("--authority", default="")

    u = sub.add_parser("udp")
    u.add_argument("--server", required=True)
    u.add_argument("--port", type=int, default=443)
    u.add_argument("--listen", required=True, help="local host:port to bind")
    u.add_argument("--target", required=True, help="remote host:port to proxy to")

    args = ap.parse_args()
    if args.mode == "server":
        run_server(args)
    elif args.mode == "udp":
        run_udp_client(args)
    else:
        run_client(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
