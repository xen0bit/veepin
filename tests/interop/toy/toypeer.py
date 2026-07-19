#!/usr/bin/env python3
"""An independent implementation of TOY v1, for the veepin interop harness.

This shares no code with veepin. It was written from internal/toy/SPEC.md, and
that is the whole point of it: a protocol whose spec is only readable by its own
implementation is not specified at all. If veepin's framing, key derivation,
keystream, tag or handshake ever drift from the document, this stops
interoperating and the interop cells fail.

TOY PROVIDES NO SECURITY. See SPEC.md. This file implements a deliberately
broken protocol on purpose; nothing here should be copied into anything real.

Usage:
    toypeer.py server --listen 0.0.0.0:5555 --user alice --secret s3cret \\
                      --tun toy0 --pool-base 10.9.0 --gateway 10.9.0.1
    toypeer.py client --server host:5555 --user alice --secret s3cret --tun toy0
"""

import argparse
import fcntl
import os
import secrets
import select
import socket
import struct
import sys
import time

# ---------------------------------------------------------------------------
# Wire constants (SPEC.md "Header", "Message types")
# ---------------------------------------------------------------------------

MAGIC = b"TOY"
VERSION = 1
HEADER_LEN = 12
NONCE_LEN = 8
TAG_LEN = 8
KEY_LEN = 32

MSG_HELLO = 0x01
MSG_CHALLENGE = 0x02
MSG_AUTH = 0x03
MSG_WELCOME = 0x04
MSG_REJECT = 0x05
MSG_DATA = 0x06
MSG_KEEPALIVE = 0x07
MSG_BYE = 0x08

NAMES = {
    MSG_HELLO: "HELLO", MSG_CHALLENGE: "CHALLENGE", MSG_AUTH: "AUTH",
    MSG_WELCOME: "WELCOME", MSG_REJECT: "REJECT", MSG_DATA: "DATA",
    MSG_KEEPALIVE: "KEEPALIVE", MSG_BYE: "BYE",
}

KEEPALIVE_INTERVAL = 15.0
REPLAY_WINDOW = 64

# ---------------------------------------------------------------------------
# The "cryptography" (SPEC.md "The digest" onwards)
# ---------------------------------------------------------------------------

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = (1 << 64) - 1


def digest(*parts):
    """FNV-1a/64 over the concatenation of parts, as 8 big-endian octets."""
    h = FNV_OFFSET
    for p in parts:
        for b in p:
            h ^= b
            h = (h * FNV_PRIME) & MASK64
    return h.to_bytes(8, "big")


def derive_key(secret, client_nonce, server_nonce):
    seed = secret.encode() + client_nonce + server_nonce
    return b"".join(digest(seed, bytes([i])) for i in range(4))


def make_proof(secret, client_nonce, server_nonce):
    return digest(secret.encode(), client_nonce, server_nonce, b"toy-auth")


def keystream(key, counter, buf):
    """XOR buf with the keystream. Its own inverse, per SPEC.md."""
    out = bytearray(len(buf))
    for i, b in enumerate(buf):
        pad = key[(i + counter) % KEY_LEN] ^ ((counter >> (8 * (i % 4))) & 0xFF)
        out[i] = b ^ pad
    return bytes(out)


def make_tag(key, header, ciphertext):
    return digest(key, header, ciphertext)


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------


def pack_header(msg_type, session, counter, flags=0):
    return MAGIC + bytes([VERSION, msg_type, flags]) + struct.pack("!HI", session, counter)


def parse_header(pkt):
    """Return (type, flags, session, counter, body) or None if not TOY v1."""
    if len(pkt) < HEADER_LEN:
        return None
    if pkt[0:3] != MAGIC or pkt[3] != VERSION:
        return None
    msg_type, flags = pkt[4], pkt[5]
    session, counter = struct.unpack("!HI", pkt[6:12])
    return msg_type, flags, session, counter, pkt[HEADER_LEN:]


class Session:
    """One established tunnel, with its counters and replay window."""

    def __init__(self, session_id, key, peer):
        self.id = session_id
        self.key = key
        self.peer = peer
        self.counter = 2  # counters 1 and 2 belonged to the handshake
        self.highest = 0
        self.seen = [False] * REPLAY_WINDOW
        self.last_seen = time.time()

    def seal(self, msg_type, payload):
        self.counter += 1
        header = pack_header(msg_type, self.id, self.counter)
        ct = keystream(self.key, self.counter, payload)
        return header + make_tag(self.key, header, ct) + ct

    def open(self, pkt):
        """Verify and unseal. Returns (type, plaintext) or None."""
        parsed = parse_header(pkt)
        if parsed is None:
            return None
        msg_type, _flags, _session, counter, body = parsed
        if msg_type not in (MSG_DATA, MSG_KEEPALIVE) or len(body) < TAG_LEN:
            return None

        tag, ct = body[:TAG_LEN], body[TAG_LEN:]
        # Verify before touching the replay window: an unauthenticated counter
        # must never be able to advance it (SPEC.md "Anti-replay").
        if make_tag(self.key, pkt[:HEADER_LEN], ct) != tag:
            return None
        if not self._accept(counter):
            return None

        self.last_seen = time.time()
        return msg_type, keystream(self.key, counter, ct)

    def _accept(self, counter):
        if counter > self.highest:
            gap = counter - self.highest
            if gap >= REPLAY_WINDOW:
                self.seen = [False] * REPLAY_WINDOW
            else:
                for i in range(self.highest + 1, counter + 1):
                    self.seen[i % REPLAY_WINDOW] = False
            self.seen[counter % REPLAY_WINDOW] = True
            self.highest = counter
            return True
        if self.highest - counter >= REPLAY_WINDOW:
            return False
        if self.seen[counter % REPLAY_WINDOW]:
            return False
        self.seen[counter % REPLAY_WINDOW] = True
        return True


# ---------------------------------------------------------------------------
# TUN
# ---------------------------------------------------------------------------

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def open_tun(name):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH22s", name.encode(), IFF_TUN | IFF_NO_PI, b"")
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd


def log(*args):
    print("toypeer:", *args, flush=True)


def parse_hostport(s, default_port):
    if ":" in s:
        host, port = s.rsplit(":", 1)
        return host, int(port)
    return s, default_port


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


def run_client(args):
    host, port = parse_hostport(args.server, 5555)
    server = (socket.gethostbyname(host), port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)

    client_nonce = secrets.token_bytes(NONCE_LEN)
    user = args.user.encode()
    hello = pack_header(MSG_HELLO, 0, 1) + client_nonce + bytes([len(user)]) + user

    session_id = None
    server_nonce = None
    for attempt in range(1, 31):
        sock.sendto(hello, server)
        try:
            pkt, _ = sock.recvfrom(65535)
        except socket.timeout:
            log(f"no CHALLENGE (attempt {attempt}); resending HELLO")
            continue
        parsed = parse_header(pkt)
        if parsed is None:
            continue
        msg_type, _f, session_id, _c, body = parsed
        if msg_type == MSG_REJECT:
            reason = body[1:1 + body[0]].decode(errors="replace") if body else ""
            log(f"server rejected the session: {reason}")
            return 1
        if msg_type == MSG_CHALLENGE and len(body) >= NONCE_LEN:
            server_nonce = body[:NONCE_LEN]
            break
    if server_nonce is None:
        log("no CHALLENGE after 30 attempts")
        return 1

    key = derive_key(args.secret, client_nonce, server_nonce)
    auth = pack_header(MSG_AUTH, session_id, 2) + make_proof(args.secret, client_nonce, server_nonce)

    welcome = None
    for attempt in range(1, 31):
        sock.sendto(auth, server)
        try:
            pkt, _ = sock.recvfrom(65535)
        except socket.timeout:
            log(f"no WELCOME (attempt {attempt}); resending AUTH")
            continue
        parsed = parse_header(pkt)
        if parsed is None:
            continue
        msg_type, _f, _s, _c, body = parsed
        if msg_type == MSG_REJECT:
            reason = body[1:1 + body[0]].decode(errors="replace") if body else ""
            log(f"server rejected the session: {reason}")
            return 1
        if msg_type == MSG_WELCOME and len(body) >= 15:
            welcome = body
            break
    if welcome is None:
        log("no WELCOME after 30 attempts")
        return 1

    assigned = socket.inet_ntoa(welcome[0:4])
    netmask = socket.inet_ntoa(welcome[4:8])
    gateway = socket.inet_ntoa(welcome[8:12])
    mtu = struct.unpack("!H", welcome[12:14])[0]
    log(f"session {session_id}: assigned {assigned}/{netmask} gw {gateway} mtu {mtu}")

    # Bring the interface up. veepin's own client deliberately does not do this
    # -- it returns the config and lets the caller apply it -- but this peer is
    # a standalone program, so it applies it itself.
    tun_fd = open_tun(args.tun)
    prefix = sum(bin(int(o)).count("1") for o in netmask.split("."))
    os.system(f"ip addr add {assigned}/{prefix} dev {args.tun}")
    os.system(f"ip link set {args.tun} mtu {mtu} up")

    session = Session(session_id, key, server)
    return pump(sock, tun_fd, {session_id: session}, is_server=False)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


def run_server(args):
    host, port = parse_hostport(args.listen, 5555)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))

    tun_fd = open_tun(args.tun)
    os.system(f"ip addr add {args.gateway}/24 dev {args.tun}")
    os.system(f"ip link set {args.tun} mtu 1400 up")
    log(f"listening on {host}:{port}, gateway {args.gateway}")

    pending = {}    # session id -> (client_nonce, server_nonce, addr, assigned)
    sessions = {}   # session id -> Session
    routes = {}     # assigned ip -> session id
    next_host = 10  # simplest possible pool: .10 upwards

    def handle(pkt, addr):
        nonlocal next_host
        parsed = parse_header(pkt)
        if parsed is None:
            return
        msg_type, _flags, session_id, _counter, body = parsed

        if msg_type == MSG_HELLO:
            if len(body) < NONCE_LEN + 1:
                return
            client_nonce = body[:NONCE_LEN]
            ulen = body[NONCE_LEN]
            user = body[NONCE_LEN + 1:NONCE_LEN + 1 + ulen].decode(errors="replace")
            if user != args.user:
                reason = b"unknown user"
                sock.sendto(pack_header(MSG_REJECT, 0, 1) + bytes([len(reason)]) + reason, addr)
                log(f"HELLO from {addr} for unknown user {user!r}")
                return

            # A repeated HELLO must not start a second handshake (SPEC.md,
            # "Handling retransmission and forgery"): the client nonce
            # identifies the attempt, so a repeat replays the same CHALLENGE.
            for existing_sid, (cn, sn, _a, _ip) in pending.items():
                if cn == client_nonce:
                    sock.sendto(pack_header(MSG_CHALLENGE, existing_sid, 1) + sn, addr)
                    return

            sid = secrets.randbelow(65535) + 1
            server_nonce = secrets.token_bytes(NONCE_LEN)
            assigned = f"{args.pool_base}.{next_host}"
            next_host += 1
            pending[sid] = (client_nonce, server_nonce, addr, assigned)
            sock.sendto(pack_header(MSG_CHALLENGE, sid, 1) + server_nonce, addr)
            log(f"session {sid}: CHALLENGE to {user!r} at {addr}, will assign {assigned}")
            return

        if msg_type == MSG_AUTH:
            if session_id not in pending or len(body) < TAG_LEN:
                return
            client_nonce, server_nonce, _addr, assigned = pending[session_id]
            if body[:TAG_LEN] != make_proof(args.secret, client_nonce, server_nonce):
                # The pending handshake is deliberately left in place: session
                # IDs are public, so discarding it here would let one forged
                # AUTH cancel a legitimate client (SPEC.md, "Handling
                # retransmission and forgery").
                reason = b"authentication failed"
                sock.sendto(pack_header(MSG_REJECT, session_id, 1) + bytes([len(reason)]) + reason, addr)
                log(f"session {session_id}: authentication failed")
                return
            del pending[session_id]

            key = derive_key(args.secret, client_nonce, server_nonce)
            sessions[session_id] = Session(session_id, key, addr)
            routes[assigned] = session_id

            welcome = (socket.inet_aton(assigned)
                       + socket.inet_aton("255.255.255.0")
                       + socket.inet_aton(args.gateway)
                       + struct.pack("!H", 1400)
                       + bytes([0]))
            sock.sendto(pack_header(MSG_WELCOME, session_id, 2) + welcome, addr)
            log(f"session {session_id}: established, assigned {assigned}")
            return

        if msg_type in (MSG_DATA, MSG_KEEPALIVE):
            session = sessions.get(session_id)
            if session is None:
                return
            opened = session.open(pkt)
            if opened is None:
                return
            kind, inner = opened
            # Follow a roaming peer, but only once the packet has authenticated.
            if session.peer != addr:
                log(f"session {session_id} roamed to {addr}")
                session.peer = addr
            if kind == MSG_DATA and inner:
                os.write(tun_fd, inner)
            return

        if msg_type == MSG_BYE:
            # Unauthenticated, so advisory only.
            log(f"session {session_id} sent BYE (advisory; ignoring)")

    return pump(sock, tun_fd, sessions, is_server=True, handle=handle, routes=routes)


# ---------------------------------------------------------------------------
# Shared data path
# ---------------------------------------------------------------------------


def pump(sock, tun_fd, sessions, is_server, handle=None, routes=None):
    """Carry packets between the TUN and the socket until interrupted."""
    sock.settimeout(None)
    last_keepalive = time.time()

    while True:
        try:
            readable, _, _ = select.select([sock, tun_fd], [], [], 1.0)
        except KeyboardInterrupt:
            return 0

        for r in readable:
            if r is sock:
                pkt, addr = sock.recvfrom(65535)
                if handle is not None:
                    handle(pkt, addr)
                    continue
                # Client: exactly one session.
                session = next(iter(sessions.values()))
                opened = session.open(pkt)
                if opened is None:
                    continue
                kind, inner = opened
                if kind == MSG_DATA and inner:
                    os.write(tun_fd, inner)
            else:
                inner = os.read(tun_fd, 65535)
                if len(inner) < 20 or (inner[0] >> 4) != 4:
                    continue  # IPv4 only
                if is_server:
                    dst = socket.inet_ntoa(inner[16:20])
                    sid = routes.get(dst)
                    if sid is None or sid not in sessions:
                        continue
                    session = sessions[sid]
                else:
                    if not sessions:
                        continue
                    session = next(iter(sessions.values()))
                sock.sendto(session.seal(MSG_DATA, inner), session.peer)

        now = time.time()
        if not is_server and now - last_keepalive >= KEEPALIVE_INTERVAL:
            last_keepalive = now
            for session in sessions.values():
                sock.sendto(session.seal(MSG_KEEPALIVE, b""), session.peer)


def main():
    ap = argparse.ArgumentParser(description="Independent TOY v1 implementation")
    sub = ap.add_subparsers(dest="mode", required=True)

    c = sub.add_parser("client")
    c.add_argument("--server", required=True)
    c.add_argument("--user", required=True)
    c.add_argument("--secret", required=True)
    c.add_argument("--tun", default="toy0")

    s = sub.add_parser("server")
    s.add_argument("--listen", default="0.0.0.0:5555")
    s.add_argument("--user", required=True)
    s.add_argument("--secret", required=True)
    s.add_argument("--tun", default="toy0")
    s.add_argument("--pool-base", default="10.9.0")
    s.add_argument("--gateway", default="10.9.0.1")

    args = ap.parse_args()
    log("TOY PROVIDES NO SECURITY. This is an example protocol; see SPEC.md.")
    if args.mode == "client":
        return run_client(args)
    return run_server(args)


if __name__ == "__main__":
    sys.exit(main())
