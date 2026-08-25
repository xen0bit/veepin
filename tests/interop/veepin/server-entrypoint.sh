#!/bin/sh
# veepin VPN server container entrypoint for the interop harness.
# -setup-nat brings up the TUN gateway address (pool .1) so a connected peer can
# ping it through the tunnel — that is the data-path assertion.
#
# LISTEN selects the outer transport family: 0.0.0.0 (default, IPv4) or :: (IPv6/
# dual-stack). PUBLIC overrides the advertised address (NAT detection); it
# defaults to the container's first address, which is IPv4.
#
# TCP additionally accepts RFC 8229/9329 TCP-encapsulated IKE and ESP on TCP
# 4500. It is additive, so the UDP cells are unaffected by a server that has it
# on -- which is what the fallback cell relies on.
#
# SHAPE is the per-flow downstream shaping budget in bytes (0, the default, is
# off). A non-zero value makes the server pad outbound ESP with RFC 4303 §2.7
# TFC padding, which the peer must tolerate — that is what the shaped cell
# proves.
#
# POOL6 is the internal IPv6 pool. It is passed explicitly rather than left to
# the flag's own default so the compose file and the ping target in the test
# name the same prefix; WAN names the interface -setup-nat masquerades behind,
# which the dual-stack cell needs because the v6 MASQUERADE rule is half of what
# that cell exists to check.
set -eu

LISTEN="${LISTEN:-0.0.0.0}"
SHAPE="${SHAPE:-0}"
# On a dual-stack compose network `hostname -i` may list the v6 address first,
# and PUBLIC is the address NAT detection hashes -- it has to be the IPv4 one
# the ESP transport actually uses. Pick the first dotted-quad rather than the
# first field.
PUB="${PUBLIC:-$(hostname -i | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -1)}"
echo "veepin-server: listen $LISTEN, public $PUB, id=$SERVER_ID pool=${POOL:-10.10.10.0/24} pool6=${POOL6:-default} wan=${WAN:-none} shape=$SHAPE"

set -- \
    -listen "$LISTEN" \
    -public "$PUB" \
    -psk "$PSK" \
    -id "$SERVER_ID" \
    -pool "${POOL:-10.10.10.0/24}" \
    -tun tun0 \
    -shape "$SHAPE" \
    -iptfs="${IPTFS:-false}" \
    -tcp="${TCP:-false}" \
    -setup-nat
# `if` rather than `[ ... ] && ...`: under `set -e` a false test makes the whole
# AND-list the script's last status and kills it, so the v4-only cells would die
# here on the line that is supposed to skip them.
if [ -n "${POOL6:-}" ]; then
    set -- "$@" -pool6 "$POOL6"
fi
if [ -n "${WAN:-}" ]; then
    set -- "$@" -wan "$WAN"
fi

# PROTOCOL selects ikev2 or its post-quantum variant pq-ikev2. The variant takes
# byte-for-byte the same flags, which is exactly why one entrypoint can serve
# both -- a second script here would be the duplication the variant scheme is
# built to avoid.
exec veepin serve "${PROTOCOL:-ikev2}" "$@"
