#!/bin/sh
# veepin nebula host for the interop harness.
#
# Nebula has no client and no server, so both roles in this matrix run the same
# command; -am-lighthouse is the only thing that differs. The certificate this
# host presents was issued by the reference nebula-cert, and the address it uses
# is the one written into that certificate -- veepin does not choose it.
#
# `veepin connect` blocks once the host is running. Unlike the point-to-point
# protocols there is no peer whose reachability makes a useful readiness signal,
# so a failure here means the host itself would not start; retry in case the PKI
# volume was still being written.
set -u

PKI=/pki
until [ -f "$PKI/ready" ]; do
    echo "veepin-nebula: waiting for the PKI"
    sleep 1
done

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

lighthouse_flag=""
if [ -n "${LIGHTHOUSES:-}" ]; then
    lighthouse_flag="-lighthouses ${LIGHTHOUSES}"
fi
am_lighthouse_flag=""
if [ "${AM_LIGHTHOUSE:-false}" = "true" ]; then
    am_lighthouse_flag="-am-lighthouse"
fi
static_flag=""
if [ -n "${STATIC_HOSTS:-}" ]; then
    static_flag="-static-hosts ${STATIC_HOSTS}"
fi
relays_flag=""
if [ -n "${RELAYS:-}" ]; then
    relays_flag="-relays ${RELAYS}"
fi
relay_for_flag=""
if [ "${RELAY_FOR:-false}" = "true" ]; then
    relay_for_flag="-relay-for"
fi

# Block the direct path to a named peer, so a relay is the only way through.
#
# Dropping rather than rejecting is deliberate: an ICMP unreachable would tell
# the sender at once, and what a real symmetric NAT does is swallow the packet.
# The cell is meant to reproduce the situation relays exist for, not a
# convenient version of it.
if [ -n "${BLOCK_DIRECT:-}" ]; then
    for host in ${BLOCK_DIRECT}; do
        for ip in $(getent ahostsv4 "$host" | awk '{print $1}' | sort -u); do
            iptables -A INPUT -s "$ip" -p udp -j DROP
            iptables -A OUTPUT -d "$ip" -p udp -j DROP
            echo "veepin-nebula: blocked direct UDP with $host ($ip)"
        done
    done
fi

echo "veepin-nebula: starting ${NAME} (lighthouse=${AM_LIGHTHOUSE:-false})"

i=1
while [ "$i" -le 30 ]; do
    # shellcheck disable=SC2086
    veepin connect nebula \
        -ca "$PKI/ca.crt" \
        -cert "$PKI/${NAME}.crt" \
        -key "$PKI/${NAME}.key" \
        -listen "0.0.0.0:${PORT:-4242}" \
        $static_flag \
        $lighthouse_flag \
        $am_lighthouse_flag \
        $relays_flag \
        $relay_for_flag \
        -tun nebula1 \
        -full-tunnel=false
    echo "veepin-nebula: attempt $i ended; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

echo "veepin-nebula: giving up after $((i - 1)) attempts"
exit 1
