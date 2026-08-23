#!/bin/sh
# libreswan initiator entrypoint. Starts pluto, then brings the connection up,
# retrying until the veepin server is reachable.
#
# TCP selects the transport, exactly as on the responder side: unset or "no"
# dials UDP 500/4500; "yes" makes pluto dial TCP 4500 instead (the conn carries
# `enable-tcp=tcp-only`, so there is no UDP to fall back to and a pass cannot be
# a silent fallback).
set -eu

# BLOCK_UDP is what turns the fallback cell from a claim into a test. libreswan
# will happily use UDP when UDP works, so a `enable-tcp=fallback` cell run
# without this passes on UDP and proves nothing about TCP at all.
if [ "${BLOCK_UDP:-no}" = "yes" ]; then
    iptables -A OUTPUT -p udp --dport 500 -j DROP
    iptables -A OUTPUT -p udp --dport 4500 -j DROP
    echo "libreswan-client: outbound UDP 500/4500 dropped; only TCP can carry this session"
fi

ipsec initnss >/dev/null 2>&1 || true

echo "libreswan-client: tcp=${TCP:-no}; starting pluto"
/usr/libexec/ipsec/pluto --config /etc/ipsec.conf --nofork --stderrlog \
    --secretsfile /etc/ipsec.secrets &
PLUTO=$!

i=0
while [ ! -S /run/pluto/pluto.ctl ]; do
    i=$((i + 1))
    [ "$i" -gt 120 ] && { echo "libreswan: control socket never appeared"; exit 1; }
    sleep 0.25
done

i=1
while [ "$i" -le 30 ]; do
    if ipsec up ss; then
        echo "libreswan-client: CHILD_SA established"
        break
    fi
    echo "libreswan-client: up attempt $i failed; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

wait "$PLUTO"
