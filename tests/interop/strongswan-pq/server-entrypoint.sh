#!/bin/sh
# strongSwan 6 responder entrypoint for the post-quantum cell.
#
# Separate from ../strongswan/server-entrypoint.sh only because strongSwan 6
# renamed the daemon: bookworm's 5.9 ships /usr/lib/ipsec/charon, trixie's 6.0
# ships /usr/sbin/charon-systemd. Everything else is identical.
set -e

# In-tunnel, pingable address on the strongSwan side (inside local_ts).
ip addr add 10.20.30.254/32 dev lo 2>/dev/null || true

/usr/sbin/charon-systemd &
CHARON=$!

i=0
while [ ! -S /run/charon.vici ] && [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))
    [ "$i" -gt 80 ] && { echo "strongswan: vici socket never appeared"; exit 1; }
    sleep 0.25
done

swanctl --load-all
echo "strongswan-server: config loaded; ready as responder (id=vpn.example.com)"

wait "$CHARON"
