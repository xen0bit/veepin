#!/bin/sh
# strongSwan responder entrypoint. Kernel-XFRM IPsec driven by swanctl.
set -e

# In-tunnel, pingable address on the strongSwan side (inside local_ts).
ip addr add 10.20.30.254/32 dev lo 2>/dev/null || true

# Start charon in the background, wait for its vici socket, then load config.
/usr/lib/ipsec/charon &
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
