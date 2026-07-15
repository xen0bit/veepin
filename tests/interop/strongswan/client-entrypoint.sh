#!/bin/sh
# strongSwan initiator entrypoint (Direction B). Starts charon, loads config,
# and initiates the SA to the ikennkt server, retrying until it is reachable.
set -e

/usr/lib/ipsec/charon &
CHARON=$!

i=0
while [ ! -S /run/charon.vici ] && [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))
    [ "$i" -gt 80 ] && { echo "strongswan: vici socket never appeared"; exit 1; }
    sleep 0.25
done

swanctl --load-all
echo "strongswan-client: config loaded; initiating to ikennkt-server"

i=1
while [ "$i" -le 30 ]; do
    if swanctl --initiate --child ss; then
        echo "strongswan-client: CHILD_SA established"
        break
    fi
    echo "strongswan-client: initiate attempt $i failed; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

wait "$CHARON"
