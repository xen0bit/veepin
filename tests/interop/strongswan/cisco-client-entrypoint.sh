#!/bin/sh
# strongSwan Cisco IPsec initiator entrypoint (here -> veepin serve cisco).
# Starts charon, loads config, and initiates the SA, retrying until the gateway
# is reachable. See cisco-server-entrypoint.sh for the aggressive-mode option.
set -e

mkdir -p /etc/strongswan.d
cat > /etc/strongswan.d/aggressive.conf <<'CONF'
charon {
    i_dont_care_about_security_and_use_aggressive_mode_psk = yes
}
CONF

/usr/lib/ipsec/charon &
CHARON=$!

i=0
while [ ! -S /run/charon.vici ] && [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))
    [ "$i" -gt 80 ] && { echo "strongswan: vici socket never appeared"; exit 1; }
    sleep 0.25
done

swanctl --load-all
echo "strongswan-cisco-client: config loaded; initiating to veepin-cisco-server"

i=1
while [ "$i" -le 30 ]; do
    if swanctl --initiate --child ra; then
        echo "strongswan-cisco-client: CHILD_SA established"
        break
    fi
    echo "strongswan-cisco-client: initiate attempt $i failed; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

wait "$CHARON"
