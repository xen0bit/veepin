#!/bin/sh
# veepin AmneziaWG client for the interop harness. The obfuscation parameters
# must match the server's exactly; there is no negotiation, so a mismatch shows
# up as a handshake that never completes rather than as an error.
set -u

echo "veepin-awg-client: connecting to ${SERVER}:51820, tun ${CLIENT_TUN_IP}"

i=1
while [ "$i" -le 30 ]; do
    veepin connect amneziawg \
        -private-key "$CLIENT_PRIVATE" \
        -public-key "$SERVER_PUBLIC" \
        -preshared-key "$PSK" \
        -endpoint "${SERVER}:51820" \
        -address "${CLIENT_TUN_IP}/24" \
        -allowed-ips "${SERVER_TUN_IP}/32" \
        -type-init "$H1" -type-resp "$H2" -type-cookie "$H3" -type-trans "$H4" \
        -pad-init "$S1" -pad-resp "$S2" -pad-cookie "$S3" -pad-trans "$S4" \
        -junk-count "${JC:-0}" -junk-min "${JMIN:-0}" -junk-max "${JMAX:-0}" \
        -tun tun0 \
        -full-tunnel=false
    echo "veepin-awg-client: attempt $i failed; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

echo "veepin-awg-client: giving up after $((i - 1)) attempts"
exit 1
