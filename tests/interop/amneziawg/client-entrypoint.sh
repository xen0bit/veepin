#!/bin/sh
# Reference AmneziaWG initiator, dialling the veepin server. awg-quick brings the
# interface up and the tunnel lives in amneziawg-go, so this shell just holds.
set -eu

export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
# amneziawg-go reads LOG_LEVEL; verbose is what makes a rejected datagram visible.
export LOG_LEVEL="${LOG_LEVEL:-verbose}"

mkdir -p /etc/amnezia/amneziawg

cat > /etc/amnezia/amneziawg/awg0.conf <<CONF
[Interface]
Address = ${CLIENT_TUN_IP}/24
PrivateKey = ${CLIENT_PRIVATE}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}

[Peer]
PublicKey = ${SERVER_PUBLIC}
PresharedKey = ${PSK}
Endpoint = ${SERVER}:51820
AllowedIPs = ${SERVER_TUN_IP}/32
PersistentKeepalive = 15
CONF

echo "awg-client: awg0 (${CLIENT_TUN_IP}) -> ${SERVER}:51820"
awg-quick up awg0
awg show

echo "awg-client: ready, holding the tunnel open"
while true; do sleep 3600; done
