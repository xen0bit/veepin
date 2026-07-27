#!/bin/sh
# veepin IKEv2 server accepting EAP-MSCHAPv2, for the interop harness.
#
# The server still authenticates itself with the PSK (RFC 7296 §2.16 lets the
# responder authenticate normally while the initiator uses EAP); the client
# proves itself with a username and password instead, and the final AUTH on both
# sides is keyed by the EAP MSK.
#
# The credential file is written here rather than mounted so the cell carries its
# own fixture: username:password, one per line.
set -eu

PUB="${PUBLIC:-$(hostname -i | awk '{print $1}')}"
printf 'alice:wonderland\n' > /eap-users
chmod 600 /eap-users

echo "veepin-server: listen 0.0.0.0, public $PUB, id=$SERVER_ID pool=${POOL:-10.10.10.0/24}, EAP-MSCHAPv2 for alice"

exec veepin serve ikev2 \
    -listen 0.0.0.0 \
    -public "$PUB" \
    -psk "$PSK" \
    -id "$SERVER_ID" \
    -pool "${POOL:-10.10.10.0/24}" \
    -eap-users /eap-users \
    -tun tun0 \
    -setup-nat
