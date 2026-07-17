#!/bin/sh
# Reference SSTP client: sstpc drives pppd over the SSTP tunnel to the veepin
# server. --cert-warn accepts the server's self-signed certificate (as the veepin
# client's -insecure does); MS-CHAPv2 and the crypto binding are the real
# authentication. It retries until the server answers.
set -u
[ -c /dev/ppp ] || mknod /dev/ppp c 108 0
echo "sstpuser * sstppass *" > /etc/ppp/chap-secrets

i=1
while [ "$i" -le 40 ]; do
    echo "sstp-client: connecting to ${SERVER:-veepin-sstp-server} (attempt $i)"
    sstpc --log-stderr --cert-warn \
        --user "${USER:-sstpuser}" --password "${PASS:-sstppass}" \
        "${SERVER:-veepin-sstp-server}" \
        require-mschap-v2 refuse-eap refuse-pap refuse-chap refuse-mschap \
        noauth noipdefault usepeerdns nodefaultroute nodetach
    echo "sstp-client: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
