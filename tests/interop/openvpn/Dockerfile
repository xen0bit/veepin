# Reference OpenVPN server for the interop tests. One image serves every profile
# variant; the entrypoint picks a config via SERVER_CONF.
FROM alpine:3.20
RUN apk add --no-cache openvpn iperf3
COPY server.conf /server.conf
COPY server-tls-auth.conf /server-tls-auth.conf
COPY server-tls-crypt.conf /server-tls-crypt.conf
COPY server-cbc.conf /server-cbc.conf
COPY server-entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
