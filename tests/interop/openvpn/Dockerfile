# Reference OpenVPN server for the interop test.
FROM alpine:3.20
RUN apk add --no-cache openvpn
COPY server.conf /server.conf
COPY server-entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
