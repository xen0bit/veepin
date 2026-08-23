# libreswan peer image for interop testing. Kernel-XFRM IPsec (no TUN needed),
# driven by ipsec.conf. Config + entrypoints are bind-mounted by compose so they
# can be iterated without rebuilding.
#
# libreswan is the whole reason this image exists: it is the only open-source
# implementation of RFC 8229/9329 TCP encapsulation in either role ("It was
# ensured that the MUSTs in the RFC are implemented, so that Libreswan could be
# used as a client or a server"), and strongSwan implements none of it.
#
# alpine:3.22, not 3.20. `doc/protocol-roadmap.md` costed this image against
# 3.20's libreswan 5.0, and 5.0 does install -- but its `addconn` segfaults on
# musl before reading a single connection, on a config file containing nothing
# but `config setup`. Nothing can be loaded, so pluto listens and answers
# nothing, which reads as veepin failing to interoperate. 3.22 carries 5.2 and
# is the oldest release here that parses a config at all.
FROM alpine:3.22
RUN apk add --no-cache libreswan iproute2 iptables ip6tables iputils tcpdump
CMD ["/bin/sh", "/entrypoint.sh"]
