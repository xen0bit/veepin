# Reference OpenSSH server, new enough to speak a post-quantum key exchange.
#
# It is a SEPARATE image from ../sshd rather than a bump of it, following the
# strongswan-pq precedent: the existing SSH cells keep their bookworm peer and
# their current results, and nothing in the rest of the matrix is revalidated as
# a side effect of this one.
#
# The base has to be trixie, and the reason is specific. veepin's SSH reaches
# golang.org/x/crypto/ssh, whose ONLY post-quantum key exchange is
# mlkem768x25519-sha256 -- it implements no sntrup761 at all. OpenSSH gained that
# same name in 9.9 and made it the default in 10.0. Bookworm ships 9.2p1, whose
# only PQ kex is sntrup761x25519-sha512@openssh.com, so the two stacks have NO
# post-quantum mechanism in common there and the base ssh cell silently settles
# on curve25519-sha256. Trixie ships 10.0p2, which does.
#
# Measured rather than assumed, with `ssh -Q kex` in each image:
#   bookworm 9.2p1   sntrup761x25519-sha512  sntrup761x25519-sha512@openssh.com
#   trixie  10.0p2   sntrup761...  mlkem768x25519-sha256
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server iproute2 iputils-ping iperf3 \
    && rm -rf /var/lib/apt/lists/*
COPY sshd_config /etc/ssh/sshd_config.d/tunnel.conf
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
