# Reference OpenSSH client, new enough to speak a post-quantum key exchange.
#
# A SEPARATE image from ../ssh-client rather than a bump of it, following the
# strongswan-pq and sshd-pq precedent: the existing SSH cells keep their bookworm
# peer and their current results, and nothing else in the matrix is revalidated
# as a side effect of this one.
#
# Trixie for the same reason ../sshd-pq is: veepin's SSH reaches
# golang.org/x/crypto/ssh, whose only post-quantum key exchange is
# mlkem768x25519-sha256 -- it implements no sntrup761 at all. Bookworm's 9.2p1
# offers only sntrup761, so the two stacks share NO post-quantum mechanism there
# and the base cell silently settles on curve25519-sha256. Trixie's 10.0p2 has
# mlkem768x25519-sha256 and makes it the default.
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-client iproute2 iputils-ping iperf3 \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
