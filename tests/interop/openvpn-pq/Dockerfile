# Reference OpenVPN, new enough to speak both halves of the post-quantum
# contract: ML-KEM key exchange and ML-DSA certificates.
#
# A SEPARATE image from ../openvpn rather than a bump of it, following the
# strongswan-pq and sshd-pq precedent: the four existing OpenVPN profile cells
# keep their alpine peer and their current results, and nothing else in the
# matrix is revalidated as a side effect of this one.
#
# Trixie because the version of OpenSSL matters more than the version of
# OpenVPN. ML-DSA and ML-KEM arrived in OpenSSL 3.5; ../openvpn is alpine:3.20,
# whose OpenSSL is 3.3 and which therefore has neither. Measured in each image
# on 2026-08-25:
#
#   alpine 3.20   OpenSSL 3.3.x   no ML-DSA, no ML-KEM group
#   trixie        OpenSSL 3.5.7   ML-DSA-44/65/87, X25519MLKEM768, MLKEM512/768/1024
#
# And measured end to end rather than inferred from the algorithm list -- whether
# OpenVPN's own certificate handling and key-type checks accept an ML-DSA leaf is
# a separate question from whether the library can, and doc/pq-variants-plan.md
# §8 scoped it as a survey with a real chance of "no". It answered yes:
#
#   Control Channel: TLSv1.3, cipher TLS_AES_256_GCM_SHA384,
#     peer certificate: 15616 bits ML-DSA-65, signature: id-ml-dsa-65,
#     peer temporary key: 768 bits X25519MLKEM768
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openvpn openssl iproute2 iputils-ping iperf3 \
    && rm -rf /var/lib/apt/lists/*
COPY server-pq.conf /server-pq.conf
COPY client-pq.conf /client-pq.conf
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
