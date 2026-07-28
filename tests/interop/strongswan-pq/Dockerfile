# strongSwan peer image for the post-quantum interop cells.
#
# Separate from ../strongswan deliberately. RFC 9370 additional key exchanges
# ("ke1_" proposal keywords) arrived in strongSwan 6.0, and ML-KEM comes from
# the openssl plugin built against OpenSSL 3.5+. Debian bookworm ships
# strongSwan 5.9, which does not know the keyword at all — it rejects the
# connection definition outright. Trixie ships 6.0.1 against OpenSSL 3.5.
#
# The other strongSwan cells stay on bookworm: they exercise nothing that needs
# 6.x, and moving every cell to a new base image to serve one feature would put
# five working directions at risk for no gain.
FROM debian:sid-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strongswan strongswan-swanctl strongswan-pki \
        libcharon-extra-plugins libstrongswan-standard-plugins \
        libcharon-extauth-plugins libstrongswan-extra-plugins \
        iproute2 iptables iputils-ping iperf3 tcpdump \
    && rm -rf /var/lib/apt/lists/*
CMD ["/bin/sh", "/entrypoint.sh"]
