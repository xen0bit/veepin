# Reference L2TP/IPsec client for the interop tests: strongSwan as the IKEv1
# initiator and xl2tpd as the LAC, driving pppd — the same pair a Linux desktop
# uses to dial an L2TP/IPsec VPN. Config and entrypoint are bind-mounted by
# compose so they can be iterated without a rebuild.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strongswan strongswan-swanctl \
        libcharon-extra-plugins libstrongswan-standard-plugins \
        xl2tpd ppp \
        iproute2 iptables iputils-ping iperf3 tcpdump procps \
    && rm -rf /var/lib/apt/lists/*
CMD ["/bin/sh", "/entrypoint.sh"]
