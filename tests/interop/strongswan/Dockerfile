# strongSwan peer image for interop testing. Kernel-XFRM IPsec (no TUN needed),
# driven by swanctl. Config + entrypoint are bind-mounted by compose so they can
# be iterated without rebuilding.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strongswan strongswan-swanctl \
        libcharon-extra-plugins libstrongswan-standard-plugins \
        iproute2 iptables iputils-ping iperf3 tcpdump \
    && rm -rf /var/lib/apt/lists/*
CMD ["/bin/sh", "/entrypoint.sh"]
