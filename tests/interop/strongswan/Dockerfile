# strongSwan peer image for interop testing. Kernel-XFRM IPsec (no TUN needed),
# driven by swanctl. Config + entrypoint are bind-mounted by compose so they can
# be iterated without rebuilding.
#
# libcharon-extauth-plugins is what carries eap-mschapv2 on Debian —
# libcharon-extra-plugins ships eap-aka/gtc/md5/radius/tls/ttls but not that one.
# Without it strongSwan answers the server's EAP request with an EAP_NAK reading
# "EAP method not supported", which looks like a veepin failure and is not.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strongswan strongswan-swanctl strongswan-pki \
        libcharon-extra-plugins libstrongswan-standard-plugins \
        libcharon-extauth-plugins \
        iproute2 iptables iputils-ping iperf3 tcpdump \
    && rm -rf /var/lib/apt/lists/*
CMD ["/bin/sh", "/entrypoint.sh"]
