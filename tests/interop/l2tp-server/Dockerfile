# Reference L2TP/IPsec server for the interop tests: the classic stack veepin's
# L2TP support exists to speak to — strongSwan terminating the IPsec transport SA
# (IKEv1, PSK) and xl2tpd behind it terminating L2TP and driving pppd. Config and
# entrypoint are bind-mounted by compose so they can be iterated without a
# rebuild.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strongswan strongswan-swanctl \
        libcharon-extra-plugins libstrongswan-standard-plugins \
        xl2tpd ppp \
        iproute2 iptables iputils-ping iperf3 tcpdump procps \
    && rm -rf /var/lib/apt/lists/*
CMD ["/bin/sh", "/entrypoint.sh"]
