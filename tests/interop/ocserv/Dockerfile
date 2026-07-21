# Reference AnyConnect server (ocserv) for the interop tests. ocserv is the
# open-source implementation of the same protocol veepin speaks, written by the
# author of the protocol draft. Config and entrypoint are bind-mounted by compose
# so they can be iterated without a rebuild.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ocserv gnutls-bin \
        iproute2 iptables iputils-ping iperf3 procps \
    && rm -rf /var/lib/apt/lists/*
CMD ["/bin/sh", "/entrypoint.sh"]
