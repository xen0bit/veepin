# Reference AnyConnect client (openconnect) for the interop tests. It drives the
# same protocol veepin's client implements, against the veepin server.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openconnect vpnc-scripts openssl \
        iproute2 iptables iputils-ping iperf3 procps \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
