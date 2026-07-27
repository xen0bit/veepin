# The independent GlobalProtect peer for the interop harness: openconnect, whose
# --protocol=gp support implements both of the protocol's data paths — the
# framed layer-3 TLS tunnel and ESP over UDP.
#
# It shares no code with veepin. If veepin's login, config XML, keying block,
# framing or ESP drift from what a real Palo Alto gateway speaks, openconnect
# fails to connect or to carry traffic.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openconnect vpnc-scripts iproute2 iputils-ping iperf3 openssl \
    && rm -rf /var/lib/apt/lists/*

# Entrypoint is bind-mounted by compose; default to a shell.
CMD ["/bin/bash"]
