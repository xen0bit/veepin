# The independent Fortinet peer for the interop harness: openconnect, the real
# reference client, which fully implements the FortiOS SSL VPN data channel.
#
# It shares no code with veepin. If veepin's login, config XML, framing or PPP
# drift from what a real FortiGate speaks, openconnect fails to connect or to
# carry traffic.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openconnect vpnc-scripts iproute2 iputils-ping iperf3 openssl \
    && rm -rf /var/lib/apt/lists/*

# Entrypoint is bind-mounted by compose; default to a shell.
CMD ["/bin/bash"]
