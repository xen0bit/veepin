# The independent Ivanti Connect Secure peer for the interop harness:
# openconnect, whose --protocol=pulse support is the only implementation of this
# protocol outside Ivanti's own.
#
# It shares no code with veepin. If veepin's IF-T/TLS framing, its nested EAP
# authentication, its configuration TLVs or its ESP-keying packet drift from
# what a real Ivanti gateway speaks, openconnect fails to connect or to carry
# traffic — and it is strict about every one of them.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openconnect vpnc-scripts iproute2 iputils-ping iperf3 openssl \
    && rm -rf /var/lib/apt/lists/*

# Entrypoint is bind-mounted by compose; default to a shell.
CMD ["/bin/bash"]
