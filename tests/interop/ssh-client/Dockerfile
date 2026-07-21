# Reference OpenSSH client (ssh -w) for the interop tests. It opens a
# tun@openssh.com forwarding channel to the veepin SSH server and brings up a
# point-to-point tun link.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-client iproute2 iputils-ping iperf3 \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
