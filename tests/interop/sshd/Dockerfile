# Reference OpenSSH server (sshd) with PermitTunnel, for the interop tests.
# The veepin SSH client connects to it and forwards IP over the tun@openssh.com
# channel it opens.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server iproute2 iputils-ping iperf3 \
    && rm -rf /var/lib/apt/lists/*
COPY sshd_config /etc/ssh/sshd_config.d/tunnel.conf
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
