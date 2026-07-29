# Reference L2TPv3 Ethernet pseudowire peer: the Linux kernel itself.
#
# This is the most durable peer in the harness and the reason L2TPv3 was chosen.
# A static pseudowire needs no daemon at all -- `ip l2tp add tunnel` and `ip l2tp
# add session` configure it entirely, so there is no vendor binary to pin, no
# release to chase, and nothing that can rot. What it tests against is the
# kernel's own l2tp_eth implementation, which is what real deployments use.
#
# The kernel modules (l2tp_core, l2tp_eth, l2tp_netlink) come from the HOST, so
# the container must run privileged enough to load them; compose grants
# NET_ADMIN and the test skips if they are unavailable.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping iperf3 tcpdump procps kmod bridge-utils \
    && rm -rf /var/lib/apt/lists/*
CMD ["/bin/sh", "/entrypoint.sh"]
