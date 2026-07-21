# Reference SSTP client (sstp-client's sstpc + pppd) for the interop tests. It
# connects to the veepin SSTP server and brings up a ppp interface.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        sstp-client ppp iproute2 iputils-ping iperf3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
