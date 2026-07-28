# Reference AmneziaWG peer for the interop harness: the real amneziawg-go
# userspace implementation plus amneziawg-tools (`awg`, `awg-quick`).
#
# amneziawg-go is a fork of wireguard-go, so this mirrors ../wireguard/Dockerfile
# — userspace rather than the kernel module, needing nothing of the host beyond
# CAP_NET_ADMIN and /dev/net/tun. It is the ground truth veepin's obfuscation is
# checked against: an implementation it shares no code with, reading a config it
# did not produce.
#
# amneziawg-tools is not packaged in Debian, so it is built from source. Its
# `awg-quick` is a patched wg-quick and lives in src/wg-quick/linux.bash.

FROM golang:1.24-bookworm AS build
RUN go install github.com/amnezia-vpn/amneziawg-go@latest

FROM debian:bookworm-slim AS tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git make gcc libc6-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools /src \
    && make -C /src/src -j"$(nproc)" \
    && make -C /src/src install

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping iperf3 bash openresolv tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /go/bin/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=tools /usr/bin/awg /usr/bin/awg
COPY --from=tools /usr/bin/awg-quick /usr/bin/awg-quick
CMD ["/bin/bash"]
