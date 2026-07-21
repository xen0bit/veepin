# Reference WireGuard responder for the interop harness: the real wireguard-go
# userspace implementation plus the wireguard-tools (`wg`, `wg-quick`).
#
# Userspace, not the kernel module, so the test needs nothing of the host beyond
# CAP_NET_ADMIN and /dev/net/tun — the same footprint the veepin client already
# requires, and no dependency on the host kernel having WireGuard built in. This
# is the ground truth the veepin initiator is checked against: a wg-quick config
# it did not produce, spoken by an implementation it shares no code with.

# --- build stage: the reference implementation ---
FROM golang:1.24-bookworm AS build
# Pin the implementation so the harness is reproducible. The last tagged release
# (0.0.20230223) no longer builds on current Go — its pinned x/net predates a
# syscall change — so this is a pinned post-release commit. The main package is
# the module root, so `go install` produces a binary named "wireguard"; wg-quick's
# WG_QUICK_USERSPACE_IMPLEMENTATION expects it to be called "wireguard-go".
RUN go install golang.zx2c4.com/wireguard@v0.0.0-20260522210424-ecfc5a8d5446

# --- runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        wireguard-tools iproute2 iputils-ping iperf3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /go/bin/wireguard /usr/local/bin/wireguard-go
# Entrypoint is bind-mounted by compose; default to a shell.
CMD ["/bin/bash"]
