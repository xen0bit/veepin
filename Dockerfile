# ikennkt runtime image — used by the interop test harness (tests/interop) to run
# the real ikev2d / ikev2 / testclient binaries in containers against strongSwan.
#
# The core binaries are pure-Go and CGO-free, so the build is fully static and the
# runtime image only needs the userspace networking tools the binaries shell out
# to (ip/iptables/sysctl) plus ping for the data-path assertion. TUN access
# (/dev/net/tun) and CAP_NET_ADMIN are granted at run time by compose, not baked
# into the image.

# --- build stage: static, CGO-free binaries ---
FROM golang:1.24-bookworm AS build
WORKDIR /src
# The root module is stdlib-only (no go.sum), so there is nothing to pre-download;
# copy the source and build all three commands into /out.
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
    -o /out/ ./cmd/ikev2d ./cmd/ikev2 ./cmd/testclient

# --- runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 iptables iputils-ping procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ikev2d /out/ikev2 /out/testclient /usr/local/bin/
# Entrypoint scripts are bind-mounted by compose; default to a shell.
CMD ["/bin/bash"]
