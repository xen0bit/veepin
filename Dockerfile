# veepin runtime image — used by the interop test harness (tests/interop) to run
# the real veepin binary in containers against strongSwan.
#
# The binary is pure-Go and CGO-free (its one dependency, golang.org/x/crypto, is
# too), so the build is fully static and the runtime image only needs the
# userspace networking tools it shells out to (ip/iptables/sysctl) plus ping for
# the data-path assertion. TUN access
# (/dev/net/tun) and CAP_NET_ADMIN are granted at run time by compose, not baked
# into the image.

# --- build stage: static, CGO-free binaries ---
FROM golang:1.25-bookworm AS build
WORKDIR /src
# Pre-download modules against go.mod/go.sum so the dependency layer caches
# independently of the source, then build the command into /out.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/ ./cmd/veepin

# --- runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 iptables iputils-ping procps ca-certificates openssl socat \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/veepin /usr/local/bin/
# Entrypoint scripts are bind-mounted by compose; default to a shell.
CMD ["/bin/bash"]
