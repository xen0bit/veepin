# Reference Nebula for the interop harness: the real slackhq/nebula daemon plus
# nebula-cert, the CA tool that issues the certificates both ends use.
#
# nebula-cert matters as much as the daemon here. veepin's certificate encoder
# has to agree with protobuf-go byte for byte, because a nebula certificate's
# signature covers the marshalled details and is verified by re-marshalling the
# parsed struct. Issuing the PKI with the reference tool means the certificates
# veepin parses and verifies in this test are ground truth, not something veepin
# produced and then agreed with itself about.
#
# Both binaries are pure Go, so this needs nothing of the host beyond
# CAP_NET_ADMIN and /dev/net/tun -- the same footprint the veepin container has.

# --- build stage: the reference implementation ---
FROM golang:1.25-bookworm AS build
# Pin the implementation so the harness is reproducible. v1.9.7 is the latest
# release that issues version 1 certificates by default, which is the format
# veepin implements -- so nothing here depends on a -version flag.
ARG NEBULA_VERSION=v1.9.7
RUN git clone --depth 1 --branch ${NEBULA_VERSION} https://github.com/slackhq/nebula.git /src \
    && cd /src \
    && go build -trimpath -o /out/nebula ./cmd/nebula \
    && go build -trimpath -o /out/nebula-cert ./cmd/nebula-cert

# --- runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping iperf3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/nebula /usr/local/bin/nebula
COPY --from=build /out/nebula-cert /usr/local/bin/nebula-cert
# Entrypoint is bind-mounted by compose; default to a shell.
CMD ["/bin/bash"]
