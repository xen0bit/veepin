# Reference L2TPv3 quiescent-tunnel peer: katalix/go-l2tp's ql2tpd.
#
# Why this peer and not something from the distro: NOTHING packaged speaks the
# L2TPv3 control protocol. xl2tpd and l2tpns are L2TPv2/PPP. go-l2tp is the only
# open-source implementation of an L2TPv3 control connection, and even it
# implements only the QUIESCENT subset -- HELLO keepalives over RFC 3931's
# reliable transport. Its dynamic tunnel (SCCRQ/ICRQ) is L2TPv2 only:
# getV3MsgSpec in l2tp/msg.go returns a spec for exactly one message, HELLO.
#
# That is why veepin implements the quiescent connection and not the dynamic
# one: this is the whole of what any peer can check.
#
# Pinned by version so the cell cannot drift under us.
FROM golang:1.25-bookworm AS build
ARG GO_L2TP_VERSION=v0.1.8
RUN CGO_ENABLED=0 go install github.com/katalix/go-l2tp/cmd/ql2tpd@${GO_L2TP_VERSION}

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping iperf3 tcpdump procps kmod \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /go/bin/ql2tpd /usr/local/bin/ql2tpd
CMD ["/bin/sh", "/entrypoint.sh"]
