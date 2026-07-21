# The independent TOY peer for the interop harness.
#
# Python, deliberately: the point of this container is that the peer shares no
# code, no language and no libraries with veepin. It was written from
# internal/toy/SPEC.md, so if veepin's framing, key derivation, keystream, tag
# or handshake drift from that document, these cells stop passing.
#
# That is the only thing here that could not be tested in Go: a spec only its
# own implementation can read is not a spec.
FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping iperf3 \
    && rm -rf /var/lib/apt/lists/*

COPY toypeer.py /usr/local/bin/toypeer
RUN chmod +x /usr/local/bin/toypeer

# Entrypoint is bind-mounted by compose; default to a shell.
CMD ["/bin/bash"]
