# The independent MASQUE CONNECT-IP peer for the interop harness.
#
# Python and aioquic, deliberately: this container shares no code, no language
# and no QUIC/HTTP-3 stack with veepin, which builds its own on x/net/quic. If
# veepin's varint, QPACK, capsule or CONNECT-IP framing drifts from RFC
# 9484/9297/9114, these cells stop passing.
FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping procps openssl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir aioquic==1.3.0

COPY masquepeer.py /usr/local/bin/masquepeer
RUN chmod +x /usr/local/bin/masquepeer

# Entrypoint is bind-mounted by compose; default to a shell.
CMD ["/bin/bash"]
