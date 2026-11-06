# Real Sliver C2 server (BishopFox/sliver v1.7.8) for duelswarm red_infra.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates procps git gcc \
    && rm -rf /var/lib/apt/lists/*
COPY sliver-server /usr/local/bin/sliver-server
COPY sliver-client /usr/local/bin/sliver-client
# Bake the embedded assets (offline unpack) so the container needs no internet at runtime.
RUN /usr/local/bin/sliver-server unpack
COPY entrypoint.sh /entrypoint.sh
COPY start_listener.rc /start_listener.rc
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
