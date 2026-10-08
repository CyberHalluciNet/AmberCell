# AmberCell SYSLOG hi-cell provider: remote relay (tunnel to your own server)
# Provider id: remote — select with AMBER_SYSLOG_PROVIDER=remote
# Requires AMBER_SYSLOG_REMOTE_ADDR=host:port (backend does NOT have to be localhost).
FROM alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

RUN apk add --no-cache socat

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
