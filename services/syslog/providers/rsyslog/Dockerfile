# AmberCell syslog hi-cell provider: rsyslog (default)
# Provider id: rsyslog — select with AMBER_SYSLOG_PROVIDER=rsyslog
FROM alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

RUN apk add --no-cache rsyslog

COPY rsyslog.conf /etc/rsyslog.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 514/tcp 514/udp
ENTRYPOINT ["/entrypoint.sh"]
