# AmberCell NTP hi-cell provider: chrony (default)
# Provider id: chrony — select with AMBER_NTP_PROVIDER=chrony
FROM alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

RUN apk add --no-cache chrony

COPY chrony.conf /etc/chrony/chrony.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 123/udp
ENTRYPOINT ["/entrypoint.sh"]
