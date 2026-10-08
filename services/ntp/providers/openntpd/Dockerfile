# AmberCell NTP hi-cell provider: openntpd (alternate)
# Provider id: openntpd — select with AMBER_NTP_PROVIDER=openntpd
FROM alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

RUN apk add --no-cache openntpd

COPY ntpd.conf /etc/ntpd.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 123/udp
ENTRYPOINT ["/entrypoint.sh"]
