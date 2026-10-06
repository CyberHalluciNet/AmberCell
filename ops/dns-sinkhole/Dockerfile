# Stage-1 DNS sinkhole stub — logs all queries, returns NXDOMAIN (no upstream).
FROM alpine:3.20
RUN apk add --no-cache dnsmasq
COPY dnsmasq.conf /etc/dnsmasq.conf
EXPOSE 53/udp 53/tcp
CMD ["dnsmasq", "-k", "--log-queries", "--log-facility=-"]
