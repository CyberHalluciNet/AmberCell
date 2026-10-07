#!/bin/sh
set -eu

LOG_FIFO="${AMBER_DNS_LOG_FIFO:-/run/amber/log/dns.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

# Keep one writer attached for the process lifetime: the collector's FIFO
# reader sees EOF between per-line appends otherwise, closes and reconnects,
# and a mid-write append can then SIGPIPE this loop (killed the container
# under BIND's high-volume startup logging).
{ tail -f /dev/null >"$LOG_FIFO" 2>/dev/null || true; } &

/usr/sbin/named -g -c /etc/bind/named.conf -u named 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
