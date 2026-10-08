#!/bin/sh
set -eu

LOG_FIFO="${AMBER_RDP_LOG_FIFO:-/run/amber/log/rdp.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")" /var/run/xrdp /var/run/xrdp/sockdir
[ -p "$LOG_FIFO" ] || { rm -f "$LOG_FIFO"; mkfifo "$LOG_FIFO"; chmod 666 "$LOG_FIFO" 2>/dev/null || true; }
{ tail -f /dev/null >"$LOG_FIFO" 2>/dev/null || true; } &

# Honeypot: no sesman — negotiation + TLS surface only; sessions never spawn.
xrdp -n 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
