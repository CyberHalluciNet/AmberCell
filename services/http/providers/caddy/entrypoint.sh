#!/bin/sh
set -eu

LOG_FIFO="${AMBER_HTTP_LOG_FIFO:-/run/amber/log/http.fifo}"
UPLOAD_DIR="${AMBER_HTTP_UPLOAD_DIR:-/var/www/uploads}"
mkdir -p "$(dirname "$LOG_FIFO")" "$UPLOAD_DIR"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

caddy run --config /etc/caddy/Caddyfile 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
