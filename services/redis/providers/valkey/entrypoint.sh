#!/bin/sh
set -eu

LOG_FIFO="${AMBER_REDIS_LOG_FIFO:-/run/amber/log/redis.fifo}"
mkdir -p /data "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

valkey-server /usr/local/etc/valkey/valkey.conf 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
