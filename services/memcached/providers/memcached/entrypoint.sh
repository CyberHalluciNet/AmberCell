#!/bin/sh
set -eu

LOG_FIFO="${AMBER_MEMCACHED_LOG_FIFO:-/run/amber/log/memcached.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

# Keep one writer attached for the process lifetime (collectors README contract).
{ tail -f /dev/null >"$LOG_FIFO" 2>/dev/null || true; } &


memcached -u memcache -p 11211 -U 11211 -m 64 -c 256 -v 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
