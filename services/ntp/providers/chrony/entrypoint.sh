#!/bin/sh
set -eu

LOG_FIFO="${AMBER_NTP_LOG_FIFO:-/run/amber/log/ntp.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

# Keep one writer attached for the process lifetime (collectors README contract).
{ tail -f /dev/null >"$LOG_FIFO" 2>/dev/null || true; } &


chronyd -d -x -f /etc/chrony/chrony.conf 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
