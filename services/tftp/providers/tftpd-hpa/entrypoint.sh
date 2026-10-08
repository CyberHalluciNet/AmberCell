#!/bin/sh
set -eu

LOG_FIFO="${AMBER_TFTP_LOG_FIFO:-/run/amber/log/tftp.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

# Keep one writer attached for the process lifetime (collectors README contract).
{ tail -f /dev/null >"$LOG_FIFO" 2>/dev/null || true; } &


# /srv is a tmpfs (image seeds are masked); re-seed it each start.
cp -r /var/lib/tftpboot-seed/. /srv/tftp/ 2>/dev/null || true
mkdir -p /srv/tftp/incoming
in.tftpd --foreground --listen --address 0.0.0.0:69 --create /srv/tftp 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
