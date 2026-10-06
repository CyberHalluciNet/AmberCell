#!/bin/sh
set -eu

LOG_FIFO="${AMBER_SSH_LOG_FIFO:-/run/amber/log/ssh.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")" /var/log
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

# -F foreground, -E log to stderr, -p listen, allow password auth
dropbear -F -E -p 22 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
