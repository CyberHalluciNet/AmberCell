#!/bin/sh
set -eu

LOG_FIFO="${AMBER_SSH_LOG_FIFO:-/run/amber/log/ssh.fifo}"
RUN_DIR="${AMBER_SSH_RUN_DIR:-/run/sshd}"
mkdir -p "$RUN_DIR" "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

# sshd -e logs Accepted/d Failed to stderr; tee into collector FIFO.
/usr/sbin/sshd -D -e 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
