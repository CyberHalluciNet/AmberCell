#!/bin/sh
set -eu

LOG_FIFO="${AMBER_DOCKERAPI_LOG_FIFO:-/run/amber/log/dockerapi.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

export AMBER_DOCKERAPI_TRAP_PROFILE="${AMBER_DOCKERAPI_TRAP_PROFILE:-v1.41}"
exec python3 /opt/trap/trap_server.py
