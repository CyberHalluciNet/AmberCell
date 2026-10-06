#!/bin/sh
set -eu

LOG_FIFO="${AMBER_MONGO_LOG_FIFO:-/run/amber/log/mongo.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

exec python3 /opt/mock/mock_server.py
