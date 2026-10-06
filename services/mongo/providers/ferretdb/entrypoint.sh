#!/bin/sh
set -eu

LOG_FIFO="${AMBER_MONGO_LOG_FIFO:-/run/amber/log/mongo.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")" /state
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

export FERRETDB_HANDLER="${FERRETDB_HANDLER:-sqlite}"
export FERRETDB_SQLITE_URL="${FERRETDB_SQLITE_URL:-file:/state/}"
export FERRETDB_LISTEN_ADDR="${FERRETDB_LISTEN_ADDR:-0.0.0.0:27017}"

if [ -x /ferretdb ]; then
  bin=/ferretdb
elif command -v ferretdb >/dev/null 2>&1; then
  bin=ferretdb
else
  bin=/ferretdb
fi

"$bin" 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
