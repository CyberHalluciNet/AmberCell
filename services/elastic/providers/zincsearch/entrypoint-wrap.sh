#!/bin/sh
set -eu

LOG_FIFO="${AMBER_ELASTIC_LOG_FIFO:-/run/amber/log/elastic.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")" /data
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

export ZINC_SERVER_PORT="${ZINC_SERVER_PORT:-9200}"
export ZINC_DATA_PATH="${ZINC_DATA_PATH:-/data}"

if command -v zincsearch >/dev/null 2>&1; then
  bin=zincsearch
elif [ -x /go/bin/zincsearch ]; then
  bin=/go/bin/zincsearch
else
  bin=zincsearch
fi

"$bin" 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
