#!/bin/bash
set -euo pipefail

LOG_FIFO="${AMBER_ELASTIC_LOG_FIFO:-/run/amber/log/elastic.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

export discovery.type=single-node
export xpack.security.enabled=false
export ES_JAVA_OPTS="${ES_JAVA_OPTS:--Xms512m -Xmx512m}"

exec /usr/local/bin/docker-entrypoint.sh eswrapper 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
