#!/bin/bash
set -euo pipefail

LOG_FIFO="${AMBER_ELASTIC_LOG_FIFO:-/run/amber/log/elastic.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

export DISABLE_SECURITY_PLUGIN="${DISABLE_SECURITY_PLUGIN:-true}"
export OPENSEARCH_JAVA_OPTS="${OPENSEARCH_JAVA_OPTS:--Xms512m -Xmx512m}"
export discovery.type=single-node

# Official image entrypoint path varies by tag.
if [ -x ./opensearch-docker-entrypoint.sh ]; then
  entry=./opensearch-docker-entrypoint.sh
elif [ -x /usr/share/opensearch/opensearch-docker-entrypoint.sh ]; then
  entry=/usr/share/opensearch/opensearch-docker-entrypoint.sh
else
  entry=opensearch
fi

exec "$entry" opensearch 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
