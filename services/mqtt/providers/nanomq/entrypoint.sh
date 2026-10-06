#!/bin/sh
set -eu

LOG_FIFO="${AMBER_MQTT_LOG_FIFO:-/run/amber/log/mqtt.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")" /tmp
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

# CLI flags avoid HOCON version drift across NanoMQ tags.
nanomq start --url nmq-tcp://0.0.0.0:1883 --allow_anonymous true 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
