#!/bin/sh
set -eu

LOG_FIFO="${AMBER_OLLAMA_LOG_FIFO:-/run/amber/log/ollama.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")" /models
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

export ADDRESS="${ADDRESS:-0.0.0.0:11434}"
# local-ai binary name varies by image tag; try common entrypoints.
if [ -x /local-ai ]; then
  cmd="/local-ai"
elif command -v local-ai >/dev/null 2>&1; then
  cmd="local-ai"
else
  cmd="local-ai"
fi

# Image ENTRYPOINT is typically the binary itself (no subcommand).
$cmd 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
