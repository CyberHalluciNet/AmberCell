#!/bin/sh
set -eu

LOG_FIFO="${AMBER_OLLAMA_LOG_FIFO:-/run/amber/log/ollama.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")" /root/.ollama
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

export OLLAMA_HOST="${OLLAMA_HOST:-0.0.0.0:11434}"
# Serve only — operators may pull models deliberately; default image has none.
ollama serve 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
