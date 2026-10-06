#!/bin/bash
set -euo pipefail

LOG_FIFO="${AMBER_MYSQL_LOG_FIFO:-/run/amber/log/mysql.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")" /var/log/mysql
chmod 777 /var/log/mysql 2>/dev/null || true
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

export MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-ambercell_root}"
export MYSQL_DATABASE="${MYSQL_DATABASE:-corp_app}"

/docker-entrypoint.sh mysqld &
pid=$!

for i in $(seq 1 90); do
  if [ -f /var/log/mysql/general.log ]; then
    break
  fi
  sleep 1
done

tail -F /var/log/mysql/general.log 2>/dev/null | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
done &
tail_pid=$!

wait "$pid" || true
kill "$tail_pid" 2>/dev/null || true
