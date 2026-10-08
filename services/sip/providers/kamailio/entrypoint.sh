#!/bin/sh
set -eu

LOG_FIFO="${AMBER_SIP_LOG_FIFO:-/run/amber/log/sip.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

# Keep one writer attached for the process lifetime (collectors README contract).
{ tail -f /dev/null >"$LOG_FIFO" 2>/dev/null || true; } &


MODS="$(dirname "$(find /usr/lib -path '*kamailio/modules*' -name sl.so | head -1)")"
sed "s|@@MPATH@@|$MODS/|" /etc/kamailio/kamailio.cfg > /tmp/kamailio.cfg
kamailio -DD -E -f /tmp/kamailio.cfg 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
