#!/bin/sh
set -eu

LOG_FIFO="${AMBER_SMTP_LOG_FIFO:-/run/amber/log/smtp.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
fi

for u in hr finance admin support; do
  touch "/var/mail/$u"
  chown "$u:mail" "/var/mail/$u" 2>/dev/null || chown "$u" "/var/mail/$u" 2>/dev/null || true
done

mkdir -p /var/spool/exim/input /var/spool/exim/msglog /var/spool/exim/db /var/spool/exim/tmp
chown -R exim:exim /var/spool/exim 2>/dev/null || true

exim -bV >/dev/null
# Foreground daemon keeps *-hi alive (Tini reaps children).
exec exim -bd -v
