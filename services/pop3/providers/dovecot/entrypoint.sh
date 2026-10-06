#!/bin/sh
set -u

LOG_FIFO="${AMBER_POP3_LOG_FIFO:-/run/amber/log/pop3.fifo}"
mkdir -p /var/mail
chown root:mail /var/mail 2>/dev/null || true
chmod 775 /var/mail 2>/dev/null || true
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
fi

for u in exec finance hr it canary; do
  if [ -f "/opt/amber-seeds/${u}.mbox" ]; then
    cp -f "/opt/amber-seeds/${u}.mbox" "/var/mail/$u" 2>/dev/null || true
    chown "$u:mail" "/var/mail/$u" 2>/dev/null || true
    chmod 600 "/var/mail/$u" 2>/dev/null || true
  fi
done

exec dovecot -F
